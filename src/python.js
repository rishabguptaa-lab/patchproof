import { promises as fs } from 'node:fs';
import path from 'node:path';

const STDLIB = new Set(['abc','argparse','asyncio','base64','collections','concurrent','contextlib','csv','datetime','decimal','email','enum','functools','hashlib','http','importlib','inspect','io','itertools','json','logging','math','multiprocessing','os','pathlib','pickle','random','re','secrets','shlex','shutil','signal','socket','sqlite3','ssl','statistics','string','subprocess','sys','tempfile','threading','time','traceback','typing','unittest','urllib','uuid','venv','warnings','xml','zipfile']);
const IMPORT_TO_PACKAGE = {yaml:'pyyaml',cv2:'opencv-python',PIL:'pillow',sklearn:'scikit-learn',bs4:'beautifulsoup4',dotenv:'python-dotenv'};
const PY_RULES = [
  ['python-shell-injection','critical','CWE-78','Python subprocess shell injection',/subprocess\.(?:run|call|Popen)\s*\([^\n]*(?:request\.|input\(|sys\.argv|shell\s*=\s*True)/g,'Untrusted data reaches a subprocess or shell-enabled command.','Use an argument list, keep shell=False, and allowlist arguments.'],
  ['python-unsafe-pickle','critical','CWE-502','Unsafe pickle deserialization',/pickle\.loads?\s*\([^\n]*(?:request\.|input\(|sys\.argv|read\()/g,'Untrusted bytes are deserialized with pickle.','Use JSON plus schema validation; never unpickle untrusted data.'],
  ['python-unsafe-yaml','high','CWE-502','Unsafe YAML loader',/yaml\.load\s*\([^\n]*(?![^\n]*Loader\s*=\s*(?:SafeLoader|yaml\.SafeLoader))/g,'yaml.load is used without a safe loader.','Use yaml.safe_load or SafeLoader.'],
  ['python-debug-mode','high','CWE-489','Production debug mode enabled',/(?:app\.run\([^\n]*debug\s*=\s*True|DEBUG\s*=\s*True)/g,'Debug mode can expose an interactive debugger or sensitive internals.','Disable debug mode outside local development.'],
  ['python-sql-injection','critical','CWE-89','Python SQL interpolation',/\.execute\s*\(\s*(?:f["']|["'][^"']*%|["'][^"']*\.format\()/g,'A SQL statement is constructed through string interpolation.','Use database parameter placeholders and a separate parameter tuple.'],
  ['python-weak-hash','medium','CWE-328','Weak password hashing primitive',/hashlib\.(?:md5|sha1)\s*\([^\n]*(?:password|passwd|secret|token)/gi,'MD5 or SHA-1 is used in a security-sensitive context.','Use Argon2id, scrypt, or bcrypt for passwords.']
  ,['django-allow-any','high','CWE-862','Django REST Framework allows anonymous access',/permission_classes\s*=\s*\[[^\]]*AllowAny[^\]]*\]/g,'A DRF view explicitly allows unrestricted access.','Use IsAuthenticated plus object-level permission checks.']
  ,['django-csrf-exempt','high','CWE-352','Django CSRF protection disabled',/@csrf_exempt/g,'A Django endpoint disables CSRF protection.','Remove csrf_exempt or implement an equivalent authenticated anti-CSRF control.']
  ,['fastapi-missing-auth','high','CWE-862','FastAPI route lacks an authorization dependency',/@(?:app|router)\.(?:post|put|patch|delete)\([^\n]*\)\s*\n(?:async\s+)?def\s+\w+\([^)]*\)(?![^:]*Depends\()/g,'A state-changing FastAPI route has no visible Depends-based authorization.','Add a verified identity dependency and resource-level authorization.']
  ,['flask-missing-auth','high','CWE-862','Flask state-changing route lacks login guard',/@(?:app|blueprint)\.route\([^\n]*methods\s*=\s*\[[^\]]*(?:POST|PUT|PATCH|DELETE)[^\]]*\][^\n]*\)\s*\n(?!\s*@(?:login_required|permission_required))/gi,'A state-changing Flask route has no adjacent login/permission decorator.','Add login_required and explicit resource authorization.']
];

export async function analyzePython(root, files, {network=true}={}) {
  const pyFiles=files.filter(file=>file.endsWith('.py'));
  const manifests=await pythonDependencies(root);
  if(!pyFiles.length && !manifests.found) return [];
  const findings=[];
  for(const file of pyFiles){
    const source=await fs.readFile(file,'utf8'); const relative=rel(root,file);
    for(const [id,severity,cwe,title,pattern,message,remediation] of PY_RULES){pattern.lastIndex=0;for(const match of source.matchAll(pattern)){const line=source.slice(0,match.index).split('\n').length;findings.push({id:`PP-PY-${hash(`${id}:${relative}:${line}`)}`,ruleId:id,title,severity,cwe,file:relative,line,column:1,message,evidence:{snippet:source.split('\n')[line-1].trim().slice(0,240),rationale:message},verification:{level:'pattern_match',method:'python-deterministic-rule',executed:false},remediation,confidence:0.91,fingerprint:`${id}:${relative}:${line}`});}}
    for(const match of source.matchAll(/^\s*(?:from|import)\s+([A-Za-z_][\w]*)/gm)){
      const imported=match[1]; const packageName=(IMPORT_TO_PACKAGE[imported]||imported).toLowerCase().replace(/_/g,'-');
      if(STDLIB.has(imported)||manifests.names.has(packageName)) continue;
      const line=source.slice(0,match.index).split('\n').length;
      findings.push({id:`PP-PY-IMPORT-${packageName}`,ruleId:'python-undeclared-import',title:'Undeclared Python import',severity:'high',cwe:'CWE-1104',file:relative,line,column:1,message:`${imported} is imported but ${packageName} is not declared in a supported Python manifest.`,evidence:{snippet:match[0].trim(),rationale:'The import was reconciled against requirements.txt and pyproject.toml.'},verification:{level:'manifest_verified',method:'python-manifest-reconciliation',executed:false},remediation:`Declare and pin ${packageName} in the project dependency manifest.`,confidence:0.95,fingerprint:`py-import:${packageName}:${relative}`});
    }
  }
  if(network&&process.env.PATCHPROOF_NO_NETWORK!=='1') for(const [name,version] of manifests.entries.slice(0,100)){
    try{const response=await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`,{signal:AbortSignal.timeout(3500)});if(response.status===404)findings.push({id:`PP-PYPI-${name}`,ruleId:'python-dependency-truth',title:'Python package does not exist',severity:'critical',cwe:'CWE-829',file:manifests.file,line:1,column:1,message:`${name} does not exist on PyPI and may be hallucinated.`,evidence:{snippet:`${name}${version||''}`,rationale:'PyPI returned HTTP 404 for the declared project.'},verification:{level:'registry_verified',method:'pypi-json-api',executed:false},remediation:`Remove ${name} or identify and verify the intended PyPI project.`,confidence:0.99,fingerprint:`pypi:${name}`});}catch{/* network uncertainty is non-blocking */}
  }
  return findings;
}

async function pythonDependencies(root){
  const names=new Set(),entries=[]; let found=false,file='requirements.txt';
  try{const text=await fs.readFile(path.join(root,'requirements.txt'),'utf8');found=true;for(const raw of text.split(/\r?\n/)){const line=raw.trim();if(!line||line.startsWith('#')||line.startsWith('-'))continue;const match=line.match(/^([A-Za-z0-9_.-]+)(.*)$/);if(match){const name=match[1].toLowerCase().replace(/_/g,'-');names.add(name);entries.push([name,match[2]]);}}}catch{}
  try{const text=await fs.readFile(path.join(root,'pyproject.toml'),'utf8');found=true;file=file==='requirements.txt'&&!entries.length?'pyproject.toml':file;for(const match of text.matchAll(/["']([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:[<>=!~].*)?["']/g)){const name=match[1].toLowerCase().replace(/_/g,'-');if(!['name','version','description','python'].includes(name)){names.add(name);entries.push([name,'']);}}}catch{}
  return {names,entries,found,file};
}
function rel(root,file){return path.relative(root,file).split(path.sep).join('/');}
function hash(value){let h=2166136261;for(let i=0;i<value.length;i++){h^=value.charCodeAt(i);h=Math.imul(h,16777619);}return(h>>>0).toString(16);}
