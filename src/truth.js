import { promises as fs } from 'node:fs';
import path from 'node:path';

export async function verifyDependencies(root,{network=true}={}) {
  let manifest; try { manifest=JSON.parse(await fs.readFile(path.join(root,'package.json'),'utf8')); } catch { return []; }
  const deps={...manifest.dependencies,...manifest.devDependencies,...manifest.optionalDependencies};
  const findings=[];
  if(!network || process.env.PATCHPROOF_NO_NETWORK==='1') return findings;
  for(const [name,version] of Object.entries(deps).slice(0,100)){
    if(version.startsWith('file:')||version.startsWith('git')||version.startsWith('workspace:')) continue;
    try{
      const response=await fetch(`https://registry.npmjs.org/${encodeURIComponent(name).replace('%40','@')}`,{signal:AbortSignal.timeout(3500),headers:{accept:'application/vnd.npm.install-v1+json'}});
      if(response.status===404) findings.push(depFinding(name,version,'critical','Package does not exist in the npm registry. This may be a hallucinated dependency or slopsquatting risk.'));
      else if(response.ok){ const data=await response.json(); const created=data.time?.created; if(created && Date.now()-Date.parse(created)<1000*60*60*24*30) findings.push(depFinding(name,version,'medium',`Package was created recently (${created}); verify ownership before installation.`)); }
    } catch { /* Network uncertainty never blocks a PR. */ }
  }
  return findings;
}

export async function verifyImports(root, files){
  let manifest; try{manifest=JSON.parse(await fs.readFile(path.join(root,'package.json'),'utf8'));}catch{return[];}
  const declared=new Set([...Object.keys(manifest.dependencies||{}),...Object.keys(manifest.devDependencies||{}),...Object.keys(manifest.peerDependencies||{})]);
  const builtins=new Set(['assert','buffer','child_process','crypto','events','fs','http','https','os','path','querystring','stream','url','util','worker_threads','zlib','node:test']);
  const findings=[];
  for(const file of files.filter(f=>/\.[cm]?[jt]sx?$/.test(f))){ let source; try{source=await fs.readFile(file,'utf8');}catch{continue;}
    for(const match of source.matchAll(/(?:from\s*|import\s*\(|require\s*\()\s*["']([^"']+)["']/g)){
      const spec=match[1]; if(spec.startsWith('.')||spec.startsWith('/')||spec.startsWith('node:')||builtins.has(spec)) continue;
      const name=spec.startsWith('@')?spec.split('/').slice(0,2).join('/'):spec.split('/')[0];
      if(!declared.has(name)) findings.push({id:`PP-IMPORT-${name}`,ruleId:'undeclared-import',title:'Undeclared package import',severity:'high',cwe:'CWE-1104',file:path.relative(root,file).split(path.sep).join('/'),line:source.slice(0,match.index).split('\n').length,column:1,message:`${name} is imported but is not declared in package.json.`,evidence:{snippet:match[0],rationale:'Clean installs and CI may resolve a different package or fail unpredictably.'},verification:{level:'manifest_verified',method:'package-json-reconciliation',executed:false},remediation:`Declare ${name} with a pinned compatible version and commit the lockfile.`,confidence:0.99,fingerprint:`undeclared:${name}:${path.relative(root,file)}`});
    }
  } return findings;
}
function depFinding(name,version,severity,message){return{id:`PP-DEP-${name}`,ruleId:'dependency-truth',title:'Untrusted dependency',severity,cwe:'CWE-829',file:'package.json',line:1,column:1,message,evidence:{snippet:`"${name}": "${version}"`,rationale:'Registry existence and age were checked directly.'},verification:{level:'registry_verified',method:'npm-registry',executed:false},remediation:`Remove ${name} or verify the intended package, publisher, provenance, and version.`,confidence:0.98,fingerprint:`dependency:${name}`};}
