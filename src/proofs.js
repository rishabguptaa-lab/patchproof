import { promises as fs } from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

const IMAGES={node:'node:20-alpine',python:'python:3.12-alpine'};

export async function runProofManifest(root, manifestPath='.patchproof/proofs.json', options={}){
  const raw=await fs.readFile(path.resolve(root,manifestPath),'utf8');
  const manifestSha256=createHash('sha256').update(raw).digest('hex');
  if(options.expectedSha256&&manifestSha256!==options.expectedSha256)throw new Error(`Proof manifest integrity check failed. Expected ${options.expectedSha256}, received ${manifestSha256}.`);
  const manifest=JSON.parse(raw);
  const bundle=await proofBundle(root,manifestPath,raw,manifest);
  if(options.expectedBundleSha256&&bundle.sha256!==options.expectedBundleSha256)throw new Error(`Proof bundle integrity check failed. Expected ${options.expectedBundleSha256}, received ${bundle.sha256}.`);
  if(manifest.version!==1||!Array.isArray(manifest.proofs))throw new Error('Proof manifest must use version 1 and contain a proofs array.');
  await ensureDocker(); const results=[];
  for(const proof of manifest.proofs){validateProof(proof);results.push(await runOne(root,proof));}
  const report={schema:'https://patchproof.dev/proof-report/v1',createdAt:new Date().toISOString(),manifest:{path:manifestPath,sha256:manifestSha256,trust:'author_supplied'},bundle,sandbox:{runtime:'docker',network:'none',rootFilesystem:'read-only',capabilities:'dropped',privileges:'no-new-privileges'},summary:{total:results.length,verified:results.filter(x=>x.verification.level==='execution_verified').length,failed:results.filter(x=>x.verification.level!=='execution_verified').length},results};
  const outputDir=path.join(root,'.patchproof','artifacts');await fs.mkdir(outputDir,{recursive:true});const output=path.join(outputDir,'proof-report.json');await fs.writeFile(output,JSON.stringify(report,null,2));return{report,output};
}
export async function inspectProofBundle(root,manifestPath='.patchproof/proofs.json'){
  const raw=await fs.readFile(path.resolve(root,manifestPath),'utf8');const manifest=JSON.parse(raw);return proofBundle(root,manifestPath,raw,manifest);
}
async function proofBundle(root,manifestPath,raw,manifest){
  if(!Array.isArray(manifest.files)||!manifest.files.length)throw new Error('Proof manifest must declare every executable/imported proof file in a non-empty files array.');
  const unique=[...new Set(manifest.files)].sort();const declaredSet=new Set(unique);const hash=createHash('sha256');const warnings=[];hash.update(`manifest:${manifestPath}\0`);hash.update(raw);hash.update('\0');
  for(const declared of unique){if(typeof declared!=='string'||!declared||path.isAbsolute(declared))throw new Error('Proof file paths must be non-empty relative paths.');const absolute=path.resolve(root,declared);const relative=path.relative(root,absolute);if(relative.startsWith('..')||path.isAbsolute(relative))throw new Error(`Proof file escapes repository root: ${declared}`);const stat=await fs.lstat(absolute);if(!stat.isFile()||stat.isSymbolicLink())throw new Error(`Proof file must be a regular non-symlink file: ${declared}`);const content=await fs.readFile(absolute);const text=content.toString('utf8');for(const specifier of staticLocalImports(declared,text)){const resolved=await resolveLocalImport(root,declared,specifier);if(resolved&&!declaredSet.has(resolved))throw new Error(`Proof file ${declared} statically imports ${resolved}, but it is missing from the manifest files array.`);}if(hasUnresolvedDynamicImport(declared,text))warnings.push(`${declared} contains a dynamic import/require that cannot be closure-verified statically.`);hash.update(`file:${declared}\0`);hash.update(content);hash.update('\0');}
  return{sha256:hash.digest('hex'),files:unique,coverage:'declared-files-plus-detected-static-local-imports',warnings};
}
function staticLocalImports(file,text){const found=[];if(/\.[cm]?[jt]sx?$/.test(file)){for(const match of text.matchAll(/(?:import\s+(?:[^"']*?\s+from\s+)?|export\s+[^"']*?\s+from\s+|require\s*\(|import\s*\()\s*["'](\.[^"']+)["']/g))found.push(match[1]);}else if(file.endsWith('.py')){for(const match of text.matchAll(/^\s*from\s+(\.+[\w.]*)\s+import\s+/gm))found.push(match[1]);}return found;}
function hasUnresolvedDynamicImport(file,text){if(/\.[cm]?[jt]sx?$/.test(file))return /(?:import|require)\s*\(\s*(?!["'])/.test(text);return file.endsWith('.py')&&/importlib\.import_module\s*\(\s*(?!["'])/.test(text);}
async function resolveLocalImport(root,fromFile,specifier){let base;if(fromFile.endsWith('.py')){const dots=specifier.match(/^\.+/)[0].length;const module=specifier.slice(dots).replace(/\./g,'/');let dir=path.dirname(fromFile);for(let i=1;i<dots;i++)dir=path.dirname(dir);base=path.join(dir,module);}else base=path.join(path.dirname(fromFile),specifier);const candidates=fromFile.endsWith('.py')?[`${base}.py`,path.join(base,'__init__.py')]:[base,`${base}.js`,`${base}.mjs`,`${base}.cjs`,`${base}.json`,path.join(base,'index.js'),path.join(base,'index.mjs')];for(const candidate of candidates){try{const stat=await fs.lstat(path.resolve(root,candidate));if(stat.isFile()&&!stat.isSymbolicLink())return candidate.split(path.sep).join('/');}catch{}}return null;}
async function runOne(root,proof){
  const started=Date.now();const timeout=Math.min(Math.max(proof.timeoutMs||10000,1000),30000);
  const args=['run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--cpus','1','--pids-limit','64','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','-v',`${root}:/workspace:ro`,'-w','/workspace',IMAGES[proof.runtime],...proof.command];
  const execution=await capture('docker',args,timeout);const expected=proof.expect||{};const matched=(expected.exitCode===undefined||execution.exitCode===expected.exitCode)&&(!expected.stdoutIncludes||execution.stdout.includes(expected.stdoutIncludes))&&(!expected.stderrIncludes||execution.stderr.includes(expected.stderrIncludes));
  const transcript=`${execution.stdout}\n${execution.stderr}`;return{id:proof.id,ruleId:proof.ruleId||null,findingFingerprint:proof.findingFingerprint||null,description:proof.description||'',verification:{level:matched?'execution_verified':'execution_failed',method:'isolated-container',executed:true},expectation:expected,execution:{exitCode:execution.exitCode,timedOut:execution.timedOut,durationMs:Date.now()-started,transcriptSha256:createHash('sha256').update(transcript).digest('hex'),stdout:execution.stdout.slice(0,4000),stderr:execution.stderr.slice(0,4000)}};
}
function validateProof(proof){if(!proof||typeof proof.id!=='string'||!IMAGES[proof.runtime]||!Array.isArray(proof.command)||!proof.command.length||proof.command.some(x=>typeof x!=='string'))throw new Error('Each proof requires id, runtime (node|python), and a string command array.');}
async function ensureDocker(){const result=await capture('docker',['version','--format','{{.Server.Version}}'],5000);if(result.exitCode!==0)throw new Error('Executable proofs require a running Docker engine. No repository code was executed.');}
function capture(command,args,timeoutMs){return new Promise((resolve,reject)=>{const child=spawn(command,args,{env:{PATH:process.env.PATH},stdio:['ignore','pipe','pipe']});let stdout='',stderr='',timedOut=false;child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.on('error',reject);const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},timeoutMs);child.on('close',code=>{clearTimeout(timer);resolve({exitCode:code??137,stdout,stderr,timedOut});});});}
