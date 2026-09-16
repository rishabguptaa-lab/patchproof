import { promises as fs } from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

const IMAGES={node:'node:20-alpine',python:'python:3.12-alpine'};

export async function runProofManifest(root, manifestPath='.patchproof/proofs.json'){
  const manifest=JSON.parse(await fs.readFile(path.resolve(root,manifestPath),'utf8'));
  if(manifest.version!==1||!Array.isArray(manifest.proofs))throw new Error('Proof manifest must use version 1 and contain a proofs array.');
  await ensureDocker(); const results=[];
  for(const proof of manifest.proofs){validateProof(proof);results.push(await runOne(root,proof));}
  const report={schema:'https://patchproof.dev/proof-report/v1',createdAt:new Date().toISOString(),sandbox:{runtime:'docker',network:'none',rootFilesystem:'read-only',capabilities:'dropped',privileges:'no-new-privileges'},summary:{total:results.length,verified:results.filter(x=>x.verification.level==='execution_verified').length,failed:results.filter(x=>x.verification.level!=='execution_verified').length},results};
  const outputDir=path.join(root,'.patchproof','artifacts');await fs.mkdir(outputDir,{recursive:true});const output=path.join(outputDir,'proof-report.json');await fs.writeFile(output,JSON.stringify(report,null,2));return{report,output};
}
async function runOne(root,proof){
  const started=Date.now();const timeout=Math.min(Math.max(proof.timeoutMs||10000,1000),30000);
  const args=['run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--cpus','1','--pids-limit','64','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','-v',`${root}:/workspace:ro`,'-w','/workspace',IMAGES[proof.runtime],...proof.command];
  const execution=await capture('docker',args,timeout);const expected=proof.expect||{};const matched=(expected.exitCode===undefined||execution.exitCode===expected.exitCode)&&(!expected.stdoutIncludes||execution.stdout.includes(expected.stdoutIncludes))&&(!expected.stderrIncludes||execution.stderr.includes(expected.stderrIncludes));
  const transcript=`${execution.stdout}\n${execution.stderr}`;return{id:proof.id,ruleId:proof.ruleId||null,findingFingerprint:proof.findingFingerprint||null,description:proof.description||'',verification:{level:matched?'execution_verified':'execution_failed',method:'isolated-container',executed:true},expectation:expected,execution:{exitCode:execution.exitCode,timedOut:execution.timedOut,durationMs:Date.now()-started,transcriptSha256:createHash('sha256').update(transcript).digest('hex'),stdout:execution.stdout.slice(0,4000),stderr:execution.stderr.slice(0,4000)}};
}
function validateProof(proof){if(!proof||typeof proof.id!=='string'||!IMAGES[proof.runtime]||!Array.isArray(proof.command)||!proof.command.length||proof.command.some(x=>typeof x!=='string'))throw new Error('Each proof requires id, runtime (node|python), and a string command array.');}
async function ensureDocker(){const result=await capture('docker',['version','--format','{{.Server.Version}}'],5000);if(result.exitCode!==0)throw new Error('Executable proofs require a running Docker engine. No repository code was executed.');}
function capture(command,args,timeoutMs){return new Promise((resolve,reject)=>{const child=spawn(command,args,{env:{PATH:process.env.PATH},stdio:['ignore','pipe','pipe']});let stdout='',stderr='',timedOut=false;child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.on('error',reject);const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},timeoutMs);child.on('close',code=>{clearTimeout(timer);resolve({exitCode:code??137,stdout,stderr,timedOut});});});}
