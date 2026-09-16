import http from 'node:http';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { verifyWebhook, installationToken, gh } from './github.js';
import { scanRepository } from '../src/scanner.js';
import { loadPolicy } from '../src/policy.js';

const required=['GITHUB_APP_ID','GITHUB_APP_PRIVATE_KEY','GITHUB_WEBHOOK_SECRET'];
for(const key of required)if(!process.env[key])throw new Error(`${key} is required`);
const api=process.env.GITHUB_API_URL||'https://api.github.com';

http.createServer(async(req,res)=>{
  if(req.method==='GET'&&req.url==='/health'){res.writeHead(200);return res.end('ok');}
  if(req.method!=='POST'||req.url!=='/webhook'){res.writeHead(404);return res.end();}
  const chunks=[];for await(const chunk of req)chunks.push(chunk);const body=Buffer.concat(chunks);
  if(!verifyWebhook(process.env.GITHUB_WEBHOOK_SECRET,body,req.headers['x-hub-signature-256'])){res.writeHead(401);return res.end('invalid signature');}
  res.writeHead(202);res.end('accepted');handle(req.headers['x-github-event'],JSON.parse(body)).catch(error=>console.error(error));
}).listen(Number(process.env.PORT||3000),()=>console.log('PatchProof GitHub App listening'));

async function handle(event,payload){
  if(event!=='pull_request'||!['opened','synchronize','reopened','ready_for_review'].includes(payload.action))return;
  const token=await installationToken(api,process.env.GITHUB_APP_ID,process.env.GITHUB_APP_PRIVATE_KEY.replace(/\\n/g,'\n'),payload.installation.id);
  const repo=payload.repository.full_name,number=payload.pull_request.number,ref=payload.pull_request.head.sha;
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'patchproof-app-'));
  try{
    const files=await gh(api,token,`/repos/${repo}/pulls/${number}/files?per_page=100`);
    for(const file of files){if(file.status==='removed'||file.changes>20000)continue;await download(api,token,repo,file.filename,ref,root);}
    for(const name of ['package.json','package-lock.json','requirements.txt','pyproject.toml','go.mod','go.sum','pom.xml','build.gradle','build.gradle.kts','.patchproof.yml'])await download(api,token,repo,name,ref,root,true);
    await organizationPolicy(api,token,root);const policy=await loadPolicy(root);const report=await scanRepository(root,{policy,network:true});
    const changed=new Set(files.map(x=>x.filename));const patches=new Map(files.map(x=>[x.filename,patchLines(x.patch||'')]));
    const comments=report.findings.filter(f=>changed.has(f.file)&&patches.get(f.file)?.has(f.line)).slice(0,20).map(f=>({path:f.file,line:f.line,side:'RIGHT',body:`**PatchProof ${f.severity.toUpperCase()} — ${f.title}**\n\n${f.message}\n\nVerification: \`${f.verification?.level||'unverified'}\` via \`${f.verification?.method||'unknown'}\`\n\nSuggested fix: ${f.remediation}`}));
    const body=`PatchProof found **${report.summary.totalFindings}** issue(s), including **${report.gate.blockingFindings}** at or above the \`${report.gate.threshold}\` policy threshold.`;
    await gh(api,token,`/repos/${repo}/pulls/${number}/reviews`,{method:'POST',body:JSON.stringify({commit_id:ref,event:'COMMENT',body,comments})});
  }finally{await fs.rm(root,{recursive:true,force:true});}
}

async function download(api,token,repo,file,ref,root,optional=false){try{const data=await gh(api,token,`/repos/${repo}/contents/${encodeURIComponent(file).replaceAll('%2F','/')}?ref=${ref}`);if(data.type!=='file'||data.encoding!=='base64')return;const target=path.resolve(root,file);if(!target.startsWith(`${root}${path.sep}`))throw new Error('Unsafe repository path');await fs.mkdir(path.dirname(target),{recursive:true});await fs.writeFile(target,Buffer.from(data.content,'base64'));}catch(error){if(!optional)throw error;}}
async function organizationPolicy(api,token,root){const repo=process.env.PATCHPROOF_POLICY_REPOSITORY;if(!repo)return;try{const data=await gh(api,token,`/repos/${repo}/contents/.patchproof.yml`);const target=path.join(root,'.patchproof.yml');try{await fs.access(target);}catch{await fs.writeFile(target,Buffer.from(data.content,'base64'));}}catch(error){console.warn(`Organization policy unavailable: ${error.message}`);}}
function patchLines(patch){const set=new Set();let line=0;for(const raw of patch.split('\n')){const header=raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);if(header){line=Number(header[1]);continue;}if(raw.startsWith('+')&&!raw.startsWith('+++'))set.add(line++);else if(!raw.startsWith('-'))line++;}return set;}
