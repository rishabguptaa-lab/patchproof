import { scanRepository } from './scanner.js';
import { loadPolicy } from './policy.js';
import { toSarif } from './reporters.js';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { runProofManifest } from './proofs.js';

const root=process.env.GITHUB_WORKSPACE||process.cwd();
try{
  const policy=await loadPolicy(root); const report=await scanRepository(root,{policy,network:process.env.INPUT_OFFLINE!=='true'});
  let proofResult=null; if(process.env.INPUT_PROOF_MANIFEST){
    const event=await githubEvent();
    if(event?.pull_request?.head?.repo?.fork) throw new Error('PatchProof refuses proof execution from fork pull requests. Run trusted proofs in a separately reviewed workflow after checkout.');
    if(process.env.GITHUB_EVENT_NAME==='pull_request'&&!process.env.INPUT_PROOF_BUNDLE_SHA256) throw new Error('Pull-request proof execution requires proof_bundle_sha256 pinned in the workflow.');
    proofResult=await runProofManifest(root,process.env.INPUT_PROOF_MANIFEST,{expectedBundleSha256:process.env.INPUT_PROOF_BUNDLE_SHA256||undefined});
  }
  const output=path.join(root,'patchproof.sarif'); await fs.writeFile(output,JSON.stringify(toSarif(report),null,2));
  if(process.env.GITHUB_OUTPUT)await fs.appendFile(process.env.GITHUB_OUTPUT,`passed=${report.gate.passed}\nfindings=${report.summary.totalFindings}\nsarif=${output}\nproof_report=${proofResult?.output||''}\n`);
  const summary=[`## ${report.gate.passed?'✅':'🛑'} PatchProof ${report.gate.passed?'passed':'blocked this change'}`,`**${report.summary.totalFindings}** findings · **${report.gate.blockingFindings}** blocking · threshold **${report.gate.threshold}**`,proofResult?`**${proofResult.report.summary.verified}/${proofResult.report.summary.total}** executable proofs verified`:null,'',...report.findings.slice(0,20).map(f=>`- **${f.severity.toUpperCase()}** \`${f.file}:${f.line}\` ${f.title} — ${f.message} _(${f.verification?.level||'unverified'})_`)].filter(x=>x!==null).join('\n');
  if(process.env.GITHUB_STEP_SUMMARY)await fs.appendFile(process.env.GITHUB_STEP_SUMMARY,summary);
  console.log(summary); if(!report.gate.passed||proofResult?.report.summary.failed)process.exitCode=1;
}catch(error){console.error(error);process.exitCode=2;}
async function githubEvent(){try{return JSON.parse(await fs.readFile(process.env.GITHUB_EVENT_PATH,'utf8'));}catch{return null;}}
