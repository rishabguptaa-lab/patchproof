#!/usr/bin/env node
import { scanRepository } from '../src/scanner.js';
import { loadPolicy } from '../src/policy.js';
import { renderTerminal, toJson, toSarif } from '../src/reporters.js';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { runProofManifest } from '../src/proofs.js';

const [command = 'scan', target = '.', ...args] = process.argv.slice(2);
if (command === '--version' || command === '-v') { console.log('1.1.0'); process.exit(0); }
if (command === '--help' || command === '-h') {
  console.log(`PatchProof — evidence-first PR security\n\nUsage:\n  patchproof scan [path] [--format terminal|json|sarif] [--output file]\n  patchproof verify [path] [--manifest .patchproof/proofs.json]\n  patchproof init [path]\n\nExit codes: 0 pass, 1 policy violation/proof failure, 2 operational error`);
  process.exit(0);
}
if (command === 'init') {
  const destination = path.join(path.resolve(target), '.patchproof.yml');
  await fs.writeFile(destination, `version: 1\nfail-on: high\nexclude:\n  - node_modules/**\n  - dist/**\nrules:\n  dependency-truth: error\n  secret-exposure: error\n  command-injection: error\n  auth-bypass: error\n  unsafe-code-execution: error\n`, { flag: 'wx' });
  console.log(`Created ${destination}`); process.exit(0);
}
if (command === 'verify') {
  try { const root=path.resolve(target); const manifest=valueAfter(args,'--manifest')||'.patchproof/proofs.json'; const {report,output}=await runProofManifest(root,manifest); console.log(`Executable proofs: ${report.summary.verified}/${report.summary.total} verified\nArtifact: ${output}`); for(const failed of report.results.filter(x=>x.verification.level!=='execution_verified')) console.error(`Proof ${failed.id} failed: exit=${failed.execution.exitCode} timeout=${failed.execution.timedOut}\nstdout: ${failed.execution.stdout||'(empty)'}\nstderr: ${failed.execution.stderr||'(empty)'}`); process.exitCode=report.summary.failed?1:0; } catch(error){ console.error(`PatchProof verification failed safely: ${error.message}`); process.exitCode=2; }
} else if (command !== 'scan') { console.error(`Unknown command: ${command}`); process.exitCode=2; }
if (command === 'scan') try {
  const format = valueAfter(args, '--format') || 'terminal';
  const output = valueAfter(args, '--output');
  const root = path.resolve(target);
  const policy = await loadPolicy(root);
  const report = await scanRepository(root, { policy, network: !args.includes('--offline') });
  const rendered = format === 'json' ? toJson(report) : format === 'sarif' ? JSON.stringify(toSarif(report), null, 2) : renderTerminal(report);
  if (output) await fs.writeFile(path.resolve(output), rendered); else console.log(rendered);
  process.exitCode = report.gate.passed ? 0 : 1;
} catch (error) { console.error(`PatchProof failed: ${error.message}`); process.exitCode = 2; }
function valueAfter(list, key) { const i = list.indexOf(key); return i >= 0 ? list[i + 1] : undefined; }
