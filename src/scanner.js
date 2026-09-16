import { promises as fs } from 'node:fs';
import path from 'node:path';
import { RULES, SEVERITY_SCORE } from './rules.js';
import { verifyDependencies, verifyImports } from './truth.js';
import { analyzePython } from './python.js';

const SOURCE_EXTENSIONS = new Set(['.js','.mjs','.cjs','.ts','.tsx','.jsx','.json','.yml','.yaml','.env','.py','.go','.java','.rb','.php']);
const IGNORED = new Set(['.git','node_modules','dist','build','coverage','.next','vendor']);

export async function scanRepository(root, options = {}) {
  const startedAt = new Date().toISOString();
  const files = await collect(root);
  const eligibleFiles = files.filter(file => !options.policy?.isExcluded(path.relative(root, file).split(path.sep).join('/')));
  const findings = [];
  for (const file of eligibleFiles) {
    const relative = path.relative(root, file).split(path.sep).join('/');
    let source; try { source = await fs.readFile(file, 'utf8'); } catch { continue; }
    if (Buffer.byteLength(source) > 1_000_000) continue;
    for (const rule of RULES) {
      if (options.policy?.ruleEnabled(rule.id) === false) continue;
      rule.pattern.lastIndex = 0;
      for (const match of source.matchAll(rule.pattern)) findings.push(finding(rule, relative, source, match));
    }
  }
  findings.push(...await verifyDependencies(root, { network: options.network }));
  findings.push(...await verifyImports(root, eligibleFiles));
  findings.push(...await analyzePython(root, eligibleFiles, { network: options.network }));
  const unique = deduplicate(findings).sort((a,b) => SEVERITY_SCORE[b.severity]-SEVERITY_SCORE[a.severity] || a.file.localeCompare(b.file));
  const threshold = options.policy?.failOn || 'high';
  const blocking = unique.filter(x => SEVERITY_SCORE[x.severity] >= SEVERITY_SCORE[threshold]);
  return {
    schema:'https://patchproof.dev/report/v1', version:'1.1.0', root, startedAt, completedAt:new Date().toISOString(),
    summary: count(unique, eligibleFiles.length), findings:unique,
    gate:{ passed:blocking.length===0, threshold, blockingFindings:blocking.length },
    integrity:{ engine:'deterministic', evidenceRequired:true, networkChecks:options.network !== false }
  };
}

function finding(rule, file, source, match) {
  const before = source.slice(0, match.index); const line = before.split('\n').length;
  const lineText = source.split('\n')[line-1]?.trim().slice(0,240) || '';
  return { id:`PP-${hash(`${rule.id}:${file}:${line}:${match[0]}`)}`, ruleId:rule.id, title:rule.title, severity:rule.severity, cwe:rule.cwe,
    file, line, column:(before.length-before.lastIndexOf('\n')), message:rule.explain,
    evidence:{ snippet:redact(lineText), rationale:rule.proof },
    verification:{ level:'pattern_match', method:'deterministic-rule', executed:false },
    remediation:remediation(rule.id), confidence:0.92, fingerprint:hash(`${rule.id}:${file}:${lineText.replace(/\s/g,'')}`) };
}
function remediation(id){ return ({'secret-exposure':'Move the value to a secret manager, rotate it, and reference it through an environment variable.','command-injection':'Use spawn/execFile with a fixed executable and an argument array; validate each argument.','unsafe-code-execution':'Replace dynamic evaluation with an explicit parser or allowlisted dispatcher.','auth-bypass':'Require verified identity and authorization middleware on the route.','permissive-cors':'Allowlist trusted origins and reject credentialed wildcard requests.','tls-disabled':'Restore certificate verification and install the required CA chain.','weak-randomness':'Use crypto.randomBytes or crypto.randomUUID.','path-traversal':'Resolve against a fixed root and reject paths escaping it.','sql-injection':'Use parameterized queries and typed placeholders.','prototype-pollution':'Reject __proto__, prototype, and constructor keys.','open-redirect':'Allowlist destinations or accept only relative paths.','unsafe-deserialization':'Use JSON and validate against a strict schema.'})[id] || 'Review and replace the unsafe construct.'; }
async function collect(root){ const output=[]; async function walk(dir){ for(const entry of await fs.readdir(dir,{withFileTypes:true})){ if(IGNORED.has(entry.name)) continue; const full=path.join(dir,entry.name); if(entry.isSymbolicLink()) continue; if(entry.isDirectory()) await walk(full); else if(SOURCE_EXTENSIONS.has(path.extname(entry.name)) || entry.name.startsWith('.env')) output.push(full); }} await walk(root); return output; }
function deduplicate(items){ const map=new Map(); for(const item of items) if(!map.has(item.fingerprint)) map.set(item.fingerprint,item); return [...map.values()]; }
function count(findings, scannedFiles){ const severities={critical:0,high:0,medium:0,low:0,info:0}; for(const f of findings) severities[f.severity]++; return { scannedFiles,totalFindings:findings.length,severities }; }
function hash(value){ let h=2166136261; for(let i=0;i<value.length;i++){h^=value.charCodeAt(i); h=Math.imul(h,16777619);} return (h>>>0).toString(16).padStart(8,'0'); }
function redact(s){ return s.replace(/((?:api[_-]?key|secret|token|password)\s*[:=]\s*["'`])([^"'`]+)(["'`])/gi,'$1[REDACTED]$3'); }
