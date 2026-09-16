# PatchProof

**Catch hallucinated dependencies before they become supply-chain incidents.**

PatchProof is an AI-era dependency-truth and evidence layer for pull requests. It checks whether suggested packages exist, whether imports are declared, whether installed versions expose the APIs code expects, and whether package publishers or maintainers changed unexpectedly. Every result states exactly how it was established.

PatchProof does **not** claim to have invented static analysis and is not a replacement for CodeQL, Semgrep, Bandit, dependency auditing, or human review. Its focused contribution is verifying failure modes that become common when code is generated at machine speed—especially fabricated packages and APIs—while separating pattern matches from manifest, registry, installed-version, and execution-backed evidence.

Beyond that wedge, PatchProof includes supporting PR security checks, diff-aware authorization analysis, GitHub-native SARIF, opt-in executable proofs, and a deployable GitHub App. These features support the dependency-truth workflow; they are not presented as novel categories of analysis.

**Precision:** PatchProof does not generate exploits. `execution_verified` appears only when a proof supplied and trusted by the repository owner is executed and meets its declared expectation; ordinary scanner findings remain `pattern_match`, `manifest_verified`, or `registry_verified`.

> PatchProof analyzes risky behavior, not whether a human or AI wrote it. Authorship detection is unreliable; security impact is what matters.

## What is actually verified?

Every finding declares exactly how far PatchProof verified it:

| Level | Meaning |
|---|---|
| `pattern_match` | A deterministic security rule matched source code. No code was executed. |
| `manifest_verified` | An import was reconciled against the repository's declared dependencies. |
| `registry_verified` | The declared package was checked directly against npm or PyPI. |
| `execution_verified` | A repository-supplied proof met its expected result inside the isolated proof runner. |

PatchProof never labels a pattern match as executable proof.

## Quick start

```bash
npx patchproof scan .
```

Node.js 20+ is the only requirement for scanning. Source stays on the runner and no account or API key is required.

### GitHub Action

```yaml
name: PatchProof
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rishabguptaa-lab/patchproof@v1
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: patchproof.sarif
```

## Executable proof runner

Executable verification is deliberately opt-in because running pull-request code is dangerous. Proofs require Docker and run with:

- No network
- Read-only repository mount and root filesystem
- All Linux capabilities dropped
- `no-new-privileges`
- CPU, memory, process and timeout limits
- A temporary 32 MB `/tmp`
- No inherited secrets or environment variables

Create `.patchproof/proofs.json`:

```json
{
  "version": 1,
  "files": ["security/proofs/command-injection.mjs"],
  "proofs": [{
    "id": "command-injection-regression",
    "ruleId": "command-injection",
    "runtime": "node",
    "command": ["node", "security/proofs/command-injection.mjs"],
    "timeoutMs": 10000,
    "expect": {
      "exitCode": 0,
      "stdoutIncludes": "VULNERABILITY_REPRODUCED"
    }
  }]
}
```

Run `patchproof verify . --manifest .patchproof/proofs.json`. PatchProof writes `.patchproof/artifacts/proof-report.json` with the sandbox configuration, expectation, exit status, duration, sanitized output, and a SHA-256 transcript hash. A working command-injection demonstration lives in [`examples/proof-target`](examples/proof-target).

To enable proofs in a pull-request GitHub Action, explicitly set the trusted manifest and pin its SHA-256:

```yaml
- uses: rishabguptaa-lab/patchproof@v1
  with:
    proof_manifest: .patchproof/proofs.json
    proof_bundle_sha256: 73705aad15bde288f39aa91f9df7b7f6012371766a3372c88b642e855cd30679
```

Declare every proof script and imported helper in the manifest's `files` array. Calculate the complete pin with `patchproof hash-proofs .` and update it only after reviewing changes to the manifest and every declared file.

`hash-proofs` fails when it detects a static local JavaScript or Python import missing from `files`. Dynamic imports cannot always be resolved safely; they produce a warning and remain a reviewer-verified limitation rather than a tool-guaranteed closure.

The Action refuses fork-provided proofs. A matching output string alone cannot establish that a proof is honest, so proof logic remains a reviewed trust anchor. Read the full [malicious-manifest threat model](THREAT_MODEL.md) before enabling executable proofs.

## JavaScript and Python coverage

| Control | JavaScript/Node | Python |
|---|:---:|:---:|
| Registry existence | npm | PyPI |
| Manifest reconciliation | `package.json` | `requirements.txt`, `pyproject.toml` |
| Command injection | ✓ | ✓ |
| SQL interpolation | ✓ | ✓ |
| Unsafe deserialization | ✓ | Pickle/YAML |
| Auth, TLS and CORS regressions | ✓ | Expanding |
| Path traversal and redirects | ✓ | Expanding |
| Debug/weak-crypto configuration | ✓ | ✓ |

Common import-to-package differences such as `yaml` → `pyyaml`, `PIL` → `pillow`, and `cv2` → `opencv-python` are handled explicitly.

## PatchProof and CodeQL

CodeQL performs deep semantic analysis across supported languages. PatchProof focuses on AI-era failure modes: fabricated dependencies, imports missing from manifests, suspicious registry facts, explicit evidence classification, and isolated execution of repository-owned proofs. They are complementary; PatchProof exports SARIF into the same GitHub security workflow and this repository runs both.

## Policy

Run `npx patchproof init` and commit `.patchproof.yml`:

```yaml
version: 1
fail-on: high
exclude:
  - dist/**
  - fixtures/**
rules:
  dependency-truth: error
  command-injection: error
  permissive-cors: off
```

## Output formats

```bash
patchproof scan . --format terminal
patchproof scan . --format json --output patchproof.json
patchproof scan . --format sarif --output patchproof.sarif
patchproof scan . --offline
patchproof scan . --base origin/main --diff-only
patchproof snapshot .
```

Exit code `0` means the policy/proofs passed, `1` means a policy or proof expectation failed, and `2` means execution could not complete safely.

## Benchmark honesty

`npm run benchmark` remains a transparent **synthetic rule-regression corpus**. PatchProof now also ships a provenance-preserving human-label schema requiring two reviewers, source commit/path, license, AI-assistance confidence, disclosure state, and snippet hash. Run `npm run benchmark:human -- labels.jsonl predictions.jsonl` to calculate precision, recall, F1, exclusions, and reviewer disagreements. The example dataset is deliberately not presented as real-world validation.

Corpus collection is governed by the locked [benchmark preregistration](docs/BENCHMARK_PREREGISTRATION.md) and [responsible disclosure protocol](docs/DISCLOSURE.md): deterministic sampling, blinded independent labels, Cohen's kappa plus raw agreement, separate natural/seeded recall, predefined headline thresholds, private disclosure, and consent before naming.

## Supply-chain and API truth

- Validates integrity fields across npm lockfile entries.
- Compares installed package versions with the lockfile.
- Creates a reviewed publisher/maintainer baseline with `patchproof snapshot .`.
- Flags registry publisher or maintainer changes against that baseline.
- Reconciles named JavaScript imports with installed TypeScript declarations when available.
- Checks PyPI, Go proxy, and Maven Central project existence.

## Diff-aware authorization analysis

Use `--base` with `--diff-only` to gate only added lines. PatchProof identifies changed routes without visible authorization controls and short-window flows from request input to command, SQL, and filesystem sinks. These heuristic findings use `diff_verified`; they do not claim whole-program dataflow proof.

## GitHub App

The App validates webhook HMACs, uses short-lived installation tokens, downloads only changed files plus dependency manifests, posts comments only on added diff lines, and supports a protected organization policy repository. See [GitHub App deployment](docs/GITHUB_APP.md).

Run all local checks with `npm run check`.

## Trust model

- Scanning never executes repository code.
- Registry failure never blocks a pull request.
- Secrets are redacted before reporting.
- Network checks can be disabled with `--offline`.
- Executable proofs require an explicit command and Docker sandbox.
- A successful scan is not a guarantee that software is secure.

## Completed v2 roadmap

- Human-label benchmark schema and evaluator
- Lockfile integrity, publisher, maintainer-change, and installed-version checks
- Installed TypeScript declaration/API truth verification
- Diff-scoped local dataflow and authorization-boundary analysis
- Django REST Framework, Django CSRF, Flask, and FastAPI authorization rules
- Go module/import and Maven/Gradle coordinate adapters
- GitHub App with inline comments and organization policy fallback

Known limits remain explicit: the benchmark still needs real labeled cases; API truth currently requires installed declarations; diff dataflow is local rather than interprocedural; registry outages are non-blocking; and the GitHub App must be deployed and registered by its operator.

Apache-2.0 · [Threat model](THREAT_MODEL.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)
