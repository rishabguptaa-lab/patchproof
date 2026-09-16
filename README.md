# PatchProof

**The AI-era PR security gate with explicit evidence levels.**

PatchProof verifies npm and PyPI dependency truth, reconciles JavaScript and Python imports with project manifests, detects high-impact insecure patterns, emits GitHub-native SARIF, and can execute opt-in vulnerability proofs inside a locked-down container.

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
    proof_manifest_sha256: 4519589b856c4b1cf7fb62fe6f4fea28c6905b36289a4be8d921cca1e42e2111
```

Calculate the pin with `sha256sum .patchproof/proofs.json` and update it only after reviewing manifest changes.

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
```

Exit code `0` means the policy/proofs passed, `1` means a policy or proof expectation failed, and `2` means execution could not complete safely.

## Benchmark honesty

`npm run benchmark` is a transparent **synthetic rule-regression corpus**. It protects detector behavior but is not presented as proof of real-world effectiveness. A separate real-AI-output benchmark requires human-labeled Copilot, Cursor and other coding-agent samples and will publish provenance, labels, false positives and per-rule recall when sufficient data exists.

Run all local checks with `npm run check`.

## Trust model

- Scanning never executes repository code.
- Registry failure never blocks a pull request.
- Secrets are redacted before reporting.
- Network checks can be disabled with `--offline`.
- Executable proofs require an explicit command and Docker sandbox.
- A successful scan is not a guarantee that software is secure.

## Roadmap

- Human-labeled AI-generated-code benchmark
- Lockfile publisher, integrity and maintainer-change verification
- Installed-version export/API truth verification
- Diff-aware dataflow and authorization-boundary analysis
- Python framework-specific authorization rules
- Go and Java dependency adapters
- GitHub App with inline comments and organization policy management

Apache-2.0 · [Threat model](THREAT_MODEL.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)
