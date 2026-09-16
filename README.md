# PatchProof

**The PR security gate that proves its findings.**

PatchProof is an open-source, evidence-first security scanner built for code produced at machine speed. It verifies dependency truth, detects high-impact insecure patterns, identifies undeclared packages, emits GitHub-native SARIF, and blocks pull requests according to a repository-owned policy.

> PatchProof scans risky code, not whether a human or AI wrote it. Authorship detection is unreliable; exploitable behavior is what matters.

## Why PatchProof

AI coding tools can fabricate package names and APIs, repeat insecure snippets, remove guardrails, and generate convincing but incorrect fixes. Traditional linters report patterns. PatchProof reports a compact evidence record: location, observed construct, exploit rationale, confidence, remediation, and a stable fingerprint.

## Quick start

```bash
npx patchproof scan .
```

No account, API key, build step, or source upload is required. Node.js 20+ is the only runtime dependency.

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

### Policy

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

## Detection coverage

| Control | Evidence produced |
|---|---|
| Dependency truth | Registry existence and package age |
| Import truth | Import not declared by the project manifest |
| Secret exposure | Redacted source evidence and rotation guidance |
| Command/SQL injection | Dangerous data-to-sink construct and exploit rationale |
| Auth/TLS/CORS regression | Disabled boundary and resulting exposure |
| Path traversal/open redirect | Request-controlled security-sensitive destination |
| Unsafe evaluation/deserialization | Executable or object-instantiating input path |
| Weak randomness/prototype pollution | Unsafe primitive and targeted replacement |

## Output formats

```bash
patchproof scan . --format terminal
patchproof scan . --format json --output patchproof.json
patchproof scan . --format sarif --output patchproof.sarif
patchproof scan . --offline
```

Exit code `0` means the policy passed, `1` means verified findings met the blocking threshold, and `2` means the scan could not complete.

## Trust model

- Source stays on the runner.
- Results are deterministic and fingerprinted.
- Secrets are redacted before reporting.
- Network failure never blocks a pull request.
- Registry lookups can be disabled with `--offline`.
- Symlinks, generated folders, oversized files, and binary content are excluded.
- PatchProof does not execute repository code during scanning.

## Benchmark

`npm run benchmark` evaluates more than 100 positive and negative rule cases. `npm run check` runs syntax validation, unit tests, the benchmark, and a self-scan. The corpus is intentionally transparent so contributors can challenge detection quality rather than trust an opaque score.

## Roadmap

- Lockfile publisher and integrity verification
- Installed-version export/API verification
- Diff-aware dataflow and authorization boundary analysis
- Isolated, opt-in exploit reproduction workers
- Python, Go, and Java dependency truth adapters
- GitHub App with inline review comments and organization policy management

## Responsible use

PatchProof is a defensive tool. Findings are decision support, not proof that a system is secure. Human review, tests, dependency controls, secret management, and runtime monitoring remain necessary.

Apache-2.0 · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)
