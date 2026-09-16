# Security policy

## Supported versions

The latest release receives security fixes. Please avoid public issues for undisclosed vulnerabilities.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** flow under the Security tab. Include the affected version, reproduction steps, impact, and any proposed mitigation. We aim to acknowledge reports within 72 hours.

PatchProof never uploads repository source. Registry truth checks send only declared package names to their public registry. Use `--offline` to disable those requests.

Executable proofs run author-supplied code. Review [THREAT_MODEL.md](THREAT_MODEL.md) before enabling them, especially in pull-request workflows.
