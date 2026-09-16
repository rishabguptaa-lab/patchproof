# Executable proof threat model

PatchProof **does not generate exploits**. It executes proofs supplied by repository authors and reports whether the declared expectation was observed. `execution_verified` means the pinned proof command produced its expected result in the sandbox; it does not independently establish that the proof is honest, complete, or linked to every scanner finding.

## Assets and trust boundaries

- The host runner, GitHub token, organization secrets, caches, and adjacent workloads must remain protected.
- Pull-request source, proof scripts, proof manifests, expected output strings, dependencies, and build tools are untrusted.
- A reviewed base-branch workflow and a pinned proof-bundle SHA-256 are trust anchors. The bundle covers the manifest plus every file declared in its `files` array.
- Docker is a security boundary with known limitations, not a perfect virtual-machine boundary.

## Malicious-manifest attacks

An attacker may attempt to:

1. Print the expected marker without reproducing a vulnerability.
2. Change `expect.stdoutIncludes`, the command, runtime, or timeout to manufacture a pass.
3. Read repository content or accidentally mounted credentials.
4. Exhaust memory, CPU, disk, processes, or execution time.
5. Reach the network to exfiltrate data or download a second-stage payload.
6. Abuse the container runtime, kernel, image, or parser to escape isolation.
7. Poison caches or write artifacts consumed by later privileged jobs.

## Enforced controls

- The proof bundle can be pinned by SHA-256; pull-request execution requires the pin. Changing the manifest or any declared proof script/helper invalidates it.
- Fork pull-request proof manifests are refused by the GitHub Action.
- The container receives no inherited environment except its image defaults.
- Networking is disabled.
- The repository and root filesystem are read-only.
- Linux capabilities are dropped and `no-new-privileges` is enabled.
- Memory, CPU, PID, timeout, and temporary-storage limits are applied.
- Output is bounded and the complete captured transcript is hashed.
- Proof artifacts are written by the host only after the container exits.

## Residual risks

- A proof can intentionally print the expected marker. Human review of proof logic remains required.
- Dynamically loaded or transitive proof code omitted from the manifest's `files` array is outside the pin. Reviewers must require the complete executable/import closure to be declared.
- Same-kernel container isolation cannot eliminate kernel/container-runtime escape risk.
- A vulnerable language runtime or pre-approved image can expand the attack surface.
- A proof can read all source mounted into `/workspace`.
- Denial of service within the configured limits remains possible.

## Recommended workflows

### Trusted branches

Run proofs after the manifest and scripts are reviewed. List every executable and imported proof file, pin the resulting bundle hash in the workflow, and keep workflow changes behind CODEOWNERS and branch protection.

### External forks

Do not run proof code in a secret-bearing or long-lived runner. PatchProof refuses this path by default. If external code must be tested, copy a reviewed proof from the protected base branch into a disposable VM with no secrets, no persistent cache, an ephemeral filesystem, and a short-lived least-privilege token. Destroy the VM after the run.

### Interpreting results

- `pattern_match` is a detector result.
- `manifest_verified` and `registry_verified` are metadata checks.
- `execution_verified` confirms only that a trusted, pinned proof met its declared expectation.
- None of these labels alone proves that an application is secure or that an exploit is impossible.

Report sandbox bypasses privately using the process in [SECURITY.md](SECURITY.md).
