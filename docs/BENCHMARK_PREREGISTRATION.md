# Real-world AI-assisted code benchmark preregistration

Status: **locked before corpus collection**. Method changes require a new version and will not be applied retroactively.

## Research questions

1. What precision does PatchProof achieve on naturally occurring, public AI-assisted pull requests?
2. What recall does it achieve against independently discovered vulnerabilities in that audited corpus?
3. What recall does it achieve on a separate seeded set with known vulnerabilities?
4. Which findings are uniquely surfaced relative to CodeQL and Semgrep under documented default configurations?

Natural and seeded results will never be combined into one recall number.

## Sampling frame and stopping rule

- Collection begins only after the commit containing this protocol.
- The primary corpus closes at the first **500 eligible PRs** or **2026-12-31 23:59 UTC**, whichever occurs first.
- Eligible languages: JavaScript/TypeScript, Python, Go, and Java.
- PRs must be public, accessible at labeling time, contain a source-code change, and have a repository license permitting analysis and short excerpt publication.
- Bots, generated dependency-update PRs, vendored-code-only changes, test-fixture-only changes, deleted repositories, and PRs over 20,000 changed lines are excluded.
- AI assistance is recorded as `confirmed`, `self-reported`, `suspected`, or `unknown`. Only confirmed and self-reported cases enter the primary AI-assisted estimate. Suspected and unknown cases are reported separately and cannot upgrade the primary result.
- Evidence for AI assistance must pre-exist scanning: author statement, commit/PR disclosure, recognized co-author metadata, or repository coding-agent configuration plus PR-level agent attribution. Code style alone is insufficient.
- Eligible PRs are ordered deterministically by SHA-256 of `protocol-commit-SHA || canonical-PR-URL`; the lowest hashes are selected. The final protocol commit SHA is the sampling seed.
- Language, repository size, stars, or finding presence will not be used to cherry-pick cases after scanning.

## Labeling protocol

- Two reviewers independently inspect the raw diff, surrounding code, dependency manifests, and tests **without seeing PatchProof, CodeQL, or Semgrep output**.
- Before labeling starts, reviewer pseudonyms, relevant experience, conflicts, and independence from PatchProof implementation are recorded in a committed `benchmark/reviewers.json`.
- Each reviewer selects `vulnerable`, `safe`, or `uncertain`, assigns CWE/severity when vulnerable, and records a concise rationale.
- Original votes are immutable. Disagreements go to a third adjudicator who records a separate final label without replacing either vote.
- Cases remain `uncertain` when evidence is insufficient; they are excluded from binary precision/recall and counted explicitly.
- Ten percent of agreed cases are randomly selected with the same commit-seeded hashing method for third-reviewer spot checks.

## Agreement metrics

- Primary agreement metric: **Cohen's kappa** on the two initial binary labels after excluding `uncertain`.
- Secondary metrics: raw percent agreement, uncertain rate, three-way confusion matrix, and adjudication rate.
- Kappa and raw agreement are always published together because expected class imbalance can make either misleading alone.

## Detection metrics

- Natural-corpus precision: confirmed PatchProof true positives divided by all PatchProof findings receiving a binary ground-truth label.
- Natural-corpus recall: PatchProof-detected vulnerabilities divided by all vulnerabilities independently identified during full manual review of sampled PRs.
- Seeded recall: detected seeded vulnerabilities divided by all seeded vulnerabilities. Seeded cases are versioned and excluded from natural-corpus metrics.
- Report precision, recall, F1, false positives per 1,000 changed lines, results per rule/language/evidence level, and bootstrap 95% confidence intervals.
- CodeQL and Semgrep comparison uses pinned versions/configuration recorded with results. A tool timeout/error is reported, never treated as a clean scan.
- No metric definition, exclusion, or severity threshold changes after results are visible.

## Headline-finding threshold

A case may become a named case study only when all conditions hold:

1. Final severity is high or critical.
2. Both initial reviewers and the adjudicator agree it is vulnerable.
3. The behavior is `registry_verified`, `installed_verified`, or independently reproduced with documented safe steps.
4. The issue exists in the submitted change and has plausible confidentiality, integrity, availability, or supply-chain impact.
5. Responsible disclosure is complete under [DISCLOSURE.md](DISCLOSURE.md).
6. The maintainer explicitly consents to being named.

If no case meets every condition, publication is limited to aggregate anonymized results. Borderline findings cannot be promoted to manufacture a story.

## Reproducibility and privacy

- Store immutable source URLs, commit SHAs, file paths, licenses, collection times, tool versions, configuration hashes, labels, and snippet hashes.
- Do not commit live secrets, exploit payloads, personal data, or embargoed vulnerability details.
- Public excerpts must be minimal and license-compatible.
- Embargoed records remain outside the public repository until disclosure completes.

## Deviations

Operational deviations are appended with date, reason, affected cases, and author. The original protocol remains visible. Deviations are reported alongside results and cannot silently rewrite the study.
