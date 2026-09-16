# Vulnerability disclosure protocol

## Intake and validation

1. Reproduce safely without accessing data that does not belong to the research team.
2. Record affected commit/version, impact, prerequisites, evidence level, and minimal remediation.
3. Have a second reviewer confirm the issue before contacting anyone.
4. Stop testing if validation would require persistence, credential use, destructive actions, or interaction with production data.

## Private notification and clocks

- Contact the repository's published security channel or GitHub private vulnerability reporting first.
- Default coordinated disclosure window: **90 days from acknowledged receipt**.
- Critical, trivially exploitable issues may use a proposed 30-day window through agreement with the maintainer.
- Credible active exploitation is escalated immediately to maintainers, hosting/registry security teams, and relevant incident responders; public timing is coordinated rather than automatically shortened.
- An unacknowledged report receives follow-ups after 7 and 21 days. At 45 days, seek a neutral coordinator such as GitHub Security Lab, CERT/CC, or the applicable ecosystem security team.
- Deadlines may be extended for good-faith remediation. Safety takes priority over a marketing date.

## GHSA, CVE, and registry escalation

- Request GHSA/CVE coordination when a vulnerability affects released software and has a concrete confidentiality, integrity, or availability impact. Download count does not determine eligibility.
- Reach—downloads, dependents, deployments, and exploitability—changes urgency and coordination scope, not whether a genuine released vulnerability deserves tracking.
- Suspected malicious, hijacked, typosquatted, or slopsquatted packages are reported privately to the relevant registry and hosting provider immediately. Do not install or interact with suspected command-and-control infrastructure.
- Credential exposure is handled through the provider's revocation channel and never reproduced by using the credential.

## Publication

- Obtain explicit consent before naming a repository, organization, or maintainer, even after remediation.
- Share drafts with affected maintainers for factual review without granting editorial control over accurate methodology.
- Remove live exploit details when publication could create disproportionate risk.
- If consent is absent or the headline threshold is not met, publish only aggregate anonymized results.
- Clearly separate facts, inference, and unresolved uncertainty.

This protocol is a research policy, not legal advice. Applicable platform rules, laws, and coordinated-disclosure guidance take precedence.
