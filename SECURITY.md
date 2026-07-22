# Security Policy

Seal is a **pre-production, research-grade high-assurance MCP mediation system.** Its Lean
kernel proves selected authorization properties under documented assumptions; the deployed
host and verifier are connected by tests and replayable evidence, not an end-to-end proof.
It has not completed an independent security audit. Read `docs/LIMITATIONS.md` and
`THREAT_MODEL.md` before deploying it anywhere that matters.

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.1.x | Supported |
| `main` | Best effort; not a release channel |
| Earlier | Unsupported |

## Reporting a vulnerability

**Email `security@velvetmonkey.com`.** If email is unavailable, open a private
[GitHub Security Advisory](https://github.com/velvetmonkey/seal-host/security/advisories/new)
on this repository.

Do not disclose publicly before the coordinated-disclosure window below has run.

Include where you can:

- the affected repository and commit;
- a minimal reproduction, or a receipt that exhibits the issue;
- whether the issue concerns proof source, conformance artifacts, deployment glue, or
  documentation;
- any key, token, or operator action involved;
- your preferred credit name, or a request to remain anonymous.

**Do not include** real customer secrets, production approvals, or private model prompts. A
redacted reproduction is worth more to us than a real one.

## What you can expect

| Stage | Target |
| --- | --- |
| Acknowledgement of receipt | 3 business days |
| Triage decision and severity assignment | 10 business days |
| Fix or documented mitigation, Critical / High | 30 days from triage |
| Fix or documented mitigation, Medium / Low | 90 days from triage |
| Coordinated public disclosure | by mutual agreement, default 90 days from triage |

If we miss a target we will say so and give a revised date rather than go quiet. If we
disagree that a report is a vulnerability, we will say that plainly and explain why, and you
remain free to disclose after the window.

Severity uses CVSS v3.1 as a starting point, adjusted for this system's assumption
boundary: an issue that defeats a property we **claim** to hold is more severe than one in
an area we already document as trusted or out of scope.

## Scope

**In scope:** the Lean kernel and its proofs; the Rust host and FFI boundary; the verifier
and assurance kit; receipt and envelope formats; key handling and the signed configuration
path; the release and build pipeline; and any case where a **published claim in `CLAIMS.md`
is false**, which we treat as a security issue in its own right.

**Out of scope**, because they are documented as trusted or unmediated rather than
defended, are the non-mediated paths in `THREAT_MODEL.md`: direct shell or network access by
the agent, alternate MCP configurations or endpoints, previously cached tool handles,
in-process orchestrator calls, spawned subprocesses, non-`tools/call` MCP methods, and
response egress. Reports here are still welcome and useful, but they confirm a documented
boundary rather than break a claim.

Also out of scope: findings against a deployment that has deliberately disabled security
controls, denial of service by resource exhaustion, missing hardening headers on
non-existent web surfaces, and automated scanner output with no demonstrated impact.

## Safe harbour

We will not pursue or support legal action against anyone who, in good faith:

- researches and reports vulnerabilities under this policy;
- avoids privacy violations, data destruction, and service degradation;
- works only against their own installation or test data, never third-party deployments;
- gives us reasonable time to remediate before public disclosure.

If a third party brings action against you for research conducted under this policy, we will
make it known that your actions were authorised.

## Handling and credit

Reports are triaged privately. Fixes ship with a GitHub Security Advisory and, where the
issue warrants one, a **CVE requested through GitHub as CNA**. Advisories name the affected
versions, the fixed version, and the exact commit and artifact hashes.

Reporters are credited by name unless they ask otherwise. **There is currently no paid bug
bounty.** We would rather say that than imply one exists.

## Ownership

Security reports are owned by the repository operator, who is responsible for
acknowledgement, triage, remediation, and disclosure. There is no 24/7 rotation; this is a
small project, and the timelines above are set to be honest about that rather than
aspirational.
