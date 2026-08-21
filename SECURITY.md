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

## Channel status

GitHub private vulnerability reporting is the canonical channel for this
repository. It is enabled: the GitHub API returned HTTP 200 with `enabled: true`
when checked on 2026-08-10. The form below is the working private intake channel.

## Reporting a vulnerability

Open a private [GitHub Security
Advisory](https://github.com/velvetmonkey/seal-host/security/advisories/new) on
this repository. Do not put sensitive report details in a public issue.

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
| Coordinated public disclosure | by mutual agreement, default **90 calendar days from initial receipt** |

The disclosure clock runs from **receipt**, not from triage, so a missed or delayed triage
cannot postpone it. **If no acknowledgement reaches you within 10 business days, you are free
to disclose**, and we would rather you did than sit on a live issue. Earlier disclosure is
also reasonable where there is active exploitation or urgent public risk; tell us if you can,
but do not wait on us.

If we miss a target we will say so and give a revised date rather than go quiet. If we
disagree that a report is a vulnerability, we will say that plainly and explain why, and you
remain free to disclose after the window.

Severity uses CVSS v3.1 as a starting point, adjusted for this system's assumption
boundary: an issue that defeats a property we **claim** to hold is more severe than one in
an area we already document as trusted or out of scope.

## Scope

<!-- FLEET-CLAIM:BEGIN -->
**In scope:** the Lean kernel and its proofs; the Rust host and FFI boundary; the verifier
and assurance kit; receipt and envelope formats; key handling and the signed configuration
path; the release and build pipeline; and any case where a **published claim in `CLAIMS.md`
is false**, which we treat as a security issue in its own right.
<!-- FLEET-CLAIM:END -->

**The false-claim rule controls.** A defect in a named TCB component remains **in scope** if
it falsifies a published claim under that claim's stated preconditions. A named unmediated
route is out of scope only when it stays outside those preconditions and does not expose an
undocumented route or a false claim. Where the two rules below appear to conflict, the
false-claim rule wins.

**Out of scope**, because they are documented as trusted or unmediated rather than
defended, are the non-mediated paths documented across `THREAT_MODEL.md`, `RUST_BRIDGE.md`
and `TCB.md`: direct shell or network access by
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

Research that complies with this policy is considered **authorised by us**. If a third party
brings action against you for such research, we will say so, **to the extent of our legal
authority** — which does not extend to third-party infrastructure, upstream components, or
rights we do not hold.

## Handling and credit

Reports are triaged privately. **Where applicable and available**, fixes ship with a GitHub
Security Advisory and, where the issue warrants one and the repository is eligible, a CVE
requested through GitHub as CNA; advisories then name the affected versions, the fixed
version, and the exact commit and artifact hashes. Not every valid report yields a release
artifact: a **false published claim** may warrant a documentation correction and disclosure
with no CVE and no new build, and that is still a resolved security issue under this policy.

Reporters are credited by name unless they ask otherwise. **There is currently no paid bug
bounty.** We would rather say that than imply one exists.

## Ownership

Security reports are owned by the repository operator, who is responsible for
acknowledgement, triage, remediation, and disclosure. There is no 24/7 rotation; this is a
small project, and the timelines above are set to be honest about that rather than
aspirational.
