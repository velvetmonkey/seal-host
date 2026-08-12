# NOTICE — seal-host

Licence: **Apache-2.0** (see `LICENSE`), matching the public `mcp-seal` repository.

This repository is **PRIVATE, pre-award**. The licence is permissive; the moat is
maintained by controlling *what is published, and when*, not by licence
restriction. Access stays private until each layer reaches its release point.

Release schedule (ARIA Safeguarded AI Track 1 bid commitment):

| Layer | Contents | Published |
|-------|----------|-----------|
| **Specification** | Kernel + composition theorem *statements*, `THREAT_MODEL`, `TCB` | Openly, **ahead of bid submission** — we write *about* the kernels |
| **Proofs** | Full Lean proof *sources* | **At grant kickoff** — held back from the public demo |
| **Implementation** | Host, registry, harness, Rust FFI, tooling | **Held back** through the commercialisation window |

The public materials describe the gate *behaviour*; they do not expose the
kernel proofs or the host implementation. Write about them, keep them back from
the demo.

**Do NOT push this repository to a public remote pre-award.** A private remote
(backup, collaboration) is fine.

## ARIA IP terms (verified 2026-06-13)

Confirmed against the Safeguarded AI: Cybersecurity solicitation and ARIA's
published terms:

- Grantees **retain ownership** of what they build and verify, and any tools
  built in the process.
- **Specifications and proof artefacts must be published openly** (Apache-2.0
  fits) — third-party inspection of claims and evidence is the trust basis.
- If no steps toward commercialisation/deployment within **12 months of project
  completion**, ARIA may reassign commercialisation rights or require
  open-sourcing / permissive licensing.

This split is compatible: spec + proofs open (required), implementation retained
private while commercialisation is pursued. The only forced-open risk is the
12-months-post-completion test (programme ends ~Nov 2027, so years off).

Copyright (c) 2026 Ben Cassie.
