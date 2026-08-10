# NOTICE — seal-host

Licence: **Apache-2.0** (see `LICENSE`), matching the public `mcp-seal` repository.

This repository is **PUBLIC**. The licence is permissive; the moat is
maintained by controlling *what is published, and when*, not by licence
restriction. The source is public; release timing still governs which layers are published.

Release schedule (ARIA Safeguarded AI Track 1 bid commitment):

| Layer | Contents | Published |
|-------|----------|-----------|
| **Specification** | Kernel + composition theorem *statements*, `THREAT_MODEL`, `TCB` | Openly, **ahead of bid submission** — we write *about* the kernels |
| **Proofs** | Full Lean proof *sources* | **At grant kickoff** — held back from the public demo |
| **Implementation** | Host, registry, harness, Rust FFI, tooling | Public source; release artifacts still follow the release gate |

The public demo (`mcp-seal` × `canary`) shows the gate *behaviour*; released
artifacts and public source remain separate publication surfaces.

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
