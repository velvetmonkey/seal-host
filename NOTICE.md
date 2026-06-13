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

The public demo (`mcp-seal` × `canary`) shows the gate *behaviour*; it does not
expose the kernel proofs or the host implementation. Write about them, keep them
back from the demo.

**Do NOT push this repository to a public remote pre-award.** A private remote
(backup, collaboration) is fine.

Copyright (c) 2026 Ben Cassie.
