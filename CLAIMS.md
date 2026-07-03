<!-- SPDX-License-Identifier: Apache-2.0 -->
# seal-host: claims map

Single source of truth for what this repo proves, what it merely runs, and what
it must never claim. Scoped to `seal-host` (the multi-kernel fail-closed host).
Sibling maps: `mcp-seal-dev/CLAIMS.md` (v2 canonical core). Nothing in any
demo, README, or pitch may exceed a row marked "can say publicly = yes".

## The one line

> Policy-covered, unapproved request-effects cannot execute through the
> mediated MCP boundary.

NOT: "the agent is safe" / "the whole stack is verified" / "theorems cannot be
bypassed."

## Profiles

The host runs a **profile**. This is load-bearing for every claim below.

| Profile | Canonical-reject `tools/call` | Forward carries | Status |
|---|---|---|---|
| `compatible` (this repo, today) | mediated on the V1 `Lean.Json` view, `ast? = none`, audit-only | V1 route decision | IMPLEMENTED (`Host/Canonical.lean`) |
| `canonical-l0` | BLOCKS | canonical parse witness | IMPLEMENTED AT THE PROOF LAYER (`Host/CanonicalL0.lean`: `stepRouteP .canonicalL0`, reject-on-parse-failure + witness-on-forward proven); NOT the deployed routing path (`Ffi.stepImpl` still runs `compatible`) |

Do not describe the deployed host as strict canonical-l0. It is `compatible`.
The canonical AST is audit input for kernels, not the mediation gate.

## Claims matrix

| Claim | Artifact | Proof status | Trusted assumptions | Known residuals | Say publicly? |
|---|---|---|---|---|---|
| Registry denies if no kernel gates the call; allows only if every gating kernel allows | `Host/Registry.lean` composition theorem | Lean theorem | Lean kernel/runtime | — | yes |
| Fail-closed AND-composition preserves headline invariants (safety non-bypass, consensus agreement) | composition theorem | Lean theorem | as above | scoped to registered kernels | yes |
| `Forward` is unconstructible without an exact kernel verdict | Rust bridge type | Rust type-level | Rust type soundness | — | yes |
| Lean-panic fail-open risk is closed | abort-on-panic in `rust/` | code + test | abort semantics | — | yes |
| Complete mediation modulo A1-A4, A2 minimised by construction; A6 (durability) stated, not hidden | THREAT_MODEL.md capstone | mixed (see below) | A1-A4 | A6 | yes (verbatim only) |
| W2-T2: byte-quorum consensus (MODEL) — a `canonicalL0` forward with the byte-consensus verdict among the combined verdicts implies a strict-majority `validB` quorum ratified exactly the forwarded action's canonical bytes, the ratified cert's value IS those bytes, and two such forwards under the same roster+votes agree byte-for-byte | `Kernels/ConsensusBytes.lean`, `Host/CompositionBytes.lean` | Lean theorem | model-level kernel: the DEPLOYED `consensusKernel` votes on `act.tool` (tool-string granularity); byte binding proven under the `canonicalL0` profile, deployed profile is `compatible`; vote authenticity/transport TCB | deployed kernel unchanged; wiring `byteConsensusKernel` into dispatch is future work | yes, "model-level" mandatory |
| W2-T3: composition residual — non-vacuous denies survive gate extension (`combine_deny_append`); allows restrict to any non-empty gate prefix (`combine_allow_restrict`); the `vs ≠ []` empty-deny boundary is stated and witnessed (`combine_extension_from_empty`) | `Host/Composition.lean` | Lean theorem (corollaries of `combine_allow_iff`/`combine_deny_of_member`) | Lean kernel/runtime | decidability candidate skipped: `VerdictKind` DecidableEq already gives it | yes |
| W2-T1: timed record admissibility — accepted entries are δ-fresh against the producing step's monotone clock; stale-clock, clock-regressed, and replayed-nonce entries are inadmissible; admissible appends preserve log clock-sortedness and nonce uniqueness; chain spine (append-only, tamper-evidence) inherited from L1 CORE under A-CR + A-GEN + A-ENC (injective entry encoding) | `Host/RecordTemporal.lean` | Lean theorem (spine inherited) | monotone host/LOGICAL clock feeding `now` (NOT wall clock — wall clock + runtime nonce/TTL remain TCB, `a3.rs`); A-ENC undischarged for the deployed `TimedEntry.line` encoder | statement-level: the runtime does not yet enforce `admissible` | yes, with the logical-clock caveat verbatim |

## Assumptions and residuals (A1-A6)

- **A2 (numeric/parse fidelity)** minimised by construction (canonical strict subset), not eliminated. Per-server equivalence obligation remains.
- **A4 (atomic consume)** discharged by the host `Mutex` carrying M6 atomic-consume; concurrency-tested 16->1 Allow.
- **A5 (single-use replay)** discharged by construction: the store IS `listReplayStore`.
- **A6 (cross-restart durability)** the in-process replay store discharges A5 for the live process only; cross-restart durability is a stated residual, a deployment-config concern, first funded hardening item. NOT a proof gap that is hidden.

## Trusted config signatures (roadmap, not a production claim)

`Host/Config.lean` currently verifies a **stub** signature:
`stub-ed25519:<pk>:<payload>` (string equality, `Host/Config.lean:120`). This is
fine pre-award and MUST NOT be described as real crypto.

- today: stub config signature in the host framework
- v2 approval path: real Ed25519 leaf (mcp-seal-dev has real `ed25519Verify` over canonical signed-message bytes)
- S1/S2: real Ed25519 config envelope + durable (cross-restart) replay store

## Response egress

seal mediates **request-effects**, not responses. Never say "seal prevents
leaks." It prevents unapproved effects through the mediated request boundary.
