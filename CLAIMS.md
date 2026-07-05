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
| Registry denies if no kernel gates the call; allows only if every gating kernel allows | `Host/Registry.lean` composition theorem | Lean theorem | Lean kernel/runtime | none | yes |
| Fail-closed AND-composition preserves headline invariants (safety non-bypass, consensus agreement) | composition theorem | Lean theorem | as above | scoped to registered kernels | yes |
| `Forward` is unconstructible without an exact kernel verdict | Rust bridge type | Rust type-level | Rust type soundness | none | yes |
| Lean-panic fail-open risk is closed | abort-on-panic in `rust/` | code + test | abort semantics | none | yes |
| Complete mediation modulo A1-A4, A2 minimised by construction; A6 (durability) stated, not hidden | THREAT_MODEL.md capstone | mixed (see below) | A1-A4 | A6 | yes (verbatim only) |
| W2-T4: convergence potential (MODEL): the undelivered-update count is a Lyapunov function over crdt-lean's `DeliverySystem`: non-increasing, strictly decreased by each delivery of a new update, zero exactly at full delivery, zero ⇒ replica state = converged state, eventually zero under fairness + quiescence | `Kernels/ConvergencePotential.lean` | Lean theorem | fairness + quiescence are `DeliverySystem` hypotheses (asserted network assumptions); kernel-op ↔ model-update binding is interpretive via `composed_convergent` | model-level; per-event acceptance modeled as delivery-of-new-update | yes, "model-level, conditional on fairness" mandatory |
| W2-T6: channel non-bypass (MODEL): any adapter trace meeting step-local obligations O1 (emit only licensed bytes) ∧ O2 (no manufactured licenses) ∧ O3 (byte fidelity via license pairs) mediates every action: each emission has a strictly earlier decide event returning Allow of byte-identical output; at gate = `SealV2.decide`, emitted bytes are canonical serializations of VALIDATED capabilities; rogue (O1-violating) and forger (O2-violating) adapters witnessed failing | `Host/ChannelModel.lean` | Lean theorem | model-level: Rust adapter compliance with O1-O3 is TCB until refined (named future work); gate clause aligned with `SealV2.decide`, not the deployed `compatible` profile | Rust refinement of `rust/` against O1-O3 = named future work | yes, "model-level" mandatory |
| W2-T6.1: seal adapter conformance (MODEL): `sealAdapter`, a Lean model of the DEPLOYED routing core (mirroring `rust/src/main.rs`'s gated-sink discipline), DISCHARGES the capstone's O1/O2 hypotheses (`sealAdapter_O1`, `sealAdapter_O2`), so `channel_preserves_non_bypass` holds unconditionally at it (`sealAdapter_trace`): every emission is preceded strictly earlier by an Allow decide of byte-identical output. Closes the W2-T6 gap that no adapter modelling the deployed core had been proven compliant | `Host/SealAdapter.lean` | Lean theorem | model-level: the byte-level refinement `rust/` ↔ `sealAdapter` (that the compiled binary implements the model's transition discipline) stays TCB, named future work; wall clock + approval providers stay TCB | binary refinement `rust/` ↔ model = named future work; deployed profile still `compatible` (not canonical-l0) | yes, "model-level discharge; binary refinement still future" mandatory |
| W2 closeout: single-request non-interference: for one request, the decision and audit record reveal nothing about `ApprovalState` beyond `authView raw`; landed theorem names are `decide_authView_noninterference`, `record_authView_noninterference`, and `observe_noninterference`, with `authView_noninterference_nonvacuous` as the witness | `Host/NonInterference.lean` | Lean theorem | controlled declassification of exactly the authorization bit; per-kernel verdict strings are LOW host inputs | timing channels and timed logs out of scope; no multi-request secrecy claim | yes, "single request / authView only" mandatory |
| W2 closeout: replay isolation: under a fixed per-request state, stores equal on the observer session's projection produce the same decision trace and preserve that projection; landed theorem names include `store_lowEq_step`, `replay_isolation_trace`, `replay_isolation_nonvacuous`, and `listReplayStore_namespaceLocal` | `Host/ReplayIsolation.lean` | Lean theorem | fixed `ApprovalState`; durable-store seam modeled as a list store | does not prove cross-restart durability or two-state non-interference composition | yes, with fixed-state caveat |
| W2 closeout: deployed adapter by name: `deployedAdapter` aliases the `sealAdapter` model and discharges O1/O2 at the deployed name (`deployed_O1`, `deployed_O2`); `deployed_preserves_non_bypass` gives the capstone, `deployed_nonvacuous` rules out vacuous always-deny, and live-Allow hypothesis forms pin emitted/licensed bytes | `Host/DeployedAdapter.lean` | Lean theorem | model-level; binary correspondence is tested by the conformance bridge, not proven | Rust/source/binary refinement remains TCB; deployed profile remains `compatible` | yes, "model-level, bridge-tested binary correspondence" mandatory |
| W2-T2: byte-quorum consensus (MODEL): a `canonicalL0` forward with the byte-consensus verdict among the combined verdicts implies a strict-majority `validB` quorum ratified exactly the forwarded action's canonical bytes, the ratified cert's value IS those bytes, and two such forwards under the same roster+votes agree byte-for-byte | `Kernels/ConsensusBytes.lean`, `Host/CompositionBytes.lean` | Lean theorem | model-level kernel: the DEPLOYED `consensusKernel` votes on `act.tool` (tool-string granularity); byte binding proven under the `canonicalL0` profile, deployed profile is `compatible`; vote authenticity/transport TCB | deployed kernel unchanged; wiring `byteConsensusKernel` into dispatch is future work | yes, "model-level" mandatory |
| W2-T3: composition residual: non-vacuous denies survive gate extension (`combine_deny_append`); allows restrict to any non-empty gate prefix (`combine_allow_restrict`); the `vs ≠ []` empty-deny boundary is stated and witnessed (`combine_extension_from_empty`) | `Host/Composition.lean` | Lean theorem (corollaries of `combine_allow_iff`/`combine_deny_of_member`) | Lean kernel/runtime | decidability candidate skipped: `VerdictKind` DecidableEq already gives it | yes |
| W2-T1: timed record admissibility: accepted entries are δ-fresh against the producing step's monotone clock; stale-clock, clock-regressed, and replayed-nonce entries are inadmissible; admissible appends preserve log clock-sortedness and nonce uniqueness; chain spine (append-only, tamper-evidence) inherited from L1 CORE under A-CR + A-GEN + A-ENC (injective entry encoding) | `Host/RecordTemporal.lean` | Lean theorem (spine inherited) | monotone host/LOGICAL clock feeding `now` (NOT wall clock; wall clock + runtime nonce/TTL remain TCB, `a3.rs`); A-ENC undischarged for the demonstration `TimedEntry.line` encoder (discharged for `encCanonical`, next row) | statement-level: the runtime does not yet enforce `admissible` | yes, with the logical-clock caveat verbatim |
| W2-T1 hardening: A-ENC DISCHARGED: `TimedEntry.encCanonical` (length-prefixed, delimiter-safe) is injective by Lean proof (`encCanonical_injective`, pure structural, no crypto); `timed_tamper_evident_canonical` gives timed tamper-evidence under A-CR + A-GEN ALONE, exactly the landed L1 crypto TCB, no encoder side-condition | `Host/RecordTemporalCanonical.lean` | Lean theorem | A-CR + A-GEN only (the L1 crypto TCB); monotone-clock caveat as above | `TimedEntry.line` remains demonstration-grade (unused by this theorem) | yes |
| Deployed receipt commitment: production audit certificates are chained with SHA-256 (`sha256(prevHeadHex || 0x1f || payload)`) by `rust/src/receipt.rs` and independently by `scripts/seal_log.mjs`; conformance checks the deployed host's emitted head against the model-derived head | Rust host + `scripts/seal_log.mjs` + `scripts/conformance_bridge.mjs` | code + differential evidence | SHA-256 collision resistance is A-CR TCB; `node:crypto`/Rust `sha2` implementations and harness are TCB | no Lean proof of SHA-256 CR; evidence over corpus C only | yes, "A-CR is TCB, not proven" mandatory |

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
