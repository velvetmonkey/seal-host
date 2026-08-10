# Proof Reference

The theorem symbols below are stable citations; source and line locations are
deliberately not hand-pinned. `python3 scripts/check_proof_references.py`
discovers each declaration and guarded axiom pin, and fails unless that pin is
inside the live `Test.Axioms` import closure.

| Claim | Theorem symbols | Axiom footprint |
|---|---|---|
| Multi-gate non-bypass over the deployed step core | `Host.step_forward_non_bypass` | Checked by axiom gate; subset of `{propext, Classical.choice, Quot.sound}` |
| Append-only record head changes on append | `Host.Record.head_after_append` | No axioms |
| Tamper-evident record chain under injective hash step | `Host.Record.tamper_evident` | No axioms |
| Netstring target encoding is injective | `Host.Encoding.encodeParts_injective` | `{propext, Classical.choice, Quot.sound}` |
| Authorization implies exact target or a commitment clash | `Host.CapabilityAdequacy.capability_sound_or_commitment_clash` | `{propext, Classical.choice, Quot.sound}` |
| A live approval authorizes only its minted target under A-CR | `Host.CapabilityAdequacy.approval_authorizes_only_its_target'` | `{propext, Classical.choice, Quot.sound}` |
| Minted approvals preserve that target-binding result | `Host.CapabilityAdequacy.minted_approval_authorizes_only_its_target'` | `{propext, Classical.choice, Quot.sound}` |
| Single-request non-interference for the observable decision plus record | `Host.NonInterference.observe_noninterference` | `{propext, Classical.choice, Quot.sound}` |
| Replay isolation across session namespace | `Host.ReplayIsolation.replay_isolation_trace` | `{propext, Classical.choice, Quot.sound}` |
| Cross-session (stateful) non-interference over the composed replay seam | `Host.StatefulNI.stateful_noninterference_trace` | `{propext, Classical.choice, Quot.sound}` |
| No coordination-free double-spend of an approval, transferred to the SealV2 gate model (within TTL, per concurrent replica) | `Host.AuthorityFrontierBridge.sealv2_frontier_card_le_one` | `{propext, Classical.choice, Quot.sound}` |
| Two disconnected replicas never both consume the same approval (bridge corollary) | `Host.AuthorityFrontierBridge.sealv2_no_disconnected_double_availability` | `{propext, Classical.choice, Quot.sound}` |
| Composed allow ⇒ the calibration kernel's executable check passed (trusted Float mirror) | `Host.composed_calibration_bound` | `{propext, Classical.choice, Quot.sound}` |
| Composed allow ⇒ the linear spend was backed and consumed exactly one use | `Host.composed_linear_conservation` | `{propext, Classical.choice, Quot.sound}` |
| Composed allow ⇒ every covering budget resolved the cost and admitted it within its cap | `Host.composed_budget_cap` | `{propext, Classical.choice, Quot.sound}` |
| **Closed algebra: one composed allow carries all seven kernels' invariants, membership-guarded, for any subset** | `Host.registry_closed_algebra` | `{propext, Classical.choice, Quot.sound}` |
| Pure registry model: any gating registered instance's verdict rides the composed allow | `Host.pureVerdicts_mem` + `Host.pure_dispatch_allow_member` | `{propext, Classical.choice, Quot.sound}` |
| **7-kernel deny composition: any kernel's deny commits only the spec-allowed ingests — no budget spend, no capability consumed, no trace event — at the deployed registry selection** | `Host.registry_deny_ingest_only` + `Host.registry_deny_no_budget_spend` + `Host.registry_deny_no_capability_consumed` + `Host.registry_deny_temporal_frozen` + `Host.commitInstsFor_kernels` | `{propext, Classical.choice, Quot.sound}` |
| Dispatch loop plan: the loop's combined verdict, unconditional writes, and allow-only held replay equal `pureCommit`'s components | `Host.dispatch_plan` + `Host.dispatch_verdicts_plan` + `Host.dispatch_ingest_plan` + `Host.dispatch_held_plan` | `{propext, Classical.choice, Quot.sound}` |
| Wiring fidelity: the commit-model mirror equals the deployed `registryFor` instance-by-instance under the common projection (kernel, config, evidence source, pre-call state slot) — and hence every gating decision | `Host.commitInstsFor_wiring` + `Host.commitInstsFor_gates` | `{propext, Classical.choice, Quot.sound}` |
| **Dispatch spelled: the deployed `do`-block IS the explicit recursion** — desugaring, `mut` accumulators, queued-held-write content and order, allow-only replay; gather execution at the deployed registry is the monad law | `Host.dispatch_spelled` + `Host.dispatchGo_cons_pure_gather` + `Host.registryFor_gather_pure` + `Host.registryFor_reader_invariance` | `{propext, Classical.choice, Quot.sound}` |
| Step spelled: one mediation step IS the pure plan around its two IO leaves — field-to-parser marshalling, single judged `line`, fail-closed branches, registry at exactly the marshalled values | `Ffi.stepImpl_spelled` + `Ffi.stepPlanFor` + `Ffi.stepInputsOf` + `Ffi.stepRender` | `{propext, Classical.choice, Quot.sound}` |
| No kernel registered twice: the deployed selection is duplicate-free for every config — no double ingest, no double verdict, at most one instance per stateful ref | `Ffi.registryFor_kernels_nodup` + `Ffi.activeKernels_nodup` + `Ffi.activeKernels_names_nodup` | `{propext, Classical.choice, Quot.sound}` |

The axiom gate is `lake exe axiom_check`. For theorem names imported and pinned
by `Test/Axioms.lean`, `#guard_msgs` makes footprint drift break that target's
build. The composition-algebra rows are pinned **inline** at the bottom of
`Host/Composition.lean` (the same `#guard_msgs` mechanism), so their footprints
are enforced whenever that module builds.

**Build-wire residual (2026-08-05).** This is not repository-wide coverage.
Of 53 theorem-bearing modules in the tracked tree, 51 are inside the
`Test.Axioms` import closure. Two remain outside it and are therefore not
built or axiom-pinned by `lake exe axiom_check`:

- `Host.CanonicalL0Liveness` — DROPPED FROM THE RELEASE CLAIM (Ben, 2026-08-01);
  reserved in `scripts/proof_inventory.py`.
- `Test.A2DivergenceClassification` — theorem-bearing since 2026-07-30, imported
  by nothing on a default target, reachable only via the non-default `Test.+`
  library glob.

Five modules that an earlier residual (2026-08-01) listed as excluded are now
**inside** that closure as direct imports of `Test/Axioms.lean` (wired
`4eb6bb4`, 2026-08-01): `Host.DurabilityA6`, `Host.EgressPerimeter`,
`Host.EgressStrength`, `Host.PolicyOverlap`, and `Host.StrictPerimeter`. Their
inline `#guard_msgs` pins therefore run whenever `axiom_check` builds. See
[LIMITATIONS.md](LIMITATIONS.md#proof-build-wire-residual).

Two rows deserve a closer look. The record-chain rows (`head_after_append`, `tamper_evident`) carry an **empty** axiom footprint — stronger than the family's usual minimal classical fragment: collision resistance (A-CR) and genesis freshness (A-GEN) enter `tamper_evident` as explicit hypotheses in the statement, not as axioms, so the theorem itself is axiom-free. The two bridge rows are instances of the abstract coordination-free impossibility proven in [crdt-lean](https://github.com/velvetmonkey/crdt-lean) (`Crdt/AuthorityFrontier.lean`), applied to this repo's real consume seam (`validateAndConsumeWithStore`) as a TTL-scoped instance mapping.

## The composition closed algebra

**The guarantee.** Compose ANY subset of the seven verified kernels — Safety (S), Consensus (C), Convergence (V), Temporal (T), Linear (L), Budget (B), Calibration (K) — under the host's fail-closed AND-gate, in any order. `Host.registry_closed_algebra` is ONE theorem stating that a single composed allow simultaneously carries every present kernel's proven safety invariant: a guarded call had a live matching approval (S); two composed allows against the same votes ratify the same value (C); the admitted op is in the proven-convergent set (V); no configured LTL safety policy forbids the call (T); the spend was capability-backed and consumed exactly one use (L); every covering budget admitted the cost within its cap (B); the executable calibration check passed (K). Each conjunct is guarded by that kernel's verdict membership, so absent kernels drop out vacuously — that is what makes the algebra closed over subsets. The pure registry model (`Host.PureInst` / `Host.pureVerdicts` in `Host/Registry.lean`, with `pure_dispatch_allow_member`) instantiates the membership guards at the registry fold, making "any registered subset" literal.

**Non-claims — read these before quoting the guarantee:**

- **SAFETY fragment only.** Nothing here is liveness or progress: a kernel may deny every call forever and every theorem above stays true. "Composed allow implies invariant" says nothing about allows ever happening.
- **A3 crypto is trusted, not proven.** Ed25519 signature verification and approval-channel freshness are assumptions of the deployment, outside these theorems (no opaque crypto symbol appears in any composition proof's axiom footprint — the pins enforce that).
- **Config is trusted operator input.** Rosters, caps, gated-tool lists, grant files, calibration windows: the theorems hold relative to whatever config was loaded; they do not validate it.
- **The deployed consensus certificate binds the tool name, not the argument bytes.** The DEPLOYED `consensusKernel` votes on `act.tool` (tool-string granularity); byte-level binding is proven (`byteConsensusKernel`, `Kernels/ConsensusBytes.lean` + `Host/CompositionBytes.lean`) but wiring it into dispatch is future work — the deployed kernel is unchanged.
- **The calibration conjunct is the executable check only.** `calibratedB = true` is Float arithmetic — a documented trusted mirror of calibration-lean's conditional sub-Gaussian / Azuma–Hoeffding mathematics (`ProbabilityTheory.hasCondSubgaussianMGF_of_mem_Icc`), cited not extracted. The measure-theoretic δ-bound is NOT formally connected to the Float computation; kernel K stays experimental for exactly this reason.
- **The IO realization is TCB.** The theorems quantify over pure verdict lists and the pure registry model. `Host.dispatch`'s loop-body state plan is now proven (`Host.dispatch_plan`: the verdicts it combines, its unconditional ingest writes, and its allow-only held replay equal `pureCommit`'s components, in the loop's own `phase1Held` vocabulary), and the deny side is closed registry-wide (`Host.registry_deny_ingest_only`). The mirror's per-instance wiring against `registryFor` is now proven, not inspected: `Host.commitInstsFor_wiring` shows the two lists project to the same instances (kernel identity and order, config section, evidence source — each deployed `gather` equals the constant returning the mirror's evidence — and pre-call state slot, for every pure reading of the session refs consistent with the mirror's state arguments), and `Host.commitInstsFor_gates` carries that to every gating decision. The IO shell is now SPELLED: `Host.dispatch_spelled` proves the deployed `do`-block equals its explicit recursion (desugaring, accumulator order, queued-held-write content/order, allow-only replay), `Ffi.stepImpl_spelled` proves the step is the pure plan around its two IO leaves, and gather execution at the deployed registry is the monad law (`registryFor_gather_pure`). What remains trusted is exactly the opaque core — the VALUE semantics of `ST.Prim.Ref.get`/`set`/`mkRef` (`opaque` externs in Lean core; nothing to unfold), the typed-runtime trust that covers ref distinctness (the five session refs have pairwise-distinct state types; `registryFor_kernels_nodup` pins one instance per kernel), and the `unsafeBaseIO`/FFI/Rust/OS boundary — see `docs/POLICY-ASSURANCE-BOUNDARY.md` for the named, justified list.
