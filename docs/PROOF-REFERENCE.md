# Proof Reference

The file and line numbers below were verified by grep in this repository.

| Claim | Theorem | Location | Axiom footprint |
|---|---|---|---|
| Multi-gate non-bypass over the deployed step core | `Host.step_forward_non_bypass` | `Host/Composition.lean:241`; axiom print entry `Test/AxiomCheckComposition.lean:23` | Checked by axiom gate; subset of `{propext, Classical.choice, Quot.sound}` |
| Append-only record head changes on append | `Host.Record.head_after_append` | `Host/Record.lean:56`; pinned at `Test/Axioms.lean:370` | No axioms |
| Tamper-evident record chain under injective hash step | `Host.Record.tamper_evident` | `Host/Record.lean:66`; pinned at `Test/Axioms.lean:373` | No axioms |
| Netstring target encoding is injective | `Host.Encoding.encodeParts_injective` | `Host/Encoding.lean:217`; pinned at `Test/Axioms.lean:497` | `{propext, Classical.choice, Quot.sound}` |
| Authorization implies exact target or a commitment clash | `Host.CapabilityAdequacy.capability_sound_or_commitment_clash` | `Host/CapabilityAdequacy.lean:123`; pinned at `Test/Axioms.lean:502` | `{propext, Classical.choice, Quot.sound}` |
| A live approval authorizes only its minted target under A-CR | `Host.CapabilityAdequacy.approval_authorizes_only_its_target'` | `Host/CapabilityAdequacy.lean:148`; pinned at `Test/Axioms.lean:509` | `{propext, Classical.choice, Quot.sound}` |
| Minted approvals preserve that target-binding result | `Host.CapabilityAdequacy.minted_approval_authorizes_only_its_target'` | `Host/CapabilityAdequacy.lean:166`; pinned at `Test/Axioms.lean:516` | `{propext, Classical.choice, Quot.sound}` |
| Single-request non-interference for the observable decision plus record | `Host.NonInterference.observe_noninterference` | `Host/NonInterference.lean:164`; pinned at `Test/Axioms.lean:433` | `{propext, Classical.choice, Quot.sound}` |
| Replay isolation across session namespace | `Host.ReplayIsolation.replay_isolation_trace` | `Host/ReplayIsolation.lean:210`; pinned at `Test/Axioms.lean:451` | `{propext, Classical.choice, Quot.sound}` |
| Cross-session (stateful) non-interference over the composed replay seam | `Host.StatefulNI.stateful_noninterference_trace` | `Host/StatefulNI.lean:354`; pinned at `Test/Axioms.lean:488` | `{propext, Classical.choice, Quot.sound}` |
| No coordination-free double-spend of an approval, transferred to the SealV2 gate model (within TTL, per concurrent replica) | `Host.AuthorityFrontierBridge.sealv2_frontier_card_le_one` | `Host/AuthorityFrontierBridge.lean:203`; pinned at `Test/Axioms.lean:518` | `{propext, Classical.choice, Quot.sound}` |
| Two disconnected replicas never both consume the same approval (bridge corollary) | `Host.AuthorityFrontierBridge.sealv2_no_disconnected_double_availability` | `Host/AuthorityFrontierBridge.lean:190`; pinned at `Test/Axioms.lean:513` | `{propext, Classical.choice, Quot.sound}` |
| Composed allow ⇒ the calibration kernel's executable check passed (trusted Float mirror) | `Host.composed_calibration_bound` | `Host/Composition.lean:202`; pinned inline `Host/Composition.lean:606` | `{propext, Classical.choice, Quot.sound}` |
| Composed allow ⇒ the linear spend was backed and consumed exactly one use | `Host.composed_linear_conservation` | `Host/Composition.lean:282`; pinned inline `Host/Composition.lean:606` | `{propext, Classical.choice, Quot.sound}` |
| Composed allow ⇒ every covering budget resolved the cost and admitted it within its cap | `Host.composed_budget_cap` | `Host/Composition.lean:410`; pinned inline `Host/Composition.lean:606` | `{propext, Classical.choice, Quot.sound}` |
| **Closed algebra: one composed allow carries all seven kernels' invariants, membership-guarded, for any subset** | `Host.registry_closed_algebra` | `Host/Composition.lean:527`; pinned inline `Host/Composition.lean:606` | `{propext, Classical.choice, Quot.sound}` |
| Pure registry model: any gating registered instance's verdict rides the composed allow | `Host.pureVerdicts_mem` + `Host.pure_dispatch_allow_member` | `Host/Registry.lean:86` + `Host/Composition.lean:597`; pinned inline `Host/Composition.lean:606` | `{propext, Classical.choice, Quot.sound}` |

The axiom gate is `lake exe axiom_check`; it is pinned with `#guard_msgs`, so drift in these footprints breaks the build. The composition-algebra rows are pinned **inline** at the bottom of `Host/Composition.lean` (same `#guard_msgs` mechanism), so their footprints are enforced whenever the module itself builds.

Two rows deserve a closer look. The record-chain rows (`head_after_append`, `tamper_evident`) carry an **empty** axiom footprint — stronger than the family's usual minimal classical fragment: collision resistance (A-CR) and genesis freshness (A-GEN) enter `tamper_evident` as explicit hypotheses in the statement, not as axioms, so the theorem itself is axiom-free. The two bridge rows are instances of the abstract coordination-free impossibility proven in [crdt-lean](https://github.com/velvetmonkey/crdt-lean) (`Crdt/AuthorityFrontier.lean`), applied to this repo's real consume seam (`validateAndConsumeWithStore`) as a TTL-scoped instance mapping.

## The composition closed algebra

**The guarantee.** Compose ANY subset of the seven verified kernels — Safety (S), Consensus (C), Convergence (V), Temporal (T), Linear (L), Budget (B), Calibration (K) — under the host's fail-closed AND-gate, in any order. `Host.registry_closed_algebra` is ONE theorem stating that a single composed allow simultaneously carries every present kernel's proven safety invariant: a guarded call had a live matching approval (S); two composed allows against the same votes ratify the same value (C); the admitted op is in the proven-convergent set (V); no configured LTL safety policy forbids the call (T); the spend was capability-backed and consumed exactly one use (L); every covering budget admitted the cost within its cap (B); the executable calibration check passed (K). Each conjunct is guarded by that kernel's verdict membership, so absent kernels drop out vacuously — that is what makes the algebra closed over subsets. The pure registry model (`Host.PureInst` / `Host.pureVerdicts` in `Host/Registry.lean`, with `pure_dispatch_allow_member`) instantiates the membership guards at the registry fold, making "any registered subset" literal.

**Non-claims — read these before quoting the guarantee:**

- **SAFETY fragment only.** Nothing here is liveness or progress: a kernel may deny every call forever and every theorem above stays true. "Composed allow implies invariant" says nothing about allows ever happening.
- **A3 crypto is trusted, not proven.** Ed25519 signature verification and approval-channel freshness are assumptions of the deployment, outside these theorems (no opaque crypto symbol appears in any composition proof's axiom footprint — the pins enforce that).
- **Config is trusted operator input.** Rosters, caps, gated-tool lists, grant files, calibration windows: the theorems hold relative to whatever config was loaded; they do not validate it.
- **The calibration conjunct is the executable check only.** `calibratedB = true` is Float arithmetic — a documented trusted mirror of calibration-lean's conditional sub-Gaussian / Azuma–Hoeffding mathematics (`ProbabilityTheory.hasCondSubgaussianMGF_of_mem_Icc`), cited not extracted. The measure-theoretic δ-bound is NOT formally connected to the Float computation; kernel K stays experimental for exactly this reason.
- **The IO realization is TCB.** The theorems quantify over pure verdict lists and the pure registry model. `Host.dispatch`'s IO — evidence gathering, `IO.Ref` session state, the commit discipline — is mirrored, not verified, exactly as `step_forward_non_bypass`'s TCB note records.
