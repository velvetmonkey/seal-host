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

The axiom gate is `lake exe axiom_check`; it is pinned with `#guard_msgs`, so drift in these footprints breaks the build.
