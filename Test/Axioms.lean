/- SPDX-License-Identifier: Apache-2.0 -/

-- Axiom gate for the seal-host build. Every decision-bearing definition and
-- every imported theorem must sit on {propext, Classical.choice, Quot.sound}
-- only — no sorryAx, no Lean.ofReduceBool. The expected output is pinned with
-- #guard_msgs, so any axiom drift fails the build itself.

import SealCore.Safety
import SealV2.DecideTheorems
import Host
import Host.CommitRegistry
import Host.RecordTemporal
import Host.RecordTemporalCanonical
import Host.CompositionBytes
import Host.ChannelModel
import Host.SealAdapter
import Host.NonInterference
import Host.RecordReflection
import Host.ReplayIsolation
import Host.StatefulNI
import Host.AuthorityFrontierBridge
import Host.GatedSinkAdapter
import Host.PassthroughPerimeter
import Host.AuditSeam
import Host.SpawnSeam
import Host.CapabilityAdequacy
import Host.DispatchSpelled
import Host.Principal
import Host.PrincipalCommit
import Host.ObjectB
import Host.ObjectA
import Host.DurabilityA6
import Host.EgressPerimeter
import Host.EgressStrength
import Host.PolicyOverlap
import Host.StrictPerimeter
import Kernels.PrincipalBudget
import FfiSpec
import Kernels
import Kernels.ConsensusBytes
import Kernels.ConvergencePotential
import Crdt.Convergence
import Crdt.ORSet
import Temporal.Monitor
import Consensus.Checker
import Calibration.CondHoeffding

-- The three-artifact byte lock is imported by `Host`; keep its two public
-- byte-identity theorems visible to the maintained axiom census.
#print axioms Host.ThreeArtifactByteLock.decode_encode_exact_content
#print axioms Host.ThreeArtifactByteLock.one_logical_content_one_encoding

-- SealCore safety theorems (kernel S's math brick)

/-- info: 'SealCore.default_deny_never_allowed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms SealCore.default_deny_never_allowed

/--
info: 'SealCore.no_allow_guarded_without_matching_approval_in_state' depends on axioms: [propext, Quot.sound]
-/
#guard_msgs in #print axioms SealCore.no_allow_guarded_without_matching_approval_in_state

/--
info: 'SealCore.approval_binds_to_target' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms SealCore.approval_binds_to_target

/--
info: 'SealCore.consumed_approval_not_live' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms SealCore.consumed_approval_not_live

/-- info: 'SealCore.expired_not_live' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms SealCore.expired_not_live

/-- info: 'SealCore.fresh_approval_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms SealCore.fresh_approval_live

-- SealV2 canonical parser / decide theorems (the host's parser service)

/-- info: 'SealV2.non_bypass' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms SealV2.non_bypass

/-- info: 'SealV2.default_deny' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms SealV2.default_deny

-- Host decision-bearing definitions

/-- info: 'Host.classifyLine' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.classifyLine

/--
info: 'Host.classifyLine_act_ast' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.classifyLine_act_ast

/-- info: 'Host.combineVerdicts' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.combineVerdicts

/-- info: 'Host.denyReason' does not depend on any axioms -/
#guard_msgs in #print axioms Host.denyReason

/-- info: 'Host.checkTrustedConfig' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.checkTrustedConfig

/-- info: 'Kernels.safetyKernel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.safetyKernel

/-- info: 'Kernels.temporalKernel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.temporalKernel

/-- info: 'Host.ofBundle' does not depend on any axioms -/
#guard_msgs in #print axioms Host.ofBundle

/-- info: 'Host.ofBundle_temporal' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.ofBundle_temporal

/-- info: 'Temporal.monitor_sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Temporal.monitor_sound

/-- info: 'Kernels.consensusKernel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.consensusKernel

/-- info: 'Consensus.Checker.validB' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Consensus.Checker.validB

/-- info: 'Host.ofBundle_consensus' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.ofBundle_consensus

/-- info: 'Seal.parsePolicyBundle' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Seal.parsePolicyBundle

-- G3 composition theorem — the AND-combinator preserves kernel invariants

/-- info: 'Host.combine_empty_deny' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.combine_empty_deny

/-- info: 'Host.combine_allow_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.combine_allow_iff

/-- info: 'Host.combine_deny_of_member' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.combine_deny_of_member

/-- info: 'Host.composed_non_bypass' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.composed_non_bypass

/--
info: 'Host.composed_no_conflicting_agreement' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.composed_no_conflicting_agreement

/--
info: 'Host.classify_act_witness' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.classify_act_witness

/--
info: 'Host.and_combinator_preserves_invariants' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.and_combinator_preserves_invariants

-- G4: Convergence (V) + Calibration (K) kernels

/-- info: 'Kernels.convergenceKernel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.convergenceKernel

/-- info: 'Kernels.provenConvergentOps' does not depend on any axioms -/
#guard_msgs in #print axioms Kernels.provenConvergentOps

/-- info: 'Kernels.calibrationKernel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.calibrationKernel

/-- info: 'Kernels.calibratedB' depends on axioms: [Classical.choice] -/
#guard_msgs in #print axioms Kernels.calibratedB

/-- info: 'Crdt.converged_states_agree' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Crdt.converged_states_agree

/-- info: 'Crdt.ORSet.add_wins' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Crdt.ORSet.add_wins

-- G5: LinearCore calculus (L) + BudgetCore gate (B) — proven in this repo

/-- info: 'LinearCore.no_double_spend' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms LinearCore.no_double_spend

/--
info: 'LinearCore.granted_plus_initial_eq_spent_plus_remaining' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms LinearCore.granted_plus_initial_eq_spent_plus_remaining

/-- info: 'LinearCore.spends_le_grants' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms LinearCore.spends_le_grants

/--
info: 'LinearCore.spend_allow_consumes' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms LinearCore.spend_allow_consumes

/-- info: 'BudgetCore.run_never_over_budget' depends on axioms: [propext] -/
#guard_msgs in #print axioms BudgetCore.run_never_over_budget

/-- info: 'BudgetCore.over_budget_denied' depends on axioms: [propext] -/
#guard_msgs in #print axioms BudgetCore.over_budget_denied

/-- info: 'BudgetCore.step_monotone' depends on axioms: [propext] -/
#guard_msgs in #print axioms BudgetCore.step_monotone

/-- info: 'Kernels.linearKernel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.linearKernel

/-- info: 'Kernels.budgetKernel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.budgetKernel

-- Lake-dep math bricks for kernels T, C, V, K (G2+): imported and axiom-clean

/-- info: 'Temporal.gateTrace_sealSafe' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Temporal.gateTrace_sealSafe

/-- info: 'Consensus.Checker.agreement' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Consensus.Checker.agreement

/--
info: 'Crdt.strong_eventual_consistency' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Crdt.strong_eventual_consistency

/--
info: 'ProbabilityTheory.hasCondSubgaussianMGF_of_mem_Icc' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms ProbabilityTheory.hasCondSubgaussianMGF_of_mem_Icc

-- W2-T3: composition residual — gate-extension corollaries (Host/Composition.lean)

/-- info: 'Host.combine_allow_restrict' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.combine_allow_restrict

/-- info: 'Host.combine_deny_append' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.combine_deny_append

/-- info: 'Host.combine_deny_append_live' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.combine_deny_append_live

/-- info: 'Host.combine_extension_from_empty' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.combine_extension_from_empty

-- W2-T4: convergence potential (Kernels/ConvergencePotential.lean)

/-- info: 'Kernels.deficit' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.deficit

/-- info: 'Kernels.deficit_antitone' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.deficit_antitone

/--
info: 'Kernels.deficit_strict_decrease' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Kernels.deficit_strict_decrease

/-- info: 'Kernels.deficit_eq_zero_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.deficit_eq_zero_iff

/--
info: 'Kernels.deficit_zero_converged' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Kernels.deficit_zero_converged

/--
info: 'Kernels.deficit_eventually_zero' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Kernels.deficit_eventually_zero

/-- info: 'Kernels.sysEx_deficit_before' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.sysEx_deficit_before

/-- info: 'Kernels.sysEx_deficit_after' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.sysEx_deficit_after

/-- info: 'Kernels.sysEx_strict_decrease' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.sysEx_strict_decrease

-- W2-T6: channel non-bypass capstone (Host/ChannelModel.lean)

/-- info: 'Host.Channel.obligation_O3' does not depend on any axioms -/
#guard_msgs in #print axioms Host.Channel.obligation_O3

/-- info: 'Host.Channel.run' does not depend on any axioms -/
#guard_msgs in #print axioms Host.Channel.run

/-- info: 'Host.Channel.run_invariant' does not depend on any axioms -/
#guard_msgs in #print axioms Host.Channel.run_invariant

/-- info: 'Host.Channel.run_decide_genuine' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Channel.run_decide_genuine

/-- info: 'Host.Channel.channel_preserves_non_bypass_gen' does not depend on any axioms -/
#guard_msgs in #print axioms Host.Channel.channel_preserves_non_bypass_gen

/--
info: 'Host.Channel.channel_preserves_non_bypass' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Channel.channel_preserves_non_bypass

/--
info: 'Host.Channel.channel_emits_only_validated' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Channel.channel_emits_only_validated

/-- info: 'Host.Channel.compliantAdapter_O1' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Channel.compliantAdapter_O1

/-- info: 'Host.Channel.compliantAdapter_O2' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.Channel.compliantAdapter_O2

/-- info: 'Host.Channel.compliant_run_mediated' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Channel.compliant_run_mediated

/-- info: 'Host.Channel.rogueAdapter_not_O1' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.Channel.rogueAdapter_not_O1

/-- info: 'Host.Channel.rogueAdapter_O2' does not depend on any axioms -/
#guard_msgs in #print axioms Host.Channel.rogueAdapter_O2

/-- info: 'Host.Channel.rogue_mediation_fails' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.Channel.rogue_mediation_fails

/-- info: 'Host.Channel.forgerAdapter_O1' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.Channel.forgerAdapter_O1

/-- info: 'Host.Channel.forgerAdapter_not_O2' does not depend on any axioms -/
#guard_msgs in #print axioms Host.Channel.forgerAdapter_not_O2

/-- info: 'Host.Channel.forger_mediation_fails' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.Channel.forger_mediation_fails

-- W2-T2: byte-quorum consensus, model-level
-- (Kernels/ConsensusBytes.lean, Host/CompositionBytes.lean)

/-- info: 'Kernels.canonicalBytesOf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.canonicalBytesOf

/-- info: 'Kernels.byteQuorumAccepts' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Kernels.byteQuorumAccepts

/-- info: 'Kernels.byteConsensusKernel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.byteConsensusKernel

/--
info: 'Kernels.byteConsensus_verdict_allow_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Kernels.byteConsensus_verdict_allow_iff

/--
info: 'Kernels.byteConsensus_denies_without_witness' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Kernels.byteConsensus_denies_without_witness

/-- info: 'Kernels.byte_quorum_agreement' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Kernels.byte_quorum_agreement

/-- info: 'Kernels.byteQuorum_accepts_majority' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Kernels.byteQuorum_accepts_majority

/-- info: 'Kernels.byteQuorum_rejects_minority' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Kernels.byteQuorum_rejects_minority

/--
info: 'Host.forward_high_stakes_byte_quorum' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.forward_high_stakes_byte_quorum

/-- info: 'Host.composed_byte_agreement' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.composed_byte_agreement

/--
info: 'Host.forward_byte_quorum_route_live' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.forward_byte_quorum_route_live

-- W2-T1: timed record admissibility (Host/RecordTemporal.lean)

/-- info: 'Host.Record.admissible' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Record.admissible

/-- info: 'Host.Record.admit' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Record.admit

/-- info: 'Host.Record.admitted_within_bound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Record.admitted_within_bound

/-- info: 'Host.Record.stale_clock_inadmissible' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Record.stale_clock_inadmissible

/-- info: 'Host.Record.regressed_clock_inadmissible' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Record.regressed_clock_inadmissible

/-- info: 'Host.Record.replayed_nonce_inadmissible' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Record.replayed_nonce_inadmissible

/-- info: 'Host.Record.admit_preserves_clock_mono' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Record.admit_preserves_clock_mono

/-- info: 'Host.Record.admit_preserves_nonce_nodup' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Record.admit_preserves_nonce_nodup

-- L1 CORE record theorems, generalized over the commitment type and
-- instantiated at the production SHA-256 commitment (Host/Record.lean).
-- Observed footprints (both axiom-free) — strictly inside the L0 baseline.

/-- info: 'Host.Record.head_after_append' does not depend on any axioms -/
#guard_msgs in #print axioms Host.Record.head_after_append

/-- info: 'Host.Record.tamper_evident' does not depend on any axioms -/
#guard_msgs in #print axioms Host.Record.tamper_evident

/-- info: 'Host.Record.timed_head_after_append' does not depend on any axioms -/
#guard_msgs in #print axioms Host.Record.timed_head_after_append

/-- info: 'Host.Record.timed_tamper_evident' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.Record.timed_tamper_evident

/-- info: 'Host.Record.wLog_clock_mono' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.Record.wLog_clock_mono

/-- info: 'Host.Record.wLog_nonce_nodup' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.Record.wLog_nonce_nodup

-- W2-T1 hardening: A-ENC discharged (Host/RecordTemporalCanonical.lean)

/--
info: 'Host.Record.TimedEntry.encCanonical_injective' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Record.TimedEntry.encCanonical_injective

/--
info: 'Host.Record.timed_tamper_evident_canonical' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Record.timed_tamper_evident_canonical

-- W2-T6.1: the seal adapter model discharges the capstone's hypotheses
-- (Host/SealAdapter.lean)

/-- info: 'Host.Channel.sealAdapter_O1' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.Channel.sealAdapter_O1

/-- info: 'Host.Channel.sealAdapter_O2' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.Channel.sealAdapter_O2

/--
info: 'Host.Channel.sealAdapter_trace' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Channel.sealAdapter_trace

-- Non-interference: the gate reveals nothing about ApprovalState beyond the
-- one declassified authorization bit (Host/NonInterference.lean)

/--
info: 'Host.NonInterference.decide_authView_noninterference' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.NonInterference.decide_authView_noninterference

/--
info: 'Host.NonInterference.authView_noninterference_nonvacuous' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.NonInterference.authView_noninterference_nonvacuous

/--
info: 'Host.NonInterference.record_authView_noninterference' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.NonInterference.record_authView_noninterference

/--
info: 'Host.NonInterference.observe_noninterference' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.NonInterference.observe_noninterference

-- Cross-session replay isolation over the durable store seam
-- (Host/ReplayIsolation.lean)

/--
info: 'Host.ReplayIsolation.ns_eq_implies_session_eq' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReplayIsolation.ns_eq_implies_session_eq

/--
info: 'Host.ReplayIsolation.store_lowEq_step' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReplayIsolation.store_lowEq_step

/--
info: 'Host.ReplayIsolation.replay_isolation_trace' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReplayIsolation.replay_isolation_trace

/--
info: 'Host.ReplayIsolation.replay_isolation_nonvacuous' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReplayIsolation.replay_isolation_nonvacuous

/--
info: 'Host.ReplayIsolation.listReplayStore_namespaceLocal' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReplayIsolation.listReplayStore_namespaceLocal

-- Two-state stateful non-interference over the composed replay seam
-- (Host/StatefulNI.lean)

/--
info: 'Host.StatefulNI.authView_eq_consumeView_isSome' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.StatefulNI.authView_eq_consumeView_isSome

/--
info: 'Host.StatefulNI.leaky_probe_fails' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.StatefulNI.leaky_probe_fails

/--
info: 'Host.StatefulNI.stateful_step' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.StatefulNI.stateful_step

/--
info: 'Host.StatefulNI.stateful_noninterference_trace' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.StatefulNI.stateful_noninterference_trace

/--
info: 'Host.StatefulNI.stateful_ni_nonvacuous' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.StatefulNI.stateful_ni_nonvacuous

/--
info: 'Host.StatefulNI.policyVersion_declassification_necessary' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.StatefulNI.policyVersion_declassification_necessary

-- The lower bound completed: every replayView field is necessary
-- (Host/StatefulNI.lean §exact minimality — replayView is the exact
-- minimal declassification interface)

/--
info: 'Host.StatefulNI.publicKey_declassification_necessary' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.StatefulNI.publicKey_declassification_necessary

/--
info: 'Host.StatefulNI.session_declassification_necessary' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.StatefulNI.session_declassification_necessary

/--
info: 'Host.StatefulNI.now_declassification_necessary' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.StatefulNI.now_declassification_necessary

-- SealV2 ↔ AuthoritySystem applicability bridge (Host/AuthorityFrontierBridge.lean):
-- the abstract no-double-spend theorem applied to the gate's real nonce seam.

/--
info: 'Host.AuthorityFrontierBridge.bridgeConsume_eq' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.bridgeConsume_eq

/--
info: 'Host.AuthorityFrontierBridge.sealv2_no_disconnected_double_availability' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
-/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.sealv2_no_disconnected_double_availability

/--
info: 'Host.AuthorityFrontierBridge.sealv2_frontier_card_le_one' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.sealv2_frontier_card_le_one

-- Sufficiency on the seam: the shared-store no-go + the single-delivery
-- deployment with Safe PROVEN (Host/AuthorityFrontierBridge.lean §Sufficiency)

/--
info: 'Host.AuthorityFrontierBridge.sealv2_shared_not_sealed_senders' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
-/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.sealv2_shared_not_sealed_senders

/-- info: 'Host.AuthorityFrontierBridge.bridgeConsume_sealed_none' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.bridgeConsume_sealed_none

/--
info: 'Host.AuthorityFrontierBridge.sealed_delivery_sealed_senders' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.sealed_delivery_sealed_senders

/-- info: 'Host.AuthorityFrontierBridge.sealv2_partitioned_safe' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.sealv2_partitioned_safe

/--
info: 'Host.AuthorityFrontierBridge.sealv2_no_disconnected_double_availability'' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
-/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.sealv2_no_disconnected_double_availability'

/--
info: 'Host.AuthorityFrontierBridge.sealv2_frontier_card_le_one'' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.sealv2_frontier_card_le_one'

-- The third shape: mesh-coordinated replicas over the SHARED store
-- (Host/AuthorityFrontierBridge.lean §Composition — seal × crdt-lean)

/-- info: 'Host.AuthorityFrontierBridge.meshReach_snd' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.meshReach_snd

/-- info: 'Host.AuthorityFrontierBridge.mesh_sealed_senders' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.mesh_sealed_senders

/-- info: 'Host.AuthorityFrontierBridge.sealv2_mesh_safe' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.sealv2_mesh_safe

/-- info: 'Host.AuthorityFrontierBridge.tokenMesh_sealed_senders' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.tokenMesh_sealed_senders

/-- info: 'Host.AuthorityFrontierBridge.mesh_holder_live_at_init' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.mesh_holder_live_at_init

/-- info: 'Host.AuthorityFrontierBridge.sealv2_token_mesh_safe' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.AuthorityFrontierBridge.sealv2_token_mesh_safe

-- Gated-sink adapter conformance by name: O1∧O2 + non-vacuity at the alias
-- (Host/GatedSinkAdapter.lean; model = W2-T6.1 sealAdapter, no duplication).
-- Renamed from `deployed_*` (K3): the alias covers the gated child-input
-- sink (P2/P3) only, not P1 passthrough (see Host/PassthroughPerimeter.lean).

/-- info: 'Host.Channel.gatedSink_O1' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.Channel.gatedSink_O1

/-- info: 'Host.Channel.gatedSink_O2' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.Channel.gatedSink_O2

/--
info: 'Host.Channel.gatedSink_preserves_non_bypass' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Channel.gatedSink_preserves_non_bypass

/-- info: 'Host.Channel.gatedSink_nonvacuous' does not depend on any axioms -/
#guard_msgs in #print axioms Host.Channel.gatedSink_nonvacuous

/--
info: 'Host.Channel.gatedSink_live_emit_of_allow' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Channel.gatedSink_live_emit_of_allow

/--
info: 'Host.Channel.gatedSink_live_license_of_allow' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Channel.gatedSink_live_license_of_allow

-- Passthrough perimeter (K4): the widened alphabet includes P1, the byte
-- classes characterise the router, and non-bypass FAILS over the widening
-- while the gated sink survives (Host/PassthroughPerimeter.lean; every
-- theorem there is also pinned inline). Central-audit copies of the
-- capstones:

/--
info: 'Host.Perimeter.mediation_perimeter' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Perimeter.mediation_perimeter

/--
info: 'Host.Perimeter.widened_non_bypass_fails' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Perimeter.widened_non_bypass_fails

/--
info: 'Host.Perimeter.widened_non_bypass_fails_live' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Perimeter.widened_non_bypass_fails_live

/--
info: 'Host.Perimeter.wchannel_gated_sink_non_bypass' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Perimeter.wchannel_gated_sink_non_bypass

/--
info: 'Host.Perimeter.toolsCallShape_eq_toolsCall?' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Perimeter.toolsCallShape_eq_toolsCall?

/-- info: 'Host.Perimeter.wireSafe' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.Perimeter.wireSafe

/-- info: 'Host.Perimeter.refusedClass' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.Perimeter.refusedClass

/-- info: 'Host.Perimeter.inPerimeter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.Perimeter.inPerimeter

-- Capability adequacy, UNCONDITIONAL (Host/Encoding.lean +
-- Host/CapabilityAdequacy.lean, ARIA S6): injective netstring encoding +
-- the no-universe reduction to A-CR on the commitment.

/--
info: 'Host.Encoding.encodeParts_injective' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Encoding.encodeParts_injective

/--
info: 'Host.CapabilityAdequacy.capability_sound_or_commitment_clash' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
-/
#guard_msgs in #print axioms Host.CapabilityAdequacy.capability_sound_or_commitment_clash

/--
info: 'Host.CapabilityAdequacy.approval_authorizes_only_its_target'' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
-/
#guard_msgs in #print axioms Host.CapabilityAdequacy.approval_authorizes_only_its_target'

/--
info: 'Host.CapabilityAdequacy.minted_approval_authorizes_only_its_target'' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
-/
#guard_msgs in #print axioms Host.CapabilityAdequacy.minted_approval_authorizes_only_its_target'

-- The commit discipline: deny-side and allow-side state commits over the pure
-- two-phase model, and the product corollaries at the committed trace
-- (Host/Commit.lean)

/-- info: 'Host.pureCommit' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit

/--
info: 'Host.pureCommit_deny_no_decide_commit' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.pureCommit_deny_no_decide_commit

/--
info: 'Host.pureCommit_allow_commits_decide' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.pureCommit_allow_commits_decide

/--
info: 'Host.pureCommit_allow_closed_algebra' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.pureCommit_allow_closed_algebra

/--
info: 'Host.pureCommit_head_commitStep' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.pureCommit_head_commitStep

/-- info: 'Host.budget_commitStep_deny' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.budget_commitStep_deny

/--
info: 'Host.budget_committed_trace_within_cap' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.budget_committed_trace_within_cap

/-- info: 'Host.budgetCapsConsistent_caps_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.budgetCapsConsistent_caps_eq

/--
info: 'Host.budget_committed_trace_within_cap_of_consistent' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.budget_committed_trace_within_cap_of_consistent

/-- info: 'Host.linear_commitStep_deny' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.linear_commitStep_deny

/--
info: 'Host.linear_committed_trace_conservation' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.linear_committed_trace_conservation

/--
info: 'Host.linear_committed_trace_no_double_spend' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.linear_committed_trace_no_double_spend

-- The budget × linear × safety composition: deny-side per-kernel corollaries,
-- the dispatch loop's plan bound to the pure model (Host/Commit.lean), and
-- the 8-kernel registry-level deny composition (Host/CommitRegistry.lean)

/-- info: 'Host.pureCommit_deny_of_member' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_deny_of_member

/--
info: 'Host.pureCommit_deny_budget_frozen' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.pureCommit_deny_budget_frozen

/--
info: 'Host.pureCommit_deny_temporal_frozen' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.pureCommit_deny_temporal_frozen

/--
info: 'Host.pureCommit_deny_safety_ingest_only' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.pureCommit_deny_safety_ingest_only

/--
info: 'Host.pureCommit_deny_linear_ingest_only' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.pureCommit_deny_linear_ingest_only

/-- info: 'Host.dispatch_verdicts_plan' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatch_verdicts_plan

/-- info: 'Host.dispatch_ingest_plan' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatch_ingest_plan

/-- info: 'Host.dispatch_held_plan' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatch_held_plan

/-- info: 'Host.dispatch_plan' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatch_plan

/-- info: 'Host.commitInstsFor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitInstsFor

/-- info: 'Host.commitInstsFor_kernels' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitInstsFor_kernels

/-- info: 'Host.Registered.wiredAt' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.Registered.wiredAt

/-- info: 'Host.CommitInst.wired' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.CommitInst.wired

/-- info: 'Host.commitInstsFor_wiring' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitInstsFor_wiring

/-- info: 'Host.commitInstsFor_gates' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitInstsFor_gates

/-- info: 'Host.linearIngested' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.linearIngested

/--
info: 'Host.registry_deny_ingest_only' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.registry_deny_ingest_only

/--
info: 'Host.registry_deny_no_budget_spend' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.registry_deny_no_budget_spend

/--
info: 'Host.registry_deny_temporal_frozen' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.registry_deny_temporal_frozen

/--
info: 'Host.parseGrantsText_grant_only' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.parseGrantsText_grant_only

/--
info: 'Host.linear_ingest_grant_only_holds' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.linear_ingest_grant_only_holds

/--
info: 'Host.registry_deny_no_capability_consumed' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.registry_deny_no_capability_consumed

-- Provenance separation: the principal is never populated from the request
-- (Host/Provenance.lean)

/--
info: 'Host.Provenance.factored_separated' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Provenance.factored_separated

/--
info: 'Host.Provenance.spoofingAssigner_not_separated' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Provenance.spoofingAssigner_not_separated

/--
info: 'Host.Provenance.boot_principal_constant' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Provenance.boot_principal_constant

/--
info: 'Host.Provenance.replayNamespace_trusted_plane' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Provenance.replayNamespace_trusted_plane

-- The kernel request commitment (Host/Audit.lean) and the modules stated
-- over auditLine. `Host.auditLine` itself is gated: the emitting definition
-- must carry no reduceBool/native evaluation axioms. RecordReflection is
-- imported HERE because nothing else in any default target builds it —
-- before this import, `log_reflects_l0_decisions` was a theorem no build
-- elaborated (found 2026-07-15; the orphan Test/AxiomCheckRecord.lean and
-- Test/AxiomCheckComposition.lean are dead build-wise, the `Test` lib glob
-- is not a default target).

/-- info: 'Host.auditLine' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.auditLine

/--
info: 'Host.Record.log_reflects_l0_decisions' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.Record.log_reflects_l0_decisions

-- Routing-untouched evidence for the request-commitment change: the deployed
-- routing core and the non-bypass theorem re-elaborate and stay on the
-- baseline-3 footprint. (Previously gated only in the never-built
-- Test/AxiomCheckComposition.lean.)

/-- info: 'Host.stepRoute' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.stepRoute

/--
info: 'Host.step_forward_non_bypass' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.step_forward_non_bypass

-- The deployed registry's specification (FfiSpec.lean): `Ffi.registryFor` —
-- the ONE function that selects which proven kernels run — registers exactly
-- `activeKernels s.config`, Safety and Temporal unconditionally. Closes the
-- selection gap between `registry_closed_algebra` (composition over any
-- subset) and `step_forward_non_bypass` (enactment). FfiSpec is imported
-- HERE so the gate builds it: the `Ffi` lib glob alone is not a proof gate.

/-- info: 'Ffi.registryFor_kernels' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.registryFor_kernels

/-- info: 'Ffi.safety_always_registered' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.safety_always_registered

/--
info: 'Ffi.temporal_always_registered' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Ffi.temporal_always_registered

/-- info: 'Ffi.consensus_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.consensus_registered_iff

/--
info: 'Ffi.convergence_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Ffi.convergence_registered_iff

/--
info: 'Ffi.calibration_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Ffi.calibration_registered_iff

/-- info: 'Ffi.linear_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.linear_registered_iff

/-- info: 'Ffi.budget_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.budget_registered_iff

/--
info: 'Ffi.byteConsensus_never_registered' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Ffi.byteConsensus_never_registered

-- D3 authority frontier: the receipt binds the approval trust root and is
-- request-independent; NO function of the mediated bytes can authenticate
-- the caller at the stdio topology (Host/ReceiptIdentity.lean)

/--
info: 'Host.ReceiptIdentity.receipt_identity_separated' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReceiptIdentity.receipt_identity_separated

/--
info: 'Host.ReceiptIdentity.receipt_identity_boot_constant' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReceiptIdentity.receipt_identity_boot_constant

/--
info: 'Host.ReceiptIdentity.token_gates_presence_not_value' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReceiptIdentity.token_gates_presence_not_value

/--
info: 'Host.ReceiptIdentity.receipt_identity_names_trust_root' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReceiptIdentity.receipt_identity_names_trust_root

/--
info: 'Host.ReceiptIdentity.keyId_only_on_signed_channel' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReceiptIdentity.keyId_only_on_signed_channel

/--
info: 'Host.ReceiptIdentity.stdio_no_caller_authentication' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReceiptIdentity.stdio_no_caller_authentication

/--
info: 'Host.ReceiptIdentity.forgeable_echo' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReceiptIdentity.forgeable_echo

/--
info: 'Host.ReceiptIdentity.credential_excludes_totality' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReceiptIdentity.credential_excludes_totality

/--
info: 'Host.ReceiptIdentity.credentialed_topology_authenticates' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReceiptIdentity.credentialed_topology_authenticates

/--
info: 'Host.ReceiptIdentity.caller_authenticator_satisfiable' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.ReceiptIdentity.caller_authenticator_satisfiable

/-- The axiom gate's runtime entry point is a no-op banner: every check in
    this module is a compile-time `#guard_msgs` pin, so building the exe IS
    the gate. -/
def main : IO Unit :=
  IO.println "axiom gate passed: all checks pinned by #guard_msgs at compile time"

-- Pathological-number fail-closed guard (Lane C number-abort fix): a wire line
-- carrying a monster-exponent number classifies as .refuse (never passthrough,
-- never act) and routes to .block (never forward) — both failure directions
-- (native/interpreter abort, wasm passthrough) closed, identically every lane.
/--
info: 'Host.classifyLine_refuse_of_unsafe' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.classifyLine_refuse_of_unsafe

/--
info: 'Host.classifyLine_refuse_of_unsafe_agreement' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.classifyLine_refuse_of_unsafe_agreement

/--
info: 'Host.classifyLine_refuse_of_unsafe_surrogates' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.classifyLine_refuse_of_unsafe_surrogates

/--
info: 'Host.classifyLine_refuse_of_unsafe_depth' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.classifyLine_refuse_of_unsafe_depth

/--
info: 'Host.SurrogateEscapes.unsafe_implies_surrogateEscape' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.SurrogateEscapes.unsafe_implies_surrogateEscape

/--
info: 'Host.SurrogateEscapes.safe_of_no_surrogateEscape' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.SurrogateEscapes.safe_of_no_surrogateEscape

/-- info: 'Host.NestingDepth.wireDepthSafe_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.NestingDepth.wireDepthSafe_iff

/--
info: 'Host.stepRoute_refuse_ne_forward' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.stepRoute_refuse_ne_forward

/--
info: 'Host.pathological_never_forwards' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.pathological_never_forwards

-- Dispatch IO shell, spelled (wrap-up): the do-desugaring, the queued
-- held-write replay structure, the no-duplicate-kernel selection and the
-- stepImpl marshalling are theorems — program equality in IO with the opaque
-- IO.Ref get/set as abstract leaves, NO new axioms (that is the point: the
-- residual TCB is exactly the opaque primitives' value semantics, named in
-- docs/POLICY-ASSURANCE-BOUNDARY.md).

/-- info: 'Host.replay' does not depend on any axioms -/
#guard_msgs in #print axioms Host.replay

/-- info: 'Host.dispatchGo' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatchGo

/-- info: 'Host.dispatch_spelled' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatch_spelled

/--
info: 'Host.dispatchGo_cons_pure_gather' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.dispatchGo_cons_pure_gather

/-- info: 'Host.registryFor_gather_pure' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.registryFor_gather_pure

/--
info: 'Host.registryFor_reader_invariance' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.registryFor_reader_invariance

/-- info: 'Ffi.activeKernels_names_nodup' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.activeKernels_names_nodup

/-- info: 'Ffi.activeKernels_nodup' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.activeKernels_nodup

/-- info: 'Ffi.registryFor_kernels_nodup' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.registryFor_kernels_nodup

/-- info: 'Ffi.stepInputsOf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepInputsOf

/-- info: 'Ffi.stepPlanFor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepPlanFor

/-- info: 'Ffi.stepRender' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepRender

/-- info: 'Ffi.stepImpl_spelled' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepImpl_spelled

-- V2.2 authority-bound signed-envelope principal (Route 2): the opaque
-- credential, the per-principal Budget kernel, the commit-discipline twins
-- and the receipt model half. Same axiom baseline as everything above; the
-- Ed25519 extern is `opaque`, never an axiom, so no crypto assumption can
-- appear here.

/-- info: 'Host.verifyEnvelope' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.verifyEnvelope

-- V2.2 bind + domain separation (council C1): the message encoding commits
-- to the config authority and the keyId, and neither the v2.1 layout nor the
-- config plane can collide with it. No sorryAx, no Lean.ofReduceBool.

/-- info: 'Host.u64be_inj' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.u64be_inj

/-- info: 'Host.envelope_message_binds_authority_and_keyId' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.envelope_message_binds_authority_and_keyId

/-- info: 'Host.envelope_cross_version_separated' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.envelope_cross_version_separated

/-- info: 'Host.envelope_cross_plane_separated' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.envelope_cross_plane_separated

/-- info: 'Host.AuthenticatedPrincipal.ext_id' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.AuthenticatedPrincipal.ext_id

/-- info: 'Host.envelope_gates_presence_not_value' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.envelope_gates_presence_not_value

/-- info: 'Host.principal_value_key_constant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.principal_value_key_constant

/-- info: 'Host.verifyEnvelope_none_of_unregistered' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.verifyEnvelope_none_of_unregistered

/-- info: 'Host.verifyEnvelope_id_registered' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.verifyEnvelope_id_registered

/-- info: 'Host.envelope_topology_authenticates' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.envelope_topology_authenticates

/-- info: 'Host.envelope_constrained_excludes_totality' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.envelope_constrained_excludes_totality

/-- info: 'Kernels.principalBudgetKernel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.principalBudgetKernel

/-- info: 'Kernels.principal_budget_ingest_id' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.principal_budget_ingest_id

/-- info: 'Kernels.principal_budget_none_denies' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.principal_budget_none_denies

/-- info: 'Kernels.principal_budget_none_frozen' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.principal_budget_none_frozen

/-- info: 'Kernels.pbStateFor_set_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.pbStateFor_set_eq

/-- info: 'Kernels.pbStateFor_set_ne' depends on axioms: [propext] -/
#guard_msgs in #print axioms Kernels.pbStateFor_set_ne

/-- info: 'Kernels.principal_budget_isolation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.principal_budget_isolation

/-- info: 'Host.principal_budget_commitStep_deny' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.principal_budget_commitStep_deny

/--
info: 'Host.principal_budget_committed_trace_within_cap' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.principal_budget_committed_trace_within_cap

/--
info: 'Host.principal_budget_committed_trace_within_cap_of_consistent' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
-/
#guard_msgs in #print axioms Host.principal_budget_committed_trace_within_cap_of_consistent

/--
info: 'Host.principal_budget_committed_trace_from_init' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.principal_budget_committed_trace_from_init

/-- info: 'Host.principal_budget_trace_isolation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.principal_budget_trace_isolation

/-- info: 'Host.principalsConsistent' does not depend on any axioms -/
#guard_msgs in #print axioms Host.principalsConsistent

/-- info: 'Host.ofBundle_principals' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.ofBundle_principals

/-- info: 'Host.ofBundle_principals_consistent' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.ofBundle_principals_consistent

/-- info: 'Seal.effectivePrincipals_isSome_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Seal.effectivePrincipals_isSome_iff

/-- info: 'Ffi.principal_budget_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.principal_budget_registered_iff

/--
info: 'Ffi.registryFor_kernels_principal_irrelevant' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Ffi.registryFor_kernels_principal_irrelevant

/--
info: 'Ffi.bundle_principal_budget_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Ffi.bundle_principal_budget_registered_iff

/--
info: 'Ffi.bundle_disabled_principals_not_registered' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Ffi.bundle_disabled_principals_not_registered

/-- info: 'Host.registry_deny_no_principal_budget_spend' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.registry_deny_no_principal_budget_spend

/-- info: 'Ffi.principalOutField_lookup' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.principalOutField_lookup

/-- info: 'Ffi.principalOutField_authenticated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.principalOutField_authenticated

/-- info: 'Ffi.faithful_principal_authenticated' depends on axioms: [propext] -/
#guard_msgs in #print axioms Ffi.faithful_principal_authenticated

/-- info: 'Ffi.receipt_principal_authenticated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.receipt_principal_authenticated

-- Object B: DECIDED + RECORDED only.

/-- info: 'Host.ObjectB.kernel_effect_boundary_matches_payload' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectB.kernel_effect_boundary_matches_payload

/-- info: 'Host.ObjectB.verdict_decoder_matches_payload' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectB.verdict_decoder_matches_payload

/-- info: 'Host.ObjectB.check_refuses_kernel_effect_mismatch' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectB.check_refuses_kernel_effect_mismatch

/-- info: 'Host.ObjectB.check_refuses_verdict_mismatch' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectB.check_refuses_verdict_mismatch

/-- info: 'Host.ObjectB.context_delegation_predicate_accepted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectB.context_delegation_predicate_accepted

/-- info: 'Host.ObjectB.context_kernel_production_predicate_accepted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectB.context_kernel_production_predicate_accepted

/-- info: 'Host.ObjectB.context_recording_predicate_accepted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectB.context_recording_predicate_accepted

/-- info: 'Host.ObjectB.core_claim_does_not_constrain_release_or_execution' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectB.core_claim_does_not_constrain_release_or_execution

/-- info: 'Host.ObjectB.asserted_provenance_cannot_affect_verdict' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectB.asserted_provenance_cannot_affect_verdict

-- Object A and Approval Statement: guarded presented bytes, independently gated.

/-- info: 'Host.ObjectA.presented_statement_bytes_match_fields' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectA.presented_statement_bytes_match_fields

/-- info: 'Host.ObjectA.judged_request_digest_matches_bytes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectA.judged_request_digest_matches_bytes

/-- info: 'Host.ObjectA.kernel_effect_boundary_accepts_judged_request' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectA.kernel_effect_boundary_accepts_judged_request

/-- info: 'Host.ObjectA.context_time_is_inside_validity_window' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectA.context_time_is_inside_validity_window

/-- info: 'Host.ObjectA.context_request_signer_delegation_predicate_accepted' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectA.context_request_signer_delegation_predicate_accepted

/-- info: 'Host.ObjectA.context_adapter_profile_predicate_accepted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectA.context_adapter_profile_predicate_accepted

/-- info: 'Host.ObjectA.context_signature_predicate_accepted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectA.context_signature_predicate_accepted

/-- info: 'Host.ObjectA.check_refuses_statement_field_mismatch' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ObjectA.check_refuses_statement_field_mismatch

/-- info: 'Host.ApprovalStatement.presented_statement_bytes_match_fields' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms Host.ApprovalStatement.presented_statement_bytes_match_fields

/-- info: 'Host.ApprovalStatement.context_time_is_inside_validity_window' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms Host.ApprovalStatement.context_time_is_inside_validity_window

/-- info: 'Host.ApprovalStatement.context_approver_delegation_predicate_accepted' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms Host.ApprovalStatement.context_approver_delegation_predicate_accepted

/-- info: 'Host.ApprovalStatement.context_adapter_profile_predicate_accepted' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms Host.ApprovalStatement.context_adapter_profile_predicate_accepted

/-- info: 'Host.ApprovalStatement.context_signature_predicate_accepted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.ApprovalStatement.context_signature_predicate_accepted

/-- info: 'Host.ApprovalStatement.check_refuses_statement_field_mismatch' depends on axioms: [propext,
 Classical.choice,
 Quot.sound] -/
#guard_msgs in #print axioms Host.ApprovalStatement.check_refuses_statement_field_mismatch
