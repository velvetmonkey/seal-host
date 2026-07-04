/- SPDX-License-Identifier: Apache-2.0 -/

-- Axiom gate for the seal-host build. Every decision-bearing definition and
-- every imported theorem must sit on {propext, Classical.choice, Quot.sound}
-- only — no sorryAx, no Lean.ofReduceBool. The expected output is pinned with
-- #guard_msgs, so any axiom drift fails the build itself.

import SealCore.Safety
import SealV2.DecideTheorems
import Host
import Host.RecordTemporal
import Host.RecordTemporalCanonical
import Host.CompositionBytes
import Host.ChannelModel
import Host.SealAdapter
import Host.NonInterference
import Kernels
import Kernels.ConsensusBytes
import Kernels.ConvergencePotential
import Crdt.Convergence
import Crdt.ORSet
import Temporal.Monitor
import Consensus.Checker
import Calibration.CondHoeffding

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

/-- info: 'Host.parseTemporalSection' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.parseTemporalSection

/-- info: 'Temporal.monitor_sound' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Temporal.monitor_sound

/-- info: 'Kernels.consensusKernel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Kernels.consensusKernel

/-- info: 'Consensus.Checker.validB' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Consensus.Checker.validB

/-- info: 'Host.parseConsensusSection' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.parseConsensusSection

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

def main : IO Unit :=
  IO.println "axiom gate passed: all checks pinned by #guard_msgs at compile time"
