/- SPDX-License-Identifier: Apache-2.0 -/

-- Axiom gate for the seal-host build. Every decision-bearing definition and
-- every imported theorem must sit on {propext, Classical.choice, Quot.sound}
-- only — no sorryAx, no Lean.ofReduceBool. The expected output is pinned with
-- #guard_msgs, so any axiom drift fails the build itself.

import SealCore.Safety
import SealV2.DecideTheorems
import Host
import Kernels
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

def main : IO Unit :=
  IO.println "axiom gate passed: all checks pinned by #guard_msgs at compile time"
