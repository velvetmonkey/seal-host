/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Registry
import Kernels.Safety
import Kernels.Consensus

/-!
# The composition theorem — the AND-combinator preserves kernel invariants

The host combines per-kernel verdicts with `Host.combineVerdicts`, fail-closed.
This module proves that composition is invariant-preserving: an allow from the
composed gate carries every individual kernel's allow (`combine_allow_iff`),
so each kernel's own proven invariant survives unchanged. Instantiated for the
two headline invariants:

* **non-bypass** (Safety Seal, S): a composed allow on a guarded call still
  implies a live matching approval in the automaton state
  (`composed_non_bypass`).
* **no-conflicting-agreement** (Consensus Seal, C): two composed allows
  against the same roster and votes still ratify the same value
  (`composed_no_conflicting_agreement`).

No Mathlib import — everything here is Lean core + Batteries, kernel-checked.
-/

namespace Host

/-- Fail-closed on the empty verdict set: nothing gated ⇒ deny. -/
theorem combine_empty_deny : combineVerdicts ([] : List Verdict) = .deny := rfl

theorem combine_cons (v : Verdict) (t : List Verdict) :
    combineVerdicts (v :: t) =
      if (v :: t).all (fun w => w.kind == .allow) then .allow else .deny := rfl

theorem kind_beq_allow_iff (k : VerdictKind) :
    (k == VerdictKind.allow) = true ↔ k = .allow := by
  cases k <;> simp_all <;> rfl

/-- **The AND-combinator, characterised.** The composed verdict is allow iff
    at least one kernel gated the call AND every gating kernel allowed it. -/
theorem combine_allow_iff (vs : List Verdict) :
    combineVerdicts vs = .allow ↔ vs ≠ [] ∧ ∀ v ∈ vs, v.kind = .allow := by
  cases vs with
  | nil => simp [combine_empty_deny]
  | cons v t =>
    rw [combine_cons]
    by_cases h : (v :: t).all (fun w => w.kind == .allow)
    · rw [if_pos h]
      simp only [List.all_eq_true] at h
      constructor
      · intro _
        exact ⟨List.cons_ne_nil v t, fun w hw => (kind_beq_allow_iff w.kind).mp (h w hw)⟩
      · intro _; rfl
    · rw [if_neg h]
      constructor
      · intro hcontra; cases hcontra
      · rintro ⟨-, hall⟩
        exact absurd (List.all_eq_true.mpr
          (fun w hw => (kind_beq_allow_iff w.kind).mpr (hall w hw))) h

/-- A composed allow carries every member kernel's allow: no kernel's verdict
    can be overridden by composition. -/
theorem combine_allow_implies_member (vs : List Verdict) (v : Verdict)
    (hmem : v ∈ vs) (hcomb : combineVerdicts vs = .allow) : v.kind = .allow :=
  (combine_allow_iff vs).mp hcomb |>.2 v hmem

/-- One denying kernel forces the composed deny (fail-closed veto). -/
theorem combine_deny_of_member (vs : List Verdict) (v : Verdict)
    (hmem : v ∈ vs) (hdeny : v.kind = .deny) : combineVerdicts vs = .deny := by
  cases hcomb : combineVerdicts vs with
  | deny => rfl
  | allow =>
      have := combine_allow_implies_member vs v hmem hcomb
      rw [hdeny] at this
      cases this

/-- **Non-bypass survives composition.** If the safety kernel's verdict for a
    guarded call is among the combined verdicts and the composed gate allows,
    then the automaton held a live approval bound to exactly that target —
    SealCore's `no_allow_guarded_without_matching_approval_in_state`, intact
    under the AND-combinator. -/
theorem composed_non_bypass
    (vs : List Verdict) (act : CanonicalAction) (pol : Seal.Policy)
    (ev : Kernels.SafetyEvidence) (st1 : SealCore.State) (target : SealCore.Hash)
    (hmem : (Kernels.safetyKernel.decide act pol ev st1).1 ∈ vs)
    (hcomb : combineVerdicts vs = .allow)
    (hguard : (Seal.classifyToolCall pol act.tool act.argsJson).toEvent =
      SealCore.Event.guarded target) :
    SealCore.live st1 target ev.now = true := by
  have hkind := combine_allow_implies_member vs _ hmem hcomb
  have hstep := (Kernels.safety_verdict_allow_iff act pol ev st1).mp hkind
  rw [hguard] at hstep
  exact SealCore.no_allow_guarded_without_matching_approval_in_state ev.now st1 target hstep

/-- **No-conflicting-agreement survives composition.** If two calls each pass
    the composed gate with the consensus kernel among their verdicts, against
    the same roster and votes, the two ratified certificates carry the same
    value — `Consensus.Checker.agreement`, intact under the AND-combinator. -/
theorem composed_no_conflicting_agreement
    (vs vs' : List Verdict) (act act' : CanonicalAction)
    (cfg : Kernels.ConsensusConfig) (votes : Consensus.Checker.Votes)
    (hmem : (Kernels.consensusKernel.decide act cfg votes ()).1 ∈ vs)
    (hmem' : (Kernels.consensusKernel.decide act' cfg votes ()).1 ∈ vs')
    (hcomb : combineVerdicts vs = .allow) (hcomb' : combineVerdicts vs' = .allow) :
    (Kernels.certFor votes act.tool).value = (Kernels.certFor votes act'.tool).value := by
  have h := (Kernels.consensus_verdict_allow_iff act cfg votes ()).mp
    (combine_allow_implies_member vs _ hmem hcomb)
  have h' := (Kernels.consensus_verdict_allow_iff act' cfg votes ()).mp
    (combine_allow_implies_member vs' _ hmem' hcomb')
  exact Consensus.Checker.agreement cfg.roster votes _ _ h h'

/-- **The composition theorem.** The fail-closed AND-combinator preserves both
    headline kernel invariants simultaneously: non-bypass (S) and
    no-conflicting-agreement (C) both survive composition under one host. -/
theorem and_combinator_preserves_invariants
    (vs vs' : List Verdict) (act act' : CanonicalAction)
    (pol : Seal.Policy) (ev : Kernels.SafetyEvidence) (st1 : SealCore.State)
    (target : SealCore.Hash)
    (cfg : Kernels.ConsensusConfig) (votes : Consensus.Checker.Votes)
    (hS : (Kernels.safetyKernel.decide act pol ev st1).1 ∈ vs)
    (hC : (Kernels.consensusKernel.decide act cfg votes ()).1 ∈ vs)
    (hC' : (Kernels.consensusKernel.decide act' cfg votes ()).1 ∈ vs')
    (hcomb : combineVerdicts vs = .allow) (hcomb' : combineVerdicts vs' = .allow)
    (hguard : (Seal.classifyToolCall pol act.tool act.argsJson).toEvent =
      SealCore.Event.guarded target) :
    SealCore.live st1 target ev.now = true ∧
      (Kernels.certFor votes act.tool).value = (Kernels.certFor votes act'.tool).value :=
  ⟨composed_non_bypass vs act pol ev st1 target hS hcomb hguard,
   composed_no_conflicting_agreement vs vs' act act' cfg votes hC hC' hcomb hcomb'⟩

end Host
