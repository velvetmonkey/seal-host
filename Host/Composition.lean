/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Registry
import Host.Canonical
import Host.Step
import Kernels.Safety
import Kernels.Consensus
import Kernels.Convergence
import Kernels.Temporal

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

/-- **Allow-restriction under gate extension (W2-T3).** If the extended gate
    set allows, any non-empty prefix allows on its own: no later kernel can
    have been load-bearing for an earlier kernel's allow. -/
theorem combine_allow_restrict (vs ws : List Verdict)
    (hne : vs ≠ []) (hallow : combineVerdicts (vs ++ ws) = .allow) :
    combineVerdicts vs = .allow :=
  (combine_allow_iff vs).mpr ⟨hne, fun v hv =>
    ((combine_allow_iff _).mp hallow).2 v (List.mem_append_left ws hv)⟩

/-- **Deny-monotonicity under gate extension (W2-T3).** A NON-VACUOUS deny
    survives adding kernels: composition never widens admission of an
    already-gated, already-denied call. `vs ≠ []` is load-bearing — the empty
    deny is the fail-closed DEFAULT, and a first gating kernel may
    legitimately allow (`combine_extension_from_empty` below witnesses the
    boundary). -/
theorem combine_deny_append (vs ws : List Verdict)
    (hne : vs ≠ []) (hdeny : combineVerdicts vs = .deny) :
    combineVerdicts (vs ++ ws) = .deny := by
  cases hcomb : combineVerdicts (vs ++ ws) with
  | deny => rfl
  | allow =>
      rw [combine_allow_restrict vs ws hne hcomb] at hdeny
      cases hdeny

/-- Non-vacuity: a real deny among the prefix keeps the extended composition
    denied. -/
theorem combine_deny_append_live :
    combineVerdicts
      ([{ kernel := "k", kind := .deny, reason := "r", certHash := 0 }]
        ++ [{ kernel := "k", kind := .allow, reason := "r", certHash := 0 }]) = .deny := rfl

/-- Boundary witness: why `vs ≠ []` is required in `combine_deny_append` —
    the fail-closed EMPTY deny does not survive extension; a first gating
    kernel legitimately opens admission. -/
theorem combine_extension_from_empty :
    combineVerdicts (([] : List Verdict)
      ++ [{ kernel := "k", kind := .allow, reason := "r", certHash := 0 }]) = .allow := rfl

/-- **Non-bypass survives composition.** If the safety kernel's verdict for a
    guarded call is among the combined verdicts and the composed gate allows,
    then the automaton held a live approval bound to exactly that target —
    SealCore's `no_allow_guarded_without_matching_approval_in_state`, intact
    under the AND-combinator. -/
theorem composed_non_bypass
    (vs : List Verdict) (act : CanonicalAction) (pol : Seal.Policy)
    (ev : Kernels.SafetyEvidence) (st1 : SealCore.State) (target : SealCore.TargetHash)
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

/-- **Convergence survives composition.** If the convergence kernel's verdict
    is among the combined verdicts and the composed gate allows, then the
    admitted operation is in the fixed, kernel-checked proven-convergent set —
    a divergent (split-brain) write cannot slip through the AND-combinator. -/
theorem composed_convergent
    (vs : List Verdict) (act : CanonicalAction) (cfg : Kernels.ConvergenceConfig)
    (ev st : Unit)
    (hmem : (Kernels.convergenceKernel.decide act cfg ev st).1 ∈ vs)
    (hcomb : combineVerdicts vs = .allow) :
    Kernels.convergentAccepts cfg act = true :=
  (Kernels.convergence_verdict_allow_iff act cfg ev st).mp
    (combine_allow_implies_member vs _ hmem hcomb)

/-- **Temporal safety survives composition.** If the temporal kernel's verdict
    is among the combined verdicts and the composed gate allows, then no
    configured LTL safety policy forbids the call in the current trace — a
    stale-capability replay (e.g. a call after its revoke) cannot slip through
    the AND-combinator. -/
theorem composed_temporal_safety
    (vs : List Verdict) (act : CanonicalAction) (policies : List Kernels.TemporalPolicy)
    (ev : Unit) (st : Kernels.TemporalState)
    (hmem : (Kernels.temporalKernel.decide act policies ev st).1 ∈ vs)
    (hcomb : combineVerdicts vs = .allow) :
    Kernels.temporalAccepts policies st act = true :=
  (Kernels.temporal_verdict_allow_iff act policies ev st).mp
    (combine_allow_implies_member vs _ hmem hcomb)

/-- **The composition theorem.** The fail-closed AND-combinator preserves both
    headline kernel invariants simultaneously: non-bypass (S) and
    no-conflicting-agreement (C) both survive composition under one host. -/
theorem and_combinator_preserves_invariants
    (vs vs' : List Verdict) (act act' : CanonicalAction)
    (pol : Seal.Policy) (ev : Kernels.SafetyEvidence) (st1 : SealCore.State)
    (target : SealCore.TargetHash)
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

/-- A line that classifies as a mediated act carries its routing/parse
    witness: the trimmed line parses as JSON to a value that `Seal.toolsCall?`
    recognises as the very `(tool, args)` the action carries. Extracted from
    `classifyLine` (Host.Canonical). -/
theorem classify_act_witness (line : String) (act : CanonicalAction)
    (h : classifyLine line = .act act) :
    ∃ json, Lean.Json.parse line.trimAscii.toString = .ok json ∧
      Seal.toolsCall? json = some (act.tool, act.argsJson) := by
  simp only [classifyLine] at h
  cases hp : Lean.Json.parse line.trimAscii.toString with
  | error e => simp [hp] at h
  | ok json =>
      cases ht : Seal.toolsCall? json with
      | none => simp [hp, ht] at h
      | some p =>
          obtain ⟨toolName, toolArgs⟩ := p
          simp only [hp, ht] at h
          injection h with hrec
          subst hrec
          exact ⟨json, rfl, ht⟩

/-- **THE FLAGSHIP — multi-gate non-bypass over the deployed step core.**

    If the pure routing core that `Ffi.stepImpl` delegates to routes a line to
    `forward`, then:

    * **(a) routing/parse witness** — the line was a genuine, parseable
      `tools/call` (`classifyLine` recognised it and the trimmed bytes parsed
      to the `(tool, args)` the mediated action carries); AND
    * **(b) fail-closed AND** — at least one kernel gated the call and EVERY
      gating kernel returned `allow` (`combine_allow_iff`). Composed with the
      per-gate `composed_*` theorems above, this means a forward implies every
      applicable gate's invariant held: a live matching approval (safety), a
      ratified quorum (consensus), a proven-convergent op (convergence), and no
      temporal-safety violation (temporal).

    TCB (NOT proven through): `Ffi.stepImpl`'s IO — the evidence gathered into
    `verdicts` via `Host.dispatch`, the session `IO.Ref` state, the JSON
    marshalling, and the `unsafeBaseIO` FFI boundary in `Ffi.sealHostStep`.
    This theorem is over the pure decision `stepImpl` delegates to
    (`Host.stepRoute`), not through the IO boundary. -/
theorem step_forward_non_bypass
    (line : String) (verdicts : List Verdict) (act : CanonicalAction)
    (hclass : classifyLine line = .act act)
    (hfwd : stepRoute (classifyLine line) verdicts = .forward) :
    (∃ json, Lean.Json.parse line.trimAscii.toString = .ok json ∧
        Seal.toolsCall? json = some (act.tool, act.argsJson)) ∧
    (verdicts ≠ [] ∧ ∀ v ∈ verdicts, v.kind = .allow) := by
  refine ⟨classify_act_witness line act hclass, ?_⟩
  rw [hclass] at hfwd
  have hall : combineVerdicts verdicts = .allow :=
    (stepRoute_act_forward_iff act verdicts).mp hfwd
  exact (combine_allow_iff verdicts).mp hall

end Host
