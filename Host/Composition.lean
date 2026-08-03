/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Registry
import Host.Canonical
import Host.Step
import Kernels.Safety
import Kernels.Consensus
import Kernels.Convergence
import Kernels.Temporal
import Kernels.Linear
import Kernels.Budget
import Kernels.Calibration

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

/-- Bridge for the composition theorem: kernel K's verdict is allow exactly
    when the executable calibration check accepts the evidence window. -/
theorem calibration_verdict_allow_iff
    (act : CanonicalAction) (cfg : Kernels.CalibrationConfig)
    (records : List Kernels.ForecastRecord) (st : Unit) :
    (Kernels.calibrationKernel.decide act cfg records st).1.kind = .allow ↔
      Kernels.calibratedB cfg records = true := by
  simp only [Kernels.calibrationKernel]
  by_cases h : Kernels.calibratedB cfg records <;> simp [h]

/-- **The calibration bound survives composition.** HONEST SCOPE: this
    delivers exactly `calibratedB = true` — the executable check passed, i.e.
    the evidence window met `minSamples` and the empirical |mean error| sat
    under the Hoeffding threshold AS COMPUTED IN FLOAT. That Float bound is a
    documented trusted mirror of calibration-lean's conditional sub-Gaussian /
    Azuma–Hoeffding mathematics (`hasCondSubgaussianMGF_of_mem_Icc`), cited
    not extracted — see `Kernels/Calibration.lean`. The statistical δ-bound is
    NOT proven here; kernel K stays experimental for exactly this reason. -/
theorem composed_calibration_bound
    (vs : List Verdict) (act : CanonicalAction) (cfg : Kernels.CalibrationConfig)
    (records : List Kernels.ForecastRecord) (st : Unit)
    (hmem : (Kernels.calibrationKernel.decide act cfg records st).1 ∈ vs)
    (hcomb : combineVerdicts vs = .allow) :
    Kernels.calibratedB cfg records = true :=
  (calibration_verdict_allow_iff act cfg records st).mp
    (combine_allow_implies_member vs _ hmem hcomb)

/-- The capability kernel L resolves for a call: the configured `capArg` path
    looked up in the call's args, for the first matching gated tool. Pure
    mirror of the resolution inside `Kernels.linearKernel.decide`. -/
def linearCapOf (cfg : Kernels.LinearConfig) (act : CanonicalAction) : Option String :=
  match cfg.tools.find? (fun t => t.tool == act.tool) with
  | none => none
  | some t => Seal.JsonUtil.atPath act.argsJson t.capArg >>=
      Seal.JsonUtil.jsonScalarToString

/-- A spend step allows exactly when the capability is actually held. -/
theorem linear_step_spend_allow_iff (st : LinearCore.LState) (cap : String) :
    (LinearCore.step st (.spend cap)).1 = .allow ↔ 0 < LinearCore.holds st cap := by
  cases h : LinearCore.holds st cap with
  | zero => rw [LinearCore.step_spend_exhausted st cap h]; simp
  | succ n => rw [LinearCore.step_spend_live st cap n h]; simp

/-- Bridge for the composition theorem: kernel L's verdict is allow exactly
    when the call resolved a capability and the linear automaton admitted the
    spend (i.e. the capability was held). -/
theorem linear_verdict_allow_iff
    (act : CanonicalAction) (cfg : Kernels.LinearConfig)
    (ev : List LinearCore.LEvent) (st : LinearCore.LState) :
    (Kernels.linearKernel.decide act cfg ev st).1.kind = .allow ↔
      ∃ cap, linearCapOf cfg act = some cap ∧
        (LinearCore.step st (.spend cap)).1 = .allow := by
  simp only [Kernels.linearKernel, linearCapOf]
  cases hfind : cfg.tools.find? (fun t => t.tool == act.tool) with
  | none => simp
  | some t =>
      cases hbind : Seal.JsonUtil.atPath act.argsJson t.capArg >>=
          Seal.JsonUtil.jsonScalarToString with
      | none => simp [hbind]
      | some cap =>
          cases hstep : LinearCore.step st (.spend cap) with
          | mk d st' => cases d <;> simp [hbind, hstep]

/-- On an allowed verdict, kernel L resolved a capability, the spend step
    allowed, and L's execution transition IS the linear automaton's spend
    transition. -/
theorem linear_decide_allow_spec
    (act : CanonicalAction) (cfg : Kernels.LinearConfig)
    (ev : List LinearCore.LEvent) (st : LinearCore.LState)
    (hallow : (Kernels.linearKernel.decide act cfg ev st).1.kind = .allow) :
    ∃ cap, linearCapOf cfg act = some cap ∧
      (LinearCore.step st (.spend cap)).1 = .allow ∧
      (Kernels.linearKernel.decide act cfg ev st).2
        = (LinearCore.step st (.spend cap)).2 := by
  simp only [Kernels.linearKernel, linearCapOf] at hallow ⊢
  cases hfind : cfg.tools.find? (fun t => t.tool == act.tool) with
  | none => simp [hfind] at hallow
  | some t =>
      cases hbind : Seal.JsonUtil.atPath act.argsJson t.capArg >>=
          Seal.JsonUtil.jsonScalarToString with
      | none => simp [hfind, hbind] at hallow
      | some cap =>
          cases hstep : LinearCore.step st (.spend cap) with
          | mk d st' =>
              cases d
              · simp [hbind, hstep]
              · simp [hfind, hbind, hstep] at hallow

/-- **Linear conservation survives composition.** A composed allow with the
    linear kernel present means the spend was BACKED: the call resolved a
    capability, the pre-state actually held at least one use (no spend from
    zero — the contrapositive of `LinearCore.spend_exhausted_blocked`), and
    the kernel's execution transition consumed EXACTLY one use
    (`LinearCore.spend_allow_consumes`). Trace-level conservation
    (`LinearCore.granted_plus_initial_eq_spent_plus_remaining` — granted +
    initial = spent + remaining) holds unconditionally over the ingest path;
    `linear_ingest_conservation` below instantiates it at kernel L's actual
    ingest fold. -/
theorem composed_linear_conservation
    (vs : List Verdict) (act : CanonicalAction) (cfg : Kernels.LinearConfig)
    (ev : List LinearCore.LEvent) (st : LinearCore.LState)
    (hmem : (Kernels.linearKernel.decide act cfg ev st).1 ∈ vs)
    (hcomb : combineVerdicts vs = .allow) :
    ∃ cap, linearCapOf cfg act = some cap ∧
      0 < LinearCore.holds st cap ∧
      LinearCore.holds (Kernels.linearKernel.decide act cfg ev st).2 cap
        = LinearCore.holds st cap - 1 := by
  have hkind := combine_allow_implies_member vs _ hmem hcomb
  obtain ⟨cap, hcap, hstep, hstate⟩ := linear_decide_allow_spec act cfg ev st hkind
  have hpos := (linear_step_spend_allow_iff st cap).mp hstep
  obtain ⟨n, hn⟩ : ∃ n, LinearCore.holds st cap = n + 1 :=
    ⟨LinearCore.holds st cap - 1, by omega⟩
  have hcons := (LinearCore.spend_allow_consumes st cap n hn).2
  refine ⟨cap, hcap, hpos, ?_⟩
  rw [hstate, hcons, hn]
  omega

/-- `runCount`'s final state is the plain step fold — the exact fold kernel L's
    `ingest` runs. -/
theorem runCount_state_eq_foldl (es : List LinearCore.LEvent) (s : LinearCore.LState)
    (cap : String) :
    (LinearCore.runCount s cap es).1
      = es.foldl (fun s e => (LinearCore.step s e).2) s := by
  induction es generalizing s with
  | nil => rfl
  | cons e rest ih =>
      simp only [LinearCore.runCount, List.foldl]
      exact ih _

/-- **Conservation at the deployed kernel state** (UNCONDITIONAL — needs no
    composed allow; stated here to bind the core linear-logic theorem to the
    state kernel L actually ingests): granted + initial = allowed spends +
    remaining, where the remaining is read off `linearKernel.ingest`'s output. -/
theorem linear_ingest_conservation
    (ev : List LinearCore.LEvent) (st0 : LinearCore.LState) (cap : String) :
    LinearCore.granted cap ev + LinearCore.holds st0 cap
      = (LinearCore.runCount st0 cap ev).2
        + LinearCore.holds (Kernels.linearKernel.ingest ev st0) cap := by
  have h := LinearCore.granted_plus_initial_eq_spent_plus_remaining ev st0 cap
  rwa [runCount_state_eq_foldl] at h

/-- Pure mirror of kernel B's per-budget fold step — byte-identical body to
    the lambda inside `Kernels.budgetKernel.decide`, so the two are
    definitionally equal. An error (missing cost, over budget) absorbs; an ok
    threads the updated counters. -/
def budgetStepE (act : CanonicalAction)
    (acc : Except String Kernels.BudgetState) (spec : Kernels.BudgetSpec) :
    Except String Kernels.BudgetState := do
  let st' ← acc
  match Kernels.costFor spec act.argsJson with
  | none => throw s!"missing cost field for budget {spec.name}: {act.tool}"
  | some cost =>
      match BudgetCore.step spec.cap (Kernels.budgetStateFor st' spec.name) cost with
      | (.allow, b') => pure (Kernels.setBudgetState st' spec.name b')
      | (.block, b) =>
          throw s!"over budget {spec.name} ({b.spent}+{cost}>{spec.cap}): {act.tool}"

/-- Bridge for the composition theorem: kernel B's verdict is allow exactly
    when the covering-budgets fold ran to completion without a veto. -/
theorem budget_verdict_allow_iff
    (act : CanonicalAction) (cfg : Kernels.BudgetConfig)
    (ev : Unit) (st : Kernels.BudgetState) :
    (Kernels.budgetKernel.decide act cfg ev st).1.kind = .allow ↔
      ∃ st', (cfg.filter (fun b => b.tools.contains act.tool)).foldl
        (budgetStepE act) (.ok st) = .ok st' := by
  show (match (cfg.filter (fun b => b.tools.contains act.tool)).foldl
      (budgetStepE act) (.ok st) with
    | .ok st' => _
    | .error reason => _ : Verdict × Kernels.BudgetState).1.kind = .allow ↔ _
  cases h : (cfg.filter (fun b => b.tools.contains act.tool)).foldl
      (budgetStepE act) (.ok st) with
  | ok st' => simp
  | error reason => simp

/-- The budget fold absorbs an error: once one covering budget vetoes, the
    outcome stays vetoed. -/
theorem budgetFold_error (act : CanonicalAction) (specs : List Kernels.BudgetSpec)
    (e : String) : specs.foldl (budgetStepE act) (.error e) = .error e := by
  induction specs with
  | nil => rfl
  | cons s rest ih => exact ih

/-- Fold elimination: an ok outcome means EVERY covering budget resolved this
    call's cost and admitted it through `BudgetCore.step` at some intermediate
    counter (the fold's actual running state for that budget name). -/
theorem budget_fold_ok_spec (act : CanonicalAction) :
    ∀ (specs : List Kernels.BudgetSpec) (st st' : Kernels.BudgetState),
      specs.foldl (budgetStepE act) (.ok st) = .ok st' →
      ∀ spec ∈ specs, ∃ (pre : BudgetCore.BState) (cost : Nat),
        Kernels.costFor spec act.argsJson = some cost ∧
        (BudgetCore.step spec.cap pre cost).1 = .allow := by
  intro specs
  induction specs with
  | nil => intro _ _ _ spec hspec; cases hspec
  | cons s rest ih =>
      intro st st' hfold spec hspec
      rw [List.foldl_cons] at hfold
      cases hhead : budgetStepE act (.ok st) s with
      | error e => rw [hhead, budgetFold_error] at hfold; cases hfold
      | ok st1 =>
          rw [hhead] at hfold
          cases hspec with
          | head =>
              simp only [budgetStepE, bind, Except.bind] at hhead
              cases hcost : Kernels.costFor s act.argsJson with
              | none => simp only [hcost] at hhead; cases hhead
              | some cost =>
                  simp only [hcost] at hhead
                  cases hstep : BudgetCore.step s.cap
                      (Kernels.budgetStateFor st s.name) cost with
                  | mk d b =>
                      cases d
                      · exact ⟨Kernels.budgetStateFor st s.name, cost, rfl,
                          by rw [hstep]⟩
                      · simp only [hstep] at hhead; cases hhead
          | tail _ hmem => exact ih st1 st' hfold spec hmem

/-- **Budget caps survive composition.** A composed allow with the budget
    kernel present means every covering budget resolved this call's cost (the
    fail-closed cost parse succeeded) and admitted it through the PROVEN gate:
    at the counter it was checked against, `spent + cost ≤ cap`
    (`BudgetCore.allow_iff_within`), the updated counter stays within the cap
    (the one-step form of `BudgetCore.run_never_over_budget`), and in
    particular `cost ≤ cap` outright. The intermediate counter `pre` is the
    fold's actual running state for that budget name; it is existentially
    quantified because covering budgets sharing a name advance it. -/
theorem composed_budget_cap
    (vs : List Verdict) (act : CanonicalAction) (cfg : Kernels.BudgetConfig)
    (ev : Unit) (st : Kernels.BudgetState)
    (hmem : (Kernels.budgetKernel.decide act cfg ev st).1 ∈ vs)
    (hcomb : combineVerdicts vs = .allow) :
    ∀ spec ∈ cfg.filter (fun b => b.tools.contains act.tool),
      ∃ (pre : BudgetCore.BState) (cost : Nat),
        Kernels.costFor spec act.argsJson = some cost ∧
        pre.spent + cost ≤ spec.cap ∧
        ((BudgetCore.step spec.cap pre cost).2).spent ≤ spec.cap ∧
        cost ≤ spec.cap := by
  intro spec hspec
  have hkind := combine_allow_implies_member vs _ hmem hcomb
  obtain ⟨st', hfold⟩ := (budget_verdict_allow_iff act cfg ev st).mp hkind
  obtain ⟨pre, cost, hcost, hallow⟩ :=
    budget_fold_ok_spec act _ st st' hfold spec hspec
  have hwithin := (BudgetCore.allow_iff_within spec.cap pre cost).mp hallow
  have hpost := BudgetCore.never_over_budget spec.cap pre cost (by omega)
  exact ⟨pre, cost, hcost, hwithin, hpost, by omega⟩

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
  split at h
  · exact absurd h (by simp)   -- unsafe wire ⇒ .refuse ≠ .act act
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

/-- **THE CLOSED ALGEBRA.** One composed allow, and EVERY kernel present in
    the verdict set carries its own proven invariant, simultaneously:

    * **S** non-bypass — a guarded call had a live matching approval;
    * **C** no-conflicting-agreement — quantified over any second composed
      allow against the same roster and votes;
    * **V** convergence — the admitted op is in the proven-convergent set;
    * **T** temporal safety — no configured LTL safety policy forbids the call;
    * **L** linear conservation — the spend was backed and consumed exactly
      one use;
    * **B** budget caps — every covering budget admitted the cost within cap;
    * **K** calibration — the executable calibration check passed (trusted
      Float mirror; see `composed_calibration_bound`).

    Each conjunct is guarded by that kernel's verdict membership, so this one
    theorem covers ANY subset of the wired kernels — including none
    (vacuously): compose any subset under the fail-closed AND-gate and every
    present kernel's proven safety invariant holds. Instantiating
    `vs := pureVerdicts insts act₀` (with `pureVerdicts_mem` discharging the
    membership guards) makes "any registered subset, in any order" literal.
    Generalises `and_combinator_preserves_invariants` from the S+C pair to
    all seven.

    SAFETY fragment only — no conjunct claims liveness or progress. -/
theorem registry_closed_algebra
    (vs : List Verdict) (hcomb : combineVerdicts vs = .allow) :
    -- S: non-bypass
    (∀ (act : CanonicalAction) (pol : Seal.Policy) (ev : Kernels.SafetyEvidence)
        (st1 : SealCore.State) (target : SealCore.TargetHash),
      (Kernels.safetyKernel.decide act pol ev st1).1 ∈ vs →
      (Seal.classifyToolCall pol act.tool act.argsJson).toEvent =
        SealCore.Event.guarded target →
      SealCore.live st1 target ev.now = true) ∧
    -- C: no conflicting agreement (any second composed allow, same votes)
    (∀ (act act' : CanonicalAction) (cfg : Kernels.ConsensusConfig)
        (votes : Consensus.Checker.Votes) (vs' : List Verdict),
      (Kernels.consensusKernel.decide act cfg votes ()).1 ∈ vs →
      (Kernels.consensusKernel.decide act' cfg votes ()).1 ∈ vs' →
      combineVerdicts vs' = .allow →
      (Kernels.certFor votes act.tool).value = (Kernels.certFor votes act'.tool).value) ∧
    -- V: convergent-op admission
    (∀ (act : CanonicalAction) (cfg : Kernels.ConvergenceConfig),
      (Kernels.convergenceKernel.decide act cfg () ()).1 ∈ vs →
      Kernels.convergentAccepts cfg act = true) ∧
    -- T: temporal safety
    (∀ (act : CanonicalAction) (policies : List Kernels.TemporalPolicy)
        (st : Kernels.TemporalState),
      (Kernels.temporalKernel.decide act policies () st).1 ∈ vs →
      Kernels.temporalAccepts policies st act = true) ∧
    -- L: backed, single-use spend
    (∀ (act : CanonicalAction) (cfg : Kernels.LinearConfig)
        (ev : List LinearCore.LEvent) (st : LinearCore.LState),
      (Kernels.linearKernel.decide act cfg ev st).1 ∈ vs →
      ∃ cap, linearCapOf cfg act = some cap ∧
        0 < LinearCore.holds st cap ∧
        LinearCore.holds (Kernels.linearKernel.decide act cfg ev st).2 cap
          = LinearCore.holds st cap - 1) ∧
    -- B: within-cap budget admission
    (∀ (act : CanonicalAction) (cfg : Kernels.BudgetConfig) (st : Kernels.BudgetState),
      (Kernels.budgetKernel.decide act cfg () st).1 ∈ vs →
      ∀ spec ∈ cfg.filter (fun b => b.tools.contains act.tool),
        ∃ (pre : BudgetCore.BState) (cost : Nat),
          Kernels.costFor spec act.argsJson = some cost ∧
          pre.spent + cost ≤ spec.cap ∧
          ((BudgetCore.step spec.cap pre cost).2).spent ≤ spec.cap ∧
          cost ≤ spec.cap) ∧
    -- K: executable calibration bound (trusted Float mirror)
    (∀ (act : CanonicalAction) (cfg : Kernels.CalibrationConfig)
        (records : List Kernels.ForecastRecord),
      (Kernels.calibrationKernel.decide act cfg records ()).1 ∈ vs →
      Kernels.calibratedB cfg records = true) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro act pol ev st1 target hmem hguard
    exact composed_non_bypass vs act pol ev st1 target hmem hcomb hguard
  · intro act act' cfg votes vs' hmem hmem' hcomb'
    exact composed_no_conflicting_agreement vs vs' act act' cfg votes hmem hmem' hcomb hcomb'
  · intro act cfg hmem
    exact composed_convergent vs act cfg () () hmem hcomb
  · intro act policies st hmem
    exact composed_temporal_safety vs act policies () st hmem hcomb
  · intro act cfg ev st hmem
    exact composed_linear_conservation vs act cfg ev st hmem hcomb
  · intro act cfg st hmem
    exact composed_budget_cap vs act cfg () st hmem hcomb
  · intro act cfg records hmem
    exact composed_calibration_bound vs act cfg records () hmem hcomb

/-- Registry altitude: for ANY pure instance list (any subset of the kernels,
    in any order — `Host.PureInst` mirrors what phase 1 of `dispatch` feeds
    each gating kernel), a composed allow over `pureVerdicts` carries every
    gating instance's individual allow. Together with `pureVerdicts_mem`, this
    is the hook that instantiates `registry_closed_algebra`'s membership
    guards at the registry fold. The IO realization of `dispatch` (evidence
    gathering, `IO.Ref` state, commit discipline) remains TCB. -/
theorem pure_dispatch_allow_member
    (insts : List PureInst) (act : CanonicalAction)
    (hallow : combineVerdicts (pureVerdicts insts act) = .allow)
    (i : PureInst) (hi : i ∈ insts) (hg : i.kernel.gates i.config act = true) :
    (i.kernel.decide act i.config i.evidence i.state).1.kind = .allow :=
  combine_allow_implies_member _ _ (pureVerdicts_mem insts act i hi hg) hallow

end Host

/-! ## Axiom pins — enforced at module build

Every theorem in the composition algebra depends on at most Lean's three
classical axioms. No opaque crypto (ed25519 / A3) and no `sorryAx` appears in
any composition proof. These `#guard_msgs` pins fail the build on drift. -/

/-- info: 'Host.calibration_verdict_allow_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.calibration_verdict_allow_iff
/-- info: 'Host.composed_calibration_bound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.composed_calibration_bound
/-- info: 'Host.linear_step_spend_allow_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.linear_step_spend_allow_iff
/-- info: 'Host.linear_verdict_allow_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.linear_verdict_allow_iff
/-- info: 'Host.linear_decide_allow_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.linear_decide_allow_spec
/-- info: 'Host.composed_linear_conservation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.composed_linear_conservation
/-- info: 'Host.runCount_state_eq_foldl' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.runCount_state_eq_foldl
/-- info: 'Host.linear_ingest_conservation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.linear_ingest_conservation
/-- info: 'Host.budget_verdict_allow_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.budget_verdict_allow_iff
/-- info: 'Host.budgetFold_error' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.budgetFold_error
/-- info: 'Host.budget_fold_ok_spec' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.budget_fold_ok_spec
/-- info: 'Host.composed_budget_cap' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.composed_budget_cap
/-- info: 'Host.registry_closed_algebra' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.registry_closed_algebra
/-- info: 'Host.pureVerdicts_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureVerdicts_mem
/-- info: 'Host.pure_dispatch_allow_member' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pure_dispatch_allow_member
