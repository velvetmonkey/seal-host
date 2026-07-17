/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Commit
import Kernels.PrincipalBudget

/-!
# Kernel PB over the committed trace — per-principal caps and isolation

The `Host/Commit.lean` budget block (kernel B, `:448–671`) re-proven at the
V2.1 per-principal key `(principal id, budget name)`:

* `principal_budget_commitStep_deny` — a denied call consumes NO principal
  budget (ingest is the identity; the decide transition is withheld).
* `principal_budget_committed_trace_within_cap(_of_consistent)` —
  **`BudgetCore.run_never_over_budget` per (principal, name) at the committed
  trace**: across ANY call sequence, denies included, every principal's
  committed counter for a spec stays within that spec's cap. `hdom` is the
  same honest-scope hypothesis as kernel B's (name-sharers share one counter
  per principal), discharged for every loaded config by the
  `Host.ofBundle_principals_consistent` lint.
* `principal_budget_trace_isolation` — **the isolation frame lemma at the
  trace**: a call sequence containing no successfully authenticated call by
  `q` never moves ANY of q's counters — the single-step
  `Kernels.principal_budget_isolation` composed through the two-phase
  commit, denies and unauthenticated (`none`) calls included.

Same model boundary as the kernel-B block: these theorems live in the pure
commit model (`commitStep`/`commitRun`); the IO realization (dispatch shell,
`stepImpl` marshalling, FFI) stays the named TCB.
-/

namespace Host

open Kernels (pbStateFor setPbState pbStepE principalBudgetKernel
  PrincipalsConfig PBState)

/-- A denied call consumes NO principal budget: kernel PB's committed state
    after a combined deny is byte-identical to its pre-call state
    (`budget_commitStep_deny` twin). -/
theorem principal_budget_commitStep_deny (cfg : PrincipalsConfig)
    (c : PureCall principalBudgetKernel) (st : PBState)
    (hdeny : combineVerdicts (c.others
        ++ [(principalBudgetKernel.decide c.act cfg c.evidence st).1]) ≠ .allow) :
    commitStep principalBudgetKernel cfg c st = st := by
  rw [commitStep_deny _ _ _ _ hdeny]
  split <;> rfl

/-- Bridge: kernel PB's verdict at authenticated evidence is allow exactly
    when the covering fold ran to completion (`budget_verdict_allow_iff`
    twin; at `none` evidence the verdict is a deny outright —
    `Kernels.principal_budget_none_denies`). -/
theorem pb_verdict_allow_iff (act : CanonicalAction) (cfg : PrincipalsConfig)
    (p : AuthenticatedPrincipal) (st : PBState) :
    (principalBudgetKernel.decide act cfg (some p) st).1.kind = .allow ↔
      ∃ st', (cfg.budgets.filter (fun b => b.tools.contains act.tool)).foldl
        (pbStepE p.id act) (.ok st) = .ok st' := by
  show (match (cfg.budgets.filter (fun b => b.tools.contains act.tool)).foldl
      (pbStepE p.id act) (.ok st) with
    | .ok st' => _
    | .error reason => _ : Verdict × PBState).1.kind = .allow ↔ _
  cases h : (cfg.budgets.filter (fun b => b.tools.contains act.tool)).foldl
      (pbStepE p.id act) (.ok st) with
  | ok st' => simp
  | error reason => simp

/-- On an ok fold, kernel PB's execution transition IS the fold's output
    (`budget_decide_snd_of_fold_ok` twin). -/
theorem pb_decide_snd_of_fold_ok (act : CanonicalAction)
    (cfg : PrincipalsConfig) (p : AuthenticatedPrincipal)
    (st st1 : PBState)
    (hfold : (cfg.budgets.filter (fun b => b.tools.contains act.tool)).foldl
        (pbStepE p.id act) (.ok st) = .ok st1) :
    (principalBudgetKernel.decide act cfg (some p) st).2 = st1 := by
  show (match (cfg.budgets.filter (fun b => b.tools.contains act.tool)).foldl
      (pbStepE p.id act) (.ok st) with
    | .ok st' => _
    | .error reason => _ : Verdict × PBState).2 = st1
  rw [hfold]

/-- One `pbStepE` step preserves the per-(principal, name) cap bound under
    cap domination for shared names (`budgetStepE_preserves` twin). -/
theorem pbStepE_preserves (pid : String) (act : CanonicalAction)
    (spec s : Kernels.BudgetSpec)
    (hdom : s.name = spec.name → s.cap ≤ spec.cap)
    (st st1 : PBState)
    (hstep : pbStepE pid act (.ok st) s = .ok st1)
    (hinv : (pbStateFor st (pid, spec.name)).spent ≤ spec.cap) :
    (pbStateFor st1 (pid, spec.name)).spent ≤ spec.cap := by
  simp only [pbStepE, bind, Except.bind] at hstep
  cases hcost : Kernels.costFor s act.argsJson with
  | none => simp [hcost] at hstep
  | some cost =>
      simp only [hcost] at hstep
      cases hbs : BudgetCore.step s.cap (pbStateFor st (pid, s.name)) cost with
      | mk d b =>
          cases d
          · simp only [hbs, pure, Except.pure] at hstep
            injection hstep with hst1
            subst hst1
            have hallow : (BudgetCore.step s.cap
                (pbStateFor st (pid, s.name)) cost).1 = .allow := by rw [hbs]
            have hspent : b.spent
                = (pbStateFor st (pid, s.name)).spent + cost := by
              have := budget_step_allow_spent s.cap
                (pbStateFor st (pid, s.name)) cost hallow
              rwa [hbs] at this
            by_cases hname : s.name = spec.name
            · rw [← hname, Kernels.pbStateFor_set_eq, hspent]
              have hw := (BudgetCore.allow_iff_within s.cap
                (pbStateFor st (pid, s.name)) cost).mp hallow
              exact Nat.le_trans hw (hdom hname)
            · rw [Kernels.pbStateFor_set_ne st (pid, s.name) (pid, spec.name) b
                (fun h => hname (congrArg Prod.snd h).symm)]
              exact hinv
          · simp only [hbs] at hstep
            cases hstep

/-- The covering fold preserves the per-(principal, name) cap bound
    (`budget_fold_ok_preserves` twin). -/
theorem pb_fold_ok_preserves (pid : String) (act : CanonicalAction)
    (spec : Kernels.BudgetSpec) :
    ∀ (specs : List Kernels.BudgetSpec),
      (∀ s ∈ specs, s.name = spec.name → s.cap ≤ spec.cap) →
      ∀ (st st1 : PBState),
        specs.foldl (pbStepE pid act) (.ok st) = .ok st1 →
        (pbStateFor st (pid, spec.name)).spent ≤ spec.cap →
        (pbStateFor st1 (pid, spec.name)).spent ≤ spec.cap := by
  intro specs
  induction specs with
  | nil =>
      intro _ st st1 hfold hinv
      injection hfold with h
      rwa [← h]
  | cons s rest ih =>
      intro hdom st st1 hfold hinv
      rw [List.foldl_cons] at hfold
      cases hhead : pbStepE pid act (.ok st) s with
      | error e => rw [hhead, Kernels.pbFold_error] at hfold; cases hfold
      | ok stm =>
          rw [hhead] at hfold
          exact ih (fun s' hs' => hdom s' (List.mem_cons_of_mem _ hs')) stm st1 hfold
            (pbStepE_preserves pid act spec s (hdom s List.mem_cons_self)
              st stm hhead hinv)

/-- **`BudgetCore.run_never_over_budget` PER (PRINCIPAL, NAME) AT THE
    COMMITTED TRACE** (`budget_committed_trace_within_cap` twin): for every
    principal id, across ANY call sequence containing denies and
    unauthenticated calls, the committed counter for `spec` stays within
    `spec.cap`. HONEST SCOPE — `hdom` as in kernel B: covering budgets
    sharing a name advance ONE shared counter per principal, so the bound is
    stated for a spec whose cap dominates its name-sharers; discharged for
    deployed configs by `..._of_consistent` below. -/
theorem principal_budget_committed_trace_within_cap (cfg : PrincipalsConfig)
    (spec : Kernels.BudgetSpec)
    (hdom : ∀ s ∈ cfg.budgets, s.name = spec.name → s.cap ≤ spec.cap)
    (pid : String)
    (calls : List (PureCall principalBudgetKernel)) (st0 : PBState)
    (h0 : (pbStateFor st0 (pid, spec.name)).spent ≤ spec.cap) :
    (pbStateFor (commitRun principalBudgetKernel cfg calls st0)
        (pid, spec.name)).spent ≤ spec.cap := by
  induction calls generalizing st0 with
  | nil => exact h0
  | cons c calls ih =>
      refine ih _ ?_
      unfold commitStep
      simp only [Kernels.principal_budget_ingest_id]
      by_cases hg : principalBudgetKernel.gates cfg c.act
      · rw [if_pos hg]
        by_cases hcomb : combineVerdicts (c.others
            ++ [(principalBudgetKernel.decide c.act cfg c.evidence st0).1]) = .allow
        · rw [if_pos hcomb]
          have hkind : (principalBudgetKernel.decide c.act cfg c.evidence
              st0).1.kind = .allow :=
            combine_allow_implies_member _ _
              (List.mem_append_right _ List.mem_cons_self) hcomb
          cases hev : c.evidence with
          | none =>
              rw [hev, Kernels.principal_budget_none_denies] at hkind
              simp at hkind
          | some p =>
              rw [hev] at hkind
              obtain ⟨st', hfold⟩ := (pb_verdict_allow_iff c.act cfg p st0).mp hkind
              rw [pb_decide_snd_of_fold_ok c.act cfg p st0 st' hfold]
              by_cases hpid : p.id = pid
              · subst hpid
                exact pb_fold_ok_preserves p.id c.act spec _
                  (fun s hs => hdom s (List.mem_of_mem_filter hs)) st0 st' hfold h0
              · rw [Kernels.pb_fold_other_principal p.id c.act pid spec.name
                      (fun h => hpid h.symm) _ st0 st' hfold]
                exact h0
        · rw [if_neg hcomb]
          exact h0
      · rw [if_neg hg]
        exact h0

/-- **`hdom` DISCHARGED FOR DEPLOYED CONFIGS**: any config `Host.ofBundle`
    accepts satisfies `Kernels.budgetCapsConsistent` on its per-principal
    specs (`Host.ofBundle_principals_consistent`), so the committed-trace
    bound holds for EVERY spec of the section, every principal
    (`budget_committed_trace_within_cap_of_consistent` twin). -/
theorem principal_budget_committed_trace_within_cap_of_consistent
    (cfg : PrincipalsConfig) (spec : Kernels.BudgetSpec)
    (hconsist : Kernels.budgetCapsConsistent cfg.budgets = true)
    (hspec : spec ∈ cfg.budgets) (pid : String)
    (calls : List (PureCall principalBudgetKernel)) (st0 : PBState)
    (h0 : (pbStateFor st0 (pid, spec.name)).spent ≤ spec.cap) :
    (pbStateFor (commitRun principalBudgetKernel cfg calls st0)
        (pid, spec.name)).spent ≤ spec.cap :=
  principal_budget_committed_trace_within_cap cfg spec
    (fun _s hs hname =>
      Nat.le_of_eq (budgetCapsConsistent_caps_eq cfg.budgets hconsist hspec hs hname))
    pid calls st0 h0

/-- The committed-trace per-principal bound from the kernel's actual initial
    state (every counter empty). -/
theorem principal_budget_committed_trace_from_init (cfg : PrincipalsConfig)
    (spec : Kernels.BudgetSpec)
    (hdom : ∀ s ∈ cfg.budgets, s.name = spec.name → s.cap ≤ spec.cap)
    (pid : String)
    (calls : List (PureCall principalBudgetKernel)) :
    (pbStateFor (commitRun principalBudgetKernel cfg calls
        principalBudgetKernel.init) (pid, spec.name)).spent ≤ spec.cap :=
  principal_budget_committed_trace_within_cap cfg spec hdom pid calls _
    (Nat.zero_le _)

/-- One committed step never moves a non-participating principal's counter:
    denied calls freeze the state, unauthenticated calls freeze the state,
    and an authenticated call by someone else only writes its own keys
    (`Kernels.principal_budget_isolation`). -/
theorem principal_budget_commitStep_other (cfg : PrincipalsConfig)
    (c : PureCall principalBudgetKernel) (st : PBState) (q name : String)
    (hq : ∀ p, c.evidence = some p → p.id ≠ q) :
    pbStateFor (commitStep principalBudgetKernel cfg c st) (q, name)
      = pbStateFor st (q, name) := by
  unfold commitStep
  simp only [Kernels.principal_budget_ingest_id]
  by_cases hg : principalBudgetKernel.gates cfg c.act
  · rw [if_pos hg]
    by_cases hcomb : combineVerdicts (c.others
        ++ [(principalBudgetKernel.decide c.act cfg c.evidence st).1]) = .allow
    · rw [if_pos hcomb]
      cases hev : c.evidence with
      | none => rw [Kernels.principal_budget_none_frozen]
      | some p =>
          exact Kernels.principal_budget_isolation c.act cfg p st q name
            (Ne.symm (hq p hev))
    · rw [if_neg hcomb]
  · rw [if_neg hg]

/-- **ISOLATION AT THE TRACE** (the V2.1 headline, composed): a call
    sequence containing NO successfully authenticated call by `q` never
    moves any of q's committed counters — whatever the other principals did,
    however many calls were denied, and however many unauthenticated calls
    were refused. A spoofed request field cannot debit `q` because no
    request field reaches the debit key at any step of any trace. -/
theorem principal_budget_trace_isolation (cfg : PrincipalsConfig)
    (calls : List (PureCall principalBudgetKernel)) (st0 : PBState)
    (q name : String)
    (hq : ∀ c ∈ calls, ∀ p, c.evidence = some p → p.id ≠ q) :
    pbStateFor (commitRun principalBudgetKernel cfg calls st0) (q, name)
      = pbStateFor st0 (q, name) := by
  induction calls generalizing st0 with
  | nil => rfl
  | cons c calls ih =>
      show pbStateFor (commitRun principalBudgetKernel cfg calls
        (commitStep principalBudgetKernel cfg c st0)) (q, name) = _
      rw [ih _ (fun c' hc' => hq c' (List.mem_cons_of_mem _ hc'))]
      exact principal_budget_commitStep_other cfg c st0 q name
        (hq c List.mem_cons_self)

end Host

/-! ## Axiom pins — enforced at module build -/

/-- info: 'Host.principal_budget_commitStep_deny' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.principal_budget_commitStep_deny
/-- info: 'Host.pb_verdict_allow_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pb_verdict_allow_iff
/-- info: 'Host.pb_decide_snd_of_fold_ok' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pb_decide_snd_of_fold_ok
/-- info: 'Host.pbStepE_preserves' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pbStepE_preserves
/-- info: 'Host.pb_fold_ok_preserves' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pb_fold_ok_preserves
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
/--
info: 'Host.principal_budget_commitStep_other' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.principal_budget_commitStep_other
/--
info: 'Host.principal_budget_trace_isolation' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.principal_budget_trace_isolation
