/- SPDX-License-Identifier: Apache-2.0 -/

import Seal.Hash
import Seal.JsonUtil
import Host.Kernel
import Host.Principal
import Kernels.BudgetCore
import Kernels.Budget

/-!
# Kernel PB — the per-principal Budget kernel (V2.1 Route 2)

The 8th wired kernel. `Kernels.budgetKernel` (kernel B) is byte-untouched;
this kernel re-keys the same proven `BudgetCore` automaton by
**(principal id, budget name)** — the principal axis is pure state indexing
above the unchanged core, which is exactly why Budget is the right first
kernel for the principal dimension.

**Where the principal comes from.** `Evidence := Option AuthenticatedPrincipal`
— produced ONLY by the Lean parse path (`Ffi.stepInputsOf` →
`Host.verifyEnvelope`) and threaded through `registryFor`. Rust never passes a
principal string; `AuthenticatedPrincipal`'s constructor is private
(`Host/Principal.lean`), so no request field can reach the debit key even by
construction.

**Mixed-mode is fail-closed.** A gated tool with `none` evidence (no envelope,
or an envelope that failed verification, or a stale/replayed nonce dropped by
the Rust freshness filter) is DENIED and the state is frozen
(`principal_budget_none_denies` / `principal_budget_none_frozen`). An operator
who adds principal budgets to a config breaks unauthenticated callers of the
covered tools — deliberately; the config lint in `Host.Config` refuses the
worst footgun (budgets with an empty key registry).

**The headline theorem** — `principal_budget_isolation`: a step by principal
`p` leaves EVERY other principal's counter unchanged, for every action, every
config, every state. Quantifying over all `act` is precisely "no request
field reaches the debit key": the key's first component comes only from the
evidence. Composition with `BudgetCore.run_never_over_budget` at the
committed trace lives in `Host/PrincipalCommit.lean`.
-/

namespace Kernels

/-- The `principals` config section: the Ed25519 key registry plus the
    per-principal budget specs. Each spec is enforced PER PRINCIPAL: every
    authenticated principal owns its own counter per budget name. -/
structure PrincipalsConfig where
  registry : Host.PrincipalRegistry
  budgets : List BudgetSpec
  deriving Repr

/-- The per-principal counter key: (principal id, budget name). -/
abbrev PBKey := String × String

/-- Per-(principal, budget) counters. Missing entry = nothing spent. -/
abbrev PBState := List (PBKey × BudgetCore.BState)

def pbStateFor (st : PBState) (k : PBKey) : BudgetCore.BState :=
  (st.find? (fun e => e.1 == k)).map (·.2) |>.getD BudgetCore.BState.empty

def setPbState (st : PBState) (k : PBKey) (b : BudgetCore.BState) : PBState :=
  (k, b) :: st.filter (fun e => e.1 != k)

/-- Kernel PB's per-budget fold step (named, unlike kernel B's historical
    inline lambda, so the commit-discipline proofs get a definitional
    handle). An error (missing cost, over budget) absorbs; an ok threads the
    updated counters. The debit key is `(pid, spec.name)` — `pid` comes from
    the fold's `AuthenticatedPrincipal` argument, never from `act`. -/
def pbStepE (pid : String) (act : Host.CanonicalAction)
    (acc : Except String PBState) (spec : BudgetSpec) :
    Except String PBState := do
  let st' ← acc
  match costFor spec act.argsJson with
  | none => throw s!"missing cost field for principal budget {spec.name}: {act.tool}"
  | some cost =>
      match BudgetCore.step spec.cap (pbStateFor st' (pid, spec.name)) cost with
      | (.allow, b') => pure (setPbState st' (pid, spec.name) b')
      | (.block, b) =>
          throw s!"over principal budget {spec.name} ({b.spent}+{cost}>{spec.cap}): {act.tool}"

/-- Kernel PB — per-principal Budget. Every covering budget must admit the
    call's cost through `BudgetCore.step` at the caller's own
    (principal, name) counter; one over-budget counter vetoes; a gated call
    with no authenticated principal is denied outright (mixed-mode
    fail-closed). -/
def principalBudgetKernel : Host.Kernel where
  name := "principal_budget"
  Config := PrincipalsConfig
  Evidence := Option Host.AuthenticatedPrincipal
  State := PBState
  init := []
  gates := fun cfg act => cfg.budgets.any (fun b => b.tools.contains act.tool)
  ingest := fun _ st => st
  decide := fun act cfg ev st =>
    let mk := fun (kind : Host.VerdictKind) (reason : String) (st' : PBState) =>
      ({ kernel := "principal_budget", kind, reason,
         certHash := Seal.auditHashParts ["principal_budget", kind.text, reason] },
       st')
    match ev with
    | none => mk .deny s!"principal envelope required: {act.tool}" st
    | some p =>
        let covering := cfg.budgets.filter (fun b => b.tools.contains act.tool)
        match covering.foldl (pbStepE p.id act) (.ok st) with
        | .ok st' => mk .allow s!"within principal budget ({p.id}): {act.tool}" st'
        | .error reason => mk .deny reason st

/-! ## Counter-map lemmas (the `budgetStateFor_set_*` clones at the pair key) -/

private theorem find?_filter_of_imp {α : Type _} (l : List α) (p q : α → Bool)
    (h : ∀ a, p a = true → q a = true) :
    (l.filter q).find? p = l.find? p := by
  induction l with
  | nil => rfl
  | cons a t ih =>
      by_cases hq : q a = true
      · rw [List.filter_cons_of_pos hq]
        by_cases hp : p a = true
        · rw [List.find?_cons_of_pos hp, List.find?_cons_of_pos hp]
        · rw [List.find?_cons_of_neg (by simpa using hp),
              List.find?_cons_of_neg (by simpa using hp), ih]
      · have hp : p a = false := by
          cases hpa : p a
          · rfl
          · exact absurd (h a hpa) (by simpa using hq)
        rw [List.filter_cons_of_neg (by simpa using hq),
            List.find?_cons_of_neg (by simp [hp]), ih]

/-- Writing one (principal, budget) counter reads back as written. -/
theorem pbStateFor_set_eq (st : PBState) (k : PBKey) (b : BudgetCore.BState) :
    pbStateFor (setPbState st k b) k = b := by
  simp [pbStateFor, setPbState]

/-- Writing one (principal, budget) counter leaves every OTHER key's counter
    alone — the single-write frame fact `principal_budget_isolation` folds. -/
theorem pbStateFor_set_ne (st : PBState) (k k' : PBKey)
    (b : BudgetCore.BState) (hne : k' ≠ k) :
    pbStateFor (setPbState st k b) k' = pbStateFor st k' := by
  simp only [pbStateFor, setPbState]
  rw [List.find?_cons_of_neg (by simp [Ne.symm hne]), find?_filter_of_imp]
  intro e he
  have : e.1 = k' := by simpa using he
  simp [this, hne]

/-- Kernel PB's `ingest` is the identity: evidence is per-call (the verified
    principal), nothing folds into state on the ingest phase — the
    `budget_ingest_id` twin, and what makes "a denied call consumes no
    principal budget" one simp step at the registry. -/
@[simp] theorem principal_budget_ingest_id
    (ev : Option Host.AuthenticatedPrincipal) (st : PBState) :
    principalBudgetKernel.ingest ev st = st := rfl

/-! ## Mixed-mode fail-closed, both halves -/

/-- A gated call with NO authenticated principal is denied. -/
theorem principal_budget_none_denies (act : Host.CanonicalAction)
    (cfg : PrincipalsConfig) (st : PBState) :
    (principalBudgetKernel.decide act cfg none st).1.kind = .deny := rfl

/-- ... and consumes nothing: the state is frozen. -/
theorem principal_budget_none_frozen (act : Host.CanonicalAction)
    (cfg : PrincipalsConfig) (st : PBState) :
    (principalBudgetKernel.decide act cfg none st).2 = st := rfl

/-! ## The isolation frame lemma -/

/-- One `pbStepE` step by principal `pid` never moves another principal's
    counter: the only write is at key `(pid, spec.name)`. -/
theorem pbStepE_other_principal (pid : String) (act : Host.CanonicalAction)
    (q name : String) (hq : q ≠ pid) (s : BudgetSpec) (st st1 : PBState)
    (h : pbStepE pid act (.ok st) s = .ok st1) :
    pbStateFor st1 (q, name) = pbStateFor st (q, name) := by
  simp only [pbStepE, bind, Except.bind] at h
  cases hcost : costFor s act.argsJson with
  | none => simp [hcost] at h
  | some cost =>
      simp only [hcost] at h
      cases hbs : BudgetCore.step s.cap (pbStateFor st (pid, s.name)) cost with
      | mk d b =>
          cases d
          · simp only [hbs, pure, Except.pure] at h
            injection h with h1
            subst h1
            exact pbStateFor_set_ne st (pid, s.name) (q, name) b
              (fun hEq => hq (congrArg Prod.fst hEq))
          · simp only [hbs] at h
            cases h

/-- The fold absorbs an error (kernel B's `budgetFold_error` twin). -/
theorem pbFold_error (pid : String) (act : Host.CanonicalAction)
    (specs : List BudgetSpec) (e : String) :
    specs.foldl (pbStepE pid act) (.error e) = .error e := by
  induction specs with
  | nil => rfl
  | cons s rest ih => exact ih

/-- The whole covering fold by principal `pid` never moves another
    principal's counter. -/
theorem pb_fold_other_principal (pid : String) (act : Host.CanonicalAction)
    (q name : String) (hq : q ≠ pid) :
    ∀ (specs : List BudgetSpec) (st st1 : PBState),
      specs.foldl (pbStepE pid act) (.ok st) = .ok st1 →
      pbStateFor st1 (q, name) = pbStateFor st (q, name) := by
  intro specs
  induction specs with
  | nil =>
      intro st st1 h
      injection h with h
      rw [h]
  | cons s rest ih =>
      intro st st1 hfold
      rw [List.foldl_cons] at hfold
      cases hhead : pbStepE pid act (.ok st) s with
      | error e => rw [hhead, pbFold_error] at hfold; cases hfold
      | ok stm =>
          rw [hhead] at hfold
          rw [ih stm st1 hfold,
              pbStepE_other_principal pid act q name hq s st stm hhead]

/-- **PRINCIPAL BUDGET ISOLATION** (the load-bearing V2.1 proof). A step by
    principal `p` leaves EVERY other principal's counter unchanged — for
    every action, every config, every state. Quantifying over all `act` is
    precisely "no request field reaches the debit key": the key's first
    component comes only from the `AuthenticatedPrincipal` evidence, which
    only `Host.verifyEnvelope` produces (private constructor). A spoofed
    request field cannot switch the debit target because no request field
    reaches the target. -/
theorem principal_budget_isolation (act : Host.CanonicalAction)
    (cfg : PrincipalsConfig) (p : Host.AuthenticatedPrincipal)
    (st : PBState) (q name : String) (hq : q ≠ p.id) :
    pbStateFor ((principalBudgetKernel.decide act cfg (some p) st).2) (q, name)
      = pbStateFor st (q, name) := by
  dsimp only [principalBudgetKernel]
  split
  · next st' hfold =>
      exact pb_fold_other_principal p.id act q name hq _ st st' hfold
  · rfl

/-! ## Axiom pins -/

/-- info: 'Kernels.pbStateFor_set_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms pbStateFor_set_eq

/-- info: 'Kernels.pbStateFor_set_ne' depends on axioms: [propext] -/
#guard_msgs in
#print axioms pbStateFor_set_ne

/-- info: 'Kernels.principal_budget_ingest_id' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms principal_budget_ingest_id

/-- info: 'Kernels.principal_budget_none_denies' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms principal_budget_none_denies

/-- info: 'Kernels.principal_budget_none_frozen' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms principal_budget_none_frozen

/-- info: 'Kernels.pbStepE_other_principal' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms pbStepE_other_principal

/-- info: 'Kernels.pb_fold_other_principal' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms pb_fold_other_principal

/-- info: 'Kernels.principal_budget_isolation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms principal_budget_isolation

end Kernels
