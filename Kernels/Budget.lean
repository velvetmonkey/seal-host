/- SPDX-License-Identifier: Apache-2.0 -/

import Seal.Hash
import Seal.JsonUtil
import Host.Kernel
import Kernels.BudgetCore

namespace Kernels

/-- One budget: a named monotone counter with a hard cap, covering a set of
    tools. `costArg` names the argument carrying the per-call cost; absent
    means every call costs 1 (a call-rate budget). -/
structure BudgetSpec where
  name : String
  cap : Nat
  tools : List String
  costArg : Option (List String)
  deriving Repr

abbrev BudgetConfig := List BudgetSpec

/-- Config lint: budgets sharing a name share ONE counter (`budgetStateFor` /
    `setBudgetState` key by name), so a same-name spec with a larger cap can
    push the shared counter past a smaller same-name cap — the smaller cap
    would look configured but be unenforceable. Same-name SAME-cap stays legal
    (one counter deliberately shared across tool groups); only conflicting
    caps are inconsistent. -/
def budgetCapsConsistent (cfg : BudgetConfig) : Bool :=
  cfg.all fun s => cfg.all fun s' => s'.name != s.name || s'.cap == s.cap

/-- Per-budget counters, keyed by budget name. Missing entry = nothing spent. -/
abbrev BudgetState := List (String × BudgetCore.BState)

def budgetStateFor (st : BudgetState) (name : String) : BudgetCore.BState :=
  (st.find? (fun e => e.1 == name)).map (·.2) |>.getD BudgetCore.BState.empty

def setBudgetState (st : BudgetState) (name : String)
    (b : BudgetCore.BState) : BudgetState :=
  (name, b) :: st.filter (fun e => e.1 != name)

/-- The cost this call charges against a budget: `costArg` if configured
    (missing/non-Nat field fails closed via none), else 1. -/
def costFor (spec : BudgetSpec) (args : Lean.Json) : Option Nat :=
  match spec.costArg with
  | none => some 1
  | some path =>
      match Seal.JsonUtil.atPath args path with
      | some j => j.getNat?.toOption
      | none => none

/-- Kernel B — the Budget/rate kernel. Every covering budget must admit the
    call's cost through `BudgetCore.step`; one over-budget counter vetoes.
    The invariants are proven in BudgetCore: counters are monotone
    (`step_monotone`) and can never exceed their caps under any trace
    (`run_never_over_budget`); an over-cap cost is denied
    (`over_budget_denied`). State advances only when the call executes. -/
def budgetKernel : Host.Kernel where
  name := "budget"
  Config := BudgetConfig
  Evidence := Unit
  State := BudgetState
  init := []
  gates := fun cfg act => cfg.any (fun b => b.tools.contains act.tool)
  ingest := fun _ st => st
  decide := fun act cfg _ st =>
    let mk := fun (kind : Host.VerdictKind) (reason : String) (st' : BudgetState) =>
      ({ kernel := "budget", kind, reason,
         certHash := Seal.auditHashParts ["budget", kind.text, reason] }, st')
    let covering := cfg.filter (fun b => b.tools.contains act.tool)
    let outcome := covering.foldl
      (fun (acc : Except String BudgetState) spec => do
        let st' ← acc
        match costFor spec act.argsJson with
        | none => throw s!"missing cost field for budget {spec.name}: {act.tool}"
        | some cost =>
            match BudgetCore.step spec.cap (budgetStateFor st' spec.name) cost with
            | (.allow, b') => pure (setBudgetState st' spec.name b')
            | (.block, b) =>
                throw s!"over budget {spec.name} ({b.spent}+{cost}>{spec.cap}): {act.tool}")
      (.ok st)
    match outcome with
    | .ok st' => mk .allow s!"within budget: {act.tool}" st'
    | .error reason => mk .deny reason st

end Kernels
