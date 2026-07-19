/- SPDX-License-Identifier: Apache-2.0 -/

import Host.CommitRegistry

/-!
# The dispatch IO shell, spelled — desugaring and held replay as theorems

`Host.dispatch` (Host/Registry.lean) is a `do`-block: two `mut` accumulators,
a `for` loop, a queued held-write list, an allow-only replay loop. Until this
module, the correspondence between that block and the pure plan
(`Host.dispatch_plan`) rested on trusting the `do`-elaboration — residuals 2
and 3 of the dispatch IO shell in `docs/POLICY-ASSURANCE-BOUNDARY.md`.

This module spells the loop as explicit structural recursion (`dispatchGo`,
`replay`) and PROVES the deployed `dispatch` equal to it — program equality
in `IO`, by list induction, using only core's `LawfulMonad (EStateM ε σ)`
laws and `List.forIn` equations. The opaque primitives (`ST.Prim.Ref.get`,
`ST.Prim.Ref.set`) appear as abstract leaves on BOTH sides: the theorem pins
the loop's structure — which reads and writes are issued, with which values,
in which order, and that the queued held writes are exactly the gating
instances' `set st2` replayed in registry order only on a combined allow —
without claiming anything about what the opaque leaves DO to the world.
That value-semantics half (get returns the ref's current value, sets land)
is irreducibly IO-TCB and stays named in the assurance docs: proving it
would require axiomatising `IO.Ref`, which this codebase forbids.

`dispatchGo_cons_pure_gather` then eliminates the `gather` binds for the
deployed registry's shape — every `Ffi.registryFor` gather is a pure
constant (pinned per instance by `commitInstsFor_wiring`), so "executing
`gather` yields its constant" is the monad law `pure_bind`, not a trust
item. `registryFor_gather_pure` states the constant-shape fact directly on
the deployed list, and `registryFor_reader_invariance` pins that the
registry's state slots depend on nothing but the session's four named refs.
-/

namespace Host

/-- Sequential replay of the queued held writes, spelled: run each queued
    `IO Unit` in order. This is the allow branch's `for commit in commits do
    commit`, as structural recursion. -/
def replay : List (IO Unit) → IO Unit
  | [] => pure ()
  | c :: cs => do c; replay cs

/-- `Host.dispatch`, spelled as structural recursion: the loop walks the
    registry accumulating `commits` (queued held writes) and `verdicts` in
    order; the epilogue combines fail-closed and replays the queued writes
    ONLY on a combined allow. `dispatch_spelled` proves the deployed
    `do`-block IS this function. -/
def dispatchGo (act : CanonicalAction) :
    Registry → List (IO Unit) → List Verdict → IO (VerdictKind × List Verdict)
  | [], commits, verdicts => do
      let combined := combineVerdicts verdicts
      if combined == VerdictKind.allow then
        replay commits
      pure (combined, verdicts)
  | r :: rest, commits, verdicts =>
      if r.kernel.gates r.config act = true then do
        let evidence ← r.gather act
        let st0 ← r.stateRef.get
        let p := phase1Held r.kernel r.config act evidence st0
        r.stateRef.set p.2.1
        dispatchGo act rest (commits ++ [r.stateRef.set p.2.2]) (verdicts ++ [p.1])
      else
        dispatchGo act rest commits verdicts

/-- The loop body of the deployed `dispatch`, exactly as the `do`-elaborator
    produces it (accumulator is `MProd commits verdicts`, yields at both
    branch leaves). Private: exists only to state `go_spelled` against the
    literal elaboration. -/
private def loopBody (act : CanonicalAction) (r : Registered)
    (acc : MProd (List (IO Unit)) (List Verdict)) :
    IO (ForInStep (MProd (List (IO Unit)) (List Verdict))) :=
  if r.kernel.gates r.config act = true then do
    let evidence ← r.gather act
    let st0 ← r.stateRef.get
    match phase1Held r.kernel r.config act evidence st0 with
    | (verdict, st1, st2) => do
        r.stateRef.set st1
        pure (ForInStep.yield ⟨acc.fst ++ [r.stateRef.set st2], acc.snd ++ [verdict]⟩)
  else
    pure (ForInStep.yield ⟨acc.fst, acc.snd⟩)

/-- The allow-branch replay loop, in the fold form `simp` normalizes the
    elaborated `forIn` to, equals `replay`. -/
private theorem replay_foldlM (u : PUnit) (commits : List (IO Unit)) :
    List.foldlM (fun (_ : PUnit) (c : IO Unit) => c) u commits = replay commits := by
  induction commits generalizing u with
  | nil => rfl
  | cons c cs ih => simp [List.foldlM_cons, replay, ih]

/-- The generalized loop: `forIn` from ANY accumulator pair, followed by the
    deployed epilogue, equals `dispatchGo`. Induction over the registry. -/
private theorem go_spelled (act : CanonicalAction) (registry : Registry)
    (commits : List (IO Unit)) (verdicts : List Verdict) :
    (do
      let s ← forIn registry
        (MProd.mk commits verdicts : MProd (List (IO Unit)) (List Verdict))
        (loopBody act)
      let combined := combineVerdicts s.snd
      if combined == VerdictKind.allow then
        forIn s.fst PUnit.unit fun commit _ => do
          commit
          pure (ForInStep.yield PUnit.unit)
      pure (combined, s.snd))
      = dispatchGo act registry commits verdicts := by
  induction registry generalizing commits verdicts with
  | nil =>
      simp only [List.forIn_nil, pure_bind, dispatchGo]
      by_cases hc : combineVerdicts verdicts == VerdictKind.allow
      · simp [hc, replay_foldlM]
      · simp [hc]
  | cons r rest ih =>
      simp only [List.forIn_cons, dispatchGo]
      by_cases hg : r.kernel.gates r.config act = true
      · simp only [loopBody, hg, if_true, bind_assoc]
        refine congrArg (r.gather act >>= ·) (funext fun evidence => ?_)
        refine congrArg (r.stateRef.get >>= ·) (funext fun st0 => ?_)
        rcases hp : phase1Held r.kernel r.config act evidence st0 with ⟨v, st1, st2⟩
        simp only [pure_bind]
        refine congrArg (r.stateRef.set st1 >>= ·) (funext fun _ => ?_)
        simpa using ih (commits ++ [r.stateRef.set st2]) (verdicts ++ [v])
      · simp only [loopBody, hg, pure_bind]
        simpa using ih commits verdicts

/-- **THE LOOP IS ITS SPELLING.** The deployed `Host.dispatch` `do`-block —
    `mut` accumulators, `for` loop, queued held writes, allow-only replay —
    equals the explicit recursion `dispatchGo` starting from empty
    accumulators. Discharges the `for`/`do`-desugaring residual and the
    STRUCTURAL half of the held-replay residual (content and order of the
    queued writes; replay exactly on allow). The opaque `IO.Ref` get/set
    leaves stay abstract on both sides — their value semantics remain the
    named IO-TCB. -/
theorem dispatch_spelled (registry : Registry) (act : CanonicalAction) :
    dispatch registry act = dispatchGo act registry [] [] :=
  (rfl : dispatch registry act
      = (do
          let s ← forIn registry
            (MProd.mk [] [] : MProd (List (IO Unit)) (List Verdict))
            (loopBody act)
          let combined := combineVerdicts s.snd
          if combined == VerdictKind.allow then
            forIn s.fst PUnit.unit fun commit _ => do
              commit
              pure (ForInStep.yield PUnit.unit)
          pure (combined, s.snd))).trans
    (go_spelled act registry [] [])

/-- One loop step at a pure-constant gather — the deployed registry's shape
    (`commitInstsFor_wiring` pins every `Ffi.registryFor` gather to
    `fun _ => pure ev`): executing the gather IS `pure_bind`, so the step
    reduces to get → `phase1Held` at the constant evidence → set → recurse.
    "Executing `gather` yields its pure constant" is a monad law here, not a
    trust item. -/
theorem dispatchGo_cons_pure_gather (act : CanonicalAction) (r : Registered)
    (ev : r.kernel.Evidence) (hg : r.gather = fun _ => pure ev)
    (rest : Registry) (commits : List (IO Unit)) (verdicts : List Verdict) :
    dispatchGo act (r :: rest) commits verdicts
      = if r.kernel.gates r.config act = true then do
          let st0 ← r.stateRef.get
          let p := phase1Held r.kernel r.config act ev st0
          r.stateRef.set p.2.1
          dispatchGo act rest (commits ++ [r.stateRef.set p.2.2]) (verdicts ++ [p.1])
        else
          dispatchGo act rest commits verdicts := by
  simp only [dispatchGo, hg, pure_bind]

/-- Every gather in the deployed registry is a pure constant — stated
    directly on `Ffi.registryFor`, so `dispatchGo_cons_pure_gather` applies
    at every position of the deployed dispatch. -/
theorem registryFor_gather_pure (s : Ffi.Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option AuthenticatedPrincipal) :
    ∀ r ∈ Ffi.registryFor s now approvalEvents votes grants forecasts principal?,
      ∃ ev : r.kernel.Evidence, r.gather = fun _ => pure ev := by
  intro r hr
  unfold Ffi.registryFor at hr
  simp only [List.mem_append] at hr
  rcases hr with ((((((h | h) | h) | h) | h) | h) | h) <;>
    (repeat split at h) <;>
    simp only [List.mem_cons, List.not_mem_nil, or_false] at h <;>
    (try rcases h with h | h) <;> subst_vars <;> exact ⟨_, rfl⟩

/-- The deployed registry's state slots depend on NOTHING but the session's
    five named refs: any two pure readers that agree on
    `safetyRef`/`temporalRef`/`linearRef`/`budgetRef`/`principalBudgetRef`
    project `registryFor`
    to the same `WiredInst` list (C/V/K sit on `unitRef` with `State = Unit`,
    where every reader returns `()`). No instance smuggles in an unnamed
    stateful ref. Two applications of `commitInstsFor_wiring`. -/
theorem registryFor_reader_invariance (s : Ffi.Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option AuthenticatedPrincipal)
    (read₁ read₂ : (K : Kernel) → IO.Ref K.State → K.State)
    (hs : read₂ Kernels.safetyKernel s.safetyRef
            = read₁ Kernels.safetyKernel s.safetyRef)
    (ht : read₂ Kernels.temporalKernel s.temporalRef
            = read₁ Kernels.temporalKernel s.temporalRef)
    (hl : read₂ Kernels.linearKernel s.linearRef
            = read₁ Kernels.linearKernel s.linearRef)
    (hb : read₂ Kernels.budgetKernel s.budgetRef
            = read₁ Kernels.budgetKernel s.budgetRef)
    (hpb : read₂ Kernels.principalBudgetKernel s.principalBudgetRef
            = read₁ Kernels.principalBudgetKernel s.principalBudgetRef) :
    (Ffi.registryFor s now approvalEvents votes grants forecasts principal?).map
        (Registered.wiredAt read₁)
      = (Ffi.registryFor s now approvalEvents votes grants forecasts principal?).map
        (Registered.wiredAt read₂) := by
  rw [commitInstsFor_wiring s now approvalEvents votes grants forecasts principal?
        _ _ _ _ _ read₁ rfl rfl rfl rfl rfl,
      commitInstsFor_wiring s now approvalEvents votes grants forecasts principal?
        _ _ _ _ _ read₂ hs ht hl hb hpb]

end Host

/-! ## Axiom pins — enforced at module build

The spelled dispatch shell sits on Lean's three classical axioms at most; no
`sorryAx`, no `Lean.ofReduceBool`, and — the point of this module — no NEW
axioms: the do-desugaring theorems use only core's lawful-monad instance for
`EStateM`. Drift fails the build here and again in `Test/Axioms.lean`. -/

/-- info: 'Host.replay' does not depend on any axioms -/
#guard_msgs in #print axioms Host.replay
/-- info: 'Host.dispatchGo' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatchGo
/-- info: 'Host.dispatch_spelled' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatch_spelled
/-- info: 'Host.dispatchGo_cons_pure_gather' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatchGo_cons_pure_gather
/-- info: 'Host.registryFor_gather_pure' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.registryFor_gather_pure
/-- info: 'Host.registryFor_reader_invariance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.registryFor_reader_invariance
