/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Kernel

namespace Host

/-- One kernel instance wired into the host: the kernel, its config section,
    its session state, and the host-side IO that gathers its evidence
    (clock, approval file, …) before each pure `decide`. -/
structure Registered where
  kernel : Kernel
  config : kernel.Config
  stateRef : IO.Ref kernel.State
  gather : CanonicalAction → IO kernel.Evidence

abbrev Registry := List Registered

/-- Fail-closed combination: allow iff at least one kernel gated the call AND
    every gating kernel allowed. An empty verdict list (no kernel governs the
    call) is a deny. G3 replaces this skeleton with the proven AND-combinator. -/
def combineVerdicts (verdicts : List Verdict) : VerdictKind :=
  match verdicts with
  | [] => .deny
  | vs => if vs.all (fun v => v.kind == .allow) then .allow else .deny

/-- The reason reported for a combined deny: the first denying kernel's reason,
    or the fail-closed default when nothing gated. -/
def denyReason (verdicts : List Verdict) : String :=
  match verdicts.find? (fun v => v.kind == .deny) with
  | some v => v.reason
  | none => "no kernel gated this call"

/-- Run every kernel whose `gates` matches, in registry order. Two-phase:

    1. For each gating kernel: gather evidence, commit `ingest` immediately
       (evidence must survive a deny), then run the pure `decide` and hold the
       returned execution-transition state.
    2. Combine fail-closed. Only on combined ALLOW are the held states
       committed — a denied call never executed, so no kernel's
       trace/automaton advances on it.

    Returns the combined verdict plus the per-kernel verdicts (audit certs). -/
def dispatch (registry : Registry) (act : CanonicalAction) :
    IO (VerdictKind × List Verdict) := do
  let mut verdicts : List Verdict := []
  let mut commits : List (IO Unit) := []
  for r in registry do
    if r.kernel.gates r.config act then
      let evidence ← r.gather act
      let st0 ← r.stateRef.get
      let st1 := r.kernel.ingest evidence st0
      r.stateRef.set st1
      let (verdict, st2) := r.kernel.decide act r.config evidence st1
      commits := commits ++ [r.stateRef.set st2]
      verdicts := verdicts ++ [verdict]
  let combined := combineVerdicts verdicts
  if combined == .allow then
    for commit in commits do
      commit
  pure (combined, verdicts)

end Host
