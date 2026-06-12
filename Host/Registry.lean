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

/-- Run every kernel whose `gates` matches, in registry order, threading each
    kernel's state through its `IO.Ref`. Returns the combined verdict plus the
    per-kernel verdicts (audit certs). -/
def dispatch (registry : Registry) (act : CanonicalAction) :
    IO (VerdictKind × List Verdict) := do
  let mut verdicts : List Verdict := []
  for r in registry do
    if r.kernel.gates r.config act then
      let evidence ← r.gather act
      let st ← r.stateRef.get
      let (verdict, st') := r.kernel.decide act r.config evidence st
      r.stateRef.set st'
      verdicts := verdicts ++ [verdict]
  pure (combineVerdicts verdicts, verdicts)

end Host
