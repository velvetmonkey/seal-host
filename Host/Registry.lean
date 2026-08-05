/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Kernel

namespace Host

/-- One kernel instance wired into the host: the kernel, its config section,
    its session state, and the host-side IO that gathers its evidence
    (clock, approval file, …) before each pure `decide`. -/
structure Registered where
  /-- The verified kernel itself. -/
  kernel : Kernel
  /-- This kernel's section of the loaded `TrustedConfig`. -/
  config : kernel.Config
  /-- The kernel's live session state, mutated only by `dispatch`. -/
  stateRef : IO.Ref kernel.State
  /-- Host-side IO gathering this kernel's per-call evidence. -/
  gather : CanonicalAction → IO kernel.Evidence

/-- The full set of kernel instances mediating this session, in dispatch order. -/
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

/-- Phase 1 for one gating kernel, purely: the verdict, the post-ingest state
    (committed immediately — evidence must survive a deny), and the HELD
    execution-transition state (committed only on a combined allow). This is
    `dispatch`'s per-kernel state logic in one pure function; the
    commit-discipline theorems in `Host.Commit` (`phase1Held_verdict`,
    `phase1Held_ingest`, `phase1Held_held`) bind it to the proven model. -/
def phase1Held (K : Kernel) (cfg : K.Config) (act : CanonicalAction)
    (ev : K.Evidence) (st0 : K.State) : Verdict × K.State × K.State :=
  let st1 := K.ingest ev st0
  let (verdict, st2) := K.decide act cfg ev st1
  (verdict, st1, st2)

/-- Run every kernel whose `gates` matches, in registry order. Two-phase:

    1. For each gating kernel: gather evidence, run the pure `phase1Held`,
       commit its `ingest` state immediately (evidence must survive a deny),
       and hold its `decide` execution-transition state.
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
      let (verdict, st1, st2) := phase1Held r.kernel r.config act evidence st0
      r.stateRef.set st1
      commits := commits ++ [r.stateRef.set st2]
      verdicts := verdicts ++ [verdict]
  let combined := combineVerdicts verdicts
  if combined == .allow then
    for commit in commits do
      commit
  pure (combined, verdicts)

/-- One registered kernel instance at decision time, purely: its config, the
    evidence gathered for this call, and the session state it decides against —
    no `IO.Ref`. This mirrors exactly the inputs phase 1 of `dispatch` feeds
    each gating kernel's pure `decide`. The IO realization (evidence gathering,
    ref state, commit discipline) remains TCB; the composition theorems in
    `Host.Composition` quantify over this pure model. -/
structure PureInst where
  /-- The verified kernel itself. -/
  kernel : Kernel
  /-- This kernel's config section. -/
  config : kernel.Config
  /-- The evidence gathered for the one call under consideration. -/
  evidence : kernel.Evidence
  /-- The session state the kernel decides against. -/
  state : kernel.State

/-- The verdict list phase 1 of `dispatch` produces for these instances, as a
    pure fold: every gating instance contributes its `decide` verdict, in
    registry order; non-gating instances contribute nothing. -/
def pureVerdicts (insts : List PureInst) (act : CanonicalAction) : List Verdict :=
  insts.filterMap fun i =>
    if i.kernel.gates i.config act
    then some (i.kernel.decide act i.config i.evidence i.state).1
    else none

/-- Membership: a registered, gating instance's verdict is among the combined
    verdicts — the hook the composition theorems' membership hypotheses attach
    to, for ANY registry subset in ANY order. -/
theorem pureVerdicts_mem (insts : List PureInst) (act : CanonicalAction)
    (i : PureInst) (hi : i ∈ insts) (hg : i.kernel.gates i.config act = true) :
    (i.kernel.decide act i.config i.evidence i.state).1 ∈ pureVerdicts insts act := by
  simp only [pureVerdicts, List.mem_filterMap]
  exact ⟨i, hi, by simp [hg]⟩

end Host
