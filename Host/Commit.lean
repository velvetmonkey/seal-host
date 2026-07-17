/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Composition

/-!
# The commit discipline — deny-side and allow-side state commits, proven

`Host.dispatch` (Host/Registry.lean) runs a two-phase commit per call:

1. For each gating kernel: gather evidence, commit `ingest` immediately
   (evidence must survive a deny), run the pure `decide` against the
   post-ingest state and HOLD the returned execution-transition state.
2. Combine fail-closed. Only on combined ALLOW are the held states committed.

Until now that discipline was asserted only in `dispatch`'s docstring: the pure
model (`PureInst`/`pureVerdicts`) carried verdicts and no state, and every
composed theorem lived on the allow branch. This module extends the pure model
with state (`CommitInst`, `pureCommit`) mirroring the two phases exactly, and
proves:

* **deny side** (`pureCommit_deny_no_decide_commit`): on a combined deny the
  committed state is EXACTLY the post-ingest state — the `decide`
  execution-transition is not applied. HONEST SCOPE: ingest state DOES advance
  on a deny by design; the claim is only that the execution transition is
  withheld. "Deny ⇒ no state moves at all" is FALSE against the source and is
  not stated.
* **allow side** (`pureCommit_allow_commits_decide`,
  `pureCommit_allow_closed_algebra`): on a combined allow the committed state
  is the `decide` transition state, and every present kernel's invariant holds
  of the committed state — discharged through the existing
  `registry_closed_algebra`, not reproven.
* **product corollaries over call sequences containing denies**
  (`budget_committed_trace_within_cap`,
  `linear_committed_trace_no_double_spend`): a denied call consumes no budget
  (kernel B's committed state is byte-identical — its ingest is the identity)
  and burns no capability (kernel L's spend is the execution transition);
  `BudgetCore.run_never_over_budget` and `LinearCore.no_double_spend` hold of
  the committed state trace.

The IO realization of `dispatch` (evidence gathering, `IO.Ref` reads/writes,
the loop) remains TCB; these theorems quantify over the pure mirror of its
state logic.
-/

namespace Host

/-! ## The pure two-phase model with state (target 1) -/

/-- One registered instance at CALL time, purely: its config, the evidence
    gathered for this call, and the SESSION state — the pre-call state `st0`
    on input, the committed state on output (the next call's `st0`).

    Deliberately distinct from `PureInst`, whose `state` is the DECIDE-INPUT
    (the post-ingest `st1`): the two meanings never share a field. After
    `ingestPhase`, `CommitInst.asPure` lands exactly on `PureInst`'s meaning. -/
structure CommitInst where
  kernel : Kernel
  config : kernel.Config
  evidence : kernel.Evidence
  state : kernel.State

/-- Forgetful view at decide time. AFTER `ingestPhase`, `state` is the
    decide-input, i.e. exactly `PureInst.state`'s existing meaning — this is
    the bridge that lets the existing composition theorems (`pureVerdicts_mem`,
    `registry_closed_algebra`) attach unchanged. -/
def CommitInst.asPure (i : CommitInst) : PureInst :=
  ⟨i.kernel, i.config, i.evidence, i.state⟩

/-- Phase 1's state write: a gating instance's evidence is folded in by
    `ingest`, committed UNCONDITIONALLY (mirrors `r.stateRef.set st1` in
    `dispatch` — approvals read from the control file must survive a deny).
    A non-gating instance is untouched (no gather, no ingest). -/
def CommitInst.ingestPhase (i : CommitInst) (act : CanonicalAction) : CommitInst :=
  { i with state := if i.kernel.gates i.config act
                    then i.kernel.ingest i.evidence i.state else i.state }

/-- Phase 2's replay: a gating instance's `decide` execution transition
    (mirrors the held `r.stateRef.set st2` — `decide` is pure, so recomputing
    it here equals holding its result). Applied by `pureCommit` only on a
    combined allow. -/
def CommitInst.decidePhase (i : CommitInst) (act : CanonicalAction) : CommitInst :=
  { i with state := if i.kernel.gates i.config act
                    then (i.kernel.decide act i.config i.evidence i.state).2
                    else i.state }

@[simp] theorem CommitInst.ingestPhase_kernel (i : CommitInst) (act : CanonicalAction) :
    (i.ingestPhase act).kernel = i.kernel := rfl

@[simp] theorem CommitInst.decidePhase_kernel (i : CommitInst) (act : CanonicalAction) :
    (i.decidePhase act).kernel = i.kernel := rfl

@[simp] theorem CommitInst.asPure_kernel (i : CommitInst) :
    i.asPure.kernel = i.kernel := rfl

theorem CommitInst.ingestPhase_state_of_gates (i : CommitInst) (act : CanonicalAction)
    (hg : i.kernel.gates i.config act = true) :
    (i.ingestPhase act).state = i.kernel.ingest i.evidence i.state := by
  simp [ingestPhase, hg]

theorem CommitInst.ingestPhase_state_of_not_gates (i : CommitInst) (act : CanonicalAction)
    (hg : i.kernel.gates i.config act = false) :
    (i.ingestPhase act).state = i.state := by
  simp [ingestPhase, hg]

theorem CommitInst.decidePhase_state_of_gates (i : CommitInst) (act : CanonicalAction)
    (hg : i.kernel.gates i.config act = true) :
    (i.decidePhase act).state = (i.kernel.decide act i.config i.evidence i.state).2 := by
  simp [decidePhase, hg]

theorem CommitInst.decidePhase_state_of_not_gates (i : CommitInst) (act : CanonicalAction)
    (hg : i.kernel.gates i.config act = false) :
    (i.decidePhase act).state = i.state := by
  simp [decidePhase, hg]

/-- Phase 1 over the whole registry: every gating instance's ingest committed,
    non-gating instances untouched. This is the state that survives a deny. -/
def ingestAll (insts : List CommitInst) (act : CanonicalAction) : List CommitInst :=
  insts.map (·.ingestPhase act)

/-- The combined verdict of the call — phase 1's verdicts (each gating
    instance's `decide` at its post-ingest state, in registry order, exactly
    as `dispatch` computes them), combined fail-closed. -/
def commitVerdict (insts : List CommitInst) (act : CanonicalAction) : VerdictKind :=
  combineVerdicts (pureVerdicts ((ingestAll insts act).map (·.asPure)) act)

/-- **The two-phase commit, purely** (target 1). Mirrors `dispatch` exactly:
    phase 1 = unconditional ingest write + `decide` against the post-ingest
    state; phase 2 = replay of the held `decide` transitions ONLY on a
    combined allow. Output states are the committed session states. -/
def pureCommit (insts : List CommitInst) (act : CanonicalAction) :
    VerdictKind × List CommitInst :=
  (commitVerdict insts act,
   if commitVerdict insts act = .allow
   then (ingestAll insts act).map (·.decidePhase act)
   else ingestAll insts act)

/-- The combined verdict of `pureCommit` is `combineVerdicts` over the
    EXISTING `pureVerdicts`, at its existing meaning (decide-input states) —
    the hypothesis shape of every composed theorem attaches directly. -/
theorem pureCommit_verdict (insts : List CommitInst) (act : CanonicalAction) :
    (pureCommit insts act).1
      = combineVerdicts (pureVerdicts ((ingestAll insts act).map (·.asPure)) act) := rfl

@[simp] theorem pureCommit_snd_length (insts : List CommitInst) (act : CanonicalAction) :
    (pureCommit insts act).2.length = insts.length := by
  simp only [pureCommit]
  split <;> simp [ingestAll]

/-! ## The deny side (target 2) -/

/-- **THE DENY-SIDE COMMIT DISCIPLINE.** On a combined deny, the committed
    state of EVERY instance is exactly its phase-1 (post-ingest) state: the
    `decide` execution-transition is NOT applied to any kernel — a denied call
    never executed, so no kernel's trace/automaton advances on it.

    HONEST SCOPE: ingest state DOES advance on a deny, by design — evidence
    (approvals read from the control file, grants, clock) must survive a deny.
    The theorem claims ONLY that the `decide` execution transition is withheld;
    per instance, the committed state is `ingest evidence st0` when gating
    (`CommitInst.ingestPhase_state_of_gates`) and the untouched `st0` when not
    gating (`CommitInst.ingestPhase_state_of_not_gates`). -/
theorem pureCommit_deny_no_decide_commit (insts : List CommitInst) (act : CanonicalAction)
    (hdeny : (pureCommit insts act).1 = .deny) :
    (pureCommit insts act).2 = ingestAll insts act := by
  have hv : commitVerdict insts act = .deny := hdeny
  simp [pureCommit, hv]

/-- Deny side, per instance: the k-th committed instance is the k-th input
    instance with ONLY its ingest applied. Combined with
    `CommitInst.ingestPhase_state_of_gates` this is literally "the committed
    state equals `i.kernel.ingest i.evidence st0`" for gating instances, and
    "the committed state equals `st0`" for non-gating ones. -/
theorem pureCommit_deny_committed (insts : List CommitInst) (act : CanonicalAction)
    (hdeny : (pureCommit insts act).1 = .deny)
    (k : Nat) (hk : k < insts.length) :
    (pureCommit insts act).2[k]'(by simpa using hk) = insts[k].ingestPhase act := by
  simp [pureCommit_deny_no_decide_commit insts act hdeny, ingestAll]

/-! ## The allow side (target 3) -/

/-- On a combined allow, the committed state of every instance is its held
    `decide` execution-transition state — phase 2's replay, purely. -/
theorem pureCommit_allow_commits_decide (insts : List CommitInst) (act : CanonicalAction)
    (hallow : (pureCommit insts act).1 = .allow) :
    (pureCommit insts act).2 = (ingestAll insts act).map (·.decidePhase act) := by
  have hv : commitVerdict insts act = .allow := hallow
  simp [pureCommit, hv]

/-- Allow side, per instance: the k-th committed instance is the k-th input
    instance with ingest AND the `decide` execution transition applied. -/
theorem pureCommit_allow_committed (insts : List CommitInst) (act : CanonicalAction)
    (hallow : (pureCommit insts act).1 = .allow)
    (k : Nat) (hk : k < insts.length) :
    (pureCommit insts act).2[k]'(by simpa using hk)
      = (insts[k].ingestPhase act).decidePhase act := by
  simp [pureCommit_allow_commits_decide insts act hallow, ingestAll]

/-- A gating instance's `decide` verdict (at its post-ingest state) is among
    the verdicts `pureCommit` combines — the membership hook for the closed
    algebra, at the stateful model. -/
theorem pureCommit_mem (insts : List CommitInst) (act : CanonicalAction)
    (k : Nat) (hk : k < insts.length)
    (hg : insts[k].kernel.gates insts[k].config act = true) :
    ((insts[k].ingestPhase act).asPure.kernel.decide act
        (insts[k].ingestPhase act).asPure.config
        (insts[k].ingestPhase act).asPure.evidence
        (insts[k].ingestPhase act).asPure.state).1
      ∈ pureVerdicts ((ingestAll insts act).map (·.asPure)) act := by
  refine pureVerdicts_mem _ act (insts[k].ingestPhase act).asPure ?_ hg
  exact List.mem_map_of_mem (List.mem_map_of_mem (List.getElem_mem hk))

/-- **THE ALLOW-SIDE CLOSED ALGEBRA AT THE COMMITTED STATE** (target 3). On a
    combined allow from `pureCommit`, every kernel present in the verdict set
    carries its proven invariant — S non-bypass, C no-conflicting-agreement,
    V convergence, T temporal safety, L backed single-use spend, B within-cap
    budgets, K calibration — discharged through the EXISTING
    `registry_closed_algebra`, not reproven. For the stateful kernels L and B
    the conjuncts speak of `(decide …).2`, which IS the committed state on
    allow (`pureCommit_allow_committed` + `CommitInst.decidePhase_state_of_gates`);
    `pureCommit_allow_linear_committed` / `pureCommit_allow_budget_committed`
    below instantiate exactly that. -/
theorem pureCommit_allow_closed_algebra (insts : List CommitInst) (act : CanonicalAction)
    (hallow : (pureCommit insts act).1 = .allow) :
    -- S: non-bypass
    (∀ (act' : CanonicalAction) (pol : Seal.Policy) (ev : Kernels.SafetyEvidence)
        (st1 : SealCore.State) (target : SealCore.TargetHash),
      (Kernels.safetyKernel.decide act' pol ev st1).1
          ∈ pureVerdicts ((ingestAll insts act).map (·.asPure)) act →
      (Seal.classifyToolCall pol act'.tool act'.argsJson).toEvent =
        SealCore.Event.guarded target →
      SealCore.live st1 target ev.now = true) ∧
    -- C: no conflicting agreement
    (∀ (act' act'' : CanonicalAction) (cfg : Kernels.ConsensusConfig)
        (votes : Consensus.Checker.Votes) (vs' : List Verdict),
      (Kernels.consensusKernel.decide act' cfg votes ()).1
          ∈ pureVerdicts ((ingestAll insts act).map (·.asPure)) act →
      (Kernels.consensusKernel.decide act'' cfg votes ()).1 ∈ vs' →
      combineVerdicts vs' = .allow →
      (Kernels.certFor votes act'.tool).value = (Kernels.certFor votes act''.tool).value) ∧
    -- V: convergent-op admission
    (∀ (act' : CanonicalAction) (cfg : Kernels.ConvergenceConfig),
      (Kernels.convergenceKernel.decide act' cfg () ()).1
          ∈ pureVerdicts ((ingestAll insts act).map (·.asPure)) act →
      Kernels.convergentAccepts cfg act' = true) ∧
    -- T: temporal safety
    (∀ (act' : CanonicalAction) (policies : List Kernels.TemporalPolicy)
        (st : Kernels.TemporalState),
      (Kernels.temporalKernel.decide act' policies () st).1
          ∈ pureVerdicts ((ingestAll insts act).map (·.asPure)) act →
      Kernels.temporalAccepts policies st act' = true) ∧
    -- L: backed, single-use spend
    (∀ (act' : CanonicalAction) (cfg : Kernels.LinearConfig)
        (ev : List LinearCore.LEvent) (st : LinearCore.LState),
      (Kernels.linearKernel.decide act' cfg ev st).1
          ∈ pureVerdicts ((ingestAll insts act).map (·.asPure)) act →
      ∃ cap, linearCapOf cfg act' = some cap ∧
        0 < LinearCore.holds st cap ∧
        LinearCore.holds (Kernels.linearKernel.decide act' cfg ev st).2 cap
          = LinearCore.holds st cap - 1) ∧
    -- B: within-cap budget admission
    (∀ (act' : CanonicalAction) (cfg : Kernels.BudgetConfig) (st : Kernels.BudgetState),
      (Kernels.budgetKernel.decide act' cfg () st).1
          ∈ pureVerdicts ((ingestAll insts act).map (·.asPure)) act →
      ∀ spec ∈ cfg.filter (fun b => b.tools.contains act'.tool),
        ∃ (pre : BudgetCore.BState) (cost : Nat),
          Kernels.costFor spec act'.argsJson = some cost ∧
          pre.spent + cost ≤ spec.cap ∧
          ((BudgetCore.step spec.cap pre cost).2).spent ≤ spec.cap ∧
          cost ≤ spec.cap) ∧
    -- K: executable calibration bound (trusted Float mirror)
    (∀ (act' : CanonicalAction) (cfg : Kernels.CalibrationConfig)
        (records : List Kernels.ForecastRecord),
      (Kernels.calibrationKernel.decide act' cfg records ()).1
          ∈ pureVerdicts ((ingestAll insts act).map (·.asPure)) act →
      Kernels.calibratedB cfg records = true) :=
  registry_closed_algebra _ hallow

/-- Allow side at kernel L's COMMITTED state: if a gating linear instance sits
    at position k and the composed gate allows, the committed instance carries
    a state in which the resolved capability was consumed EXACTLY once from
    its post-ingest holding — the spend the call committed was backed. -/
theorem pureCommit_allow_linear_committed
    (insts : List CommitInst) (act : CanonicalAction)
    (cfg : Kernels.LinearConfig) (ev : List LinearCore.LEvent) (st0 : LinearCore.LState)
    (k : Nat) (hk : k < insts.length)
    (hinst : insts[k] = ⟨Kernels.linearKernel, cfg, ev, st0⟩)
    (hg : Kernels.linearKernel.gates cfg act = true)
    (hallow : (pureCommit insts act).1 = .allow) :
    ∃ (cap : LinearCore.CapId) (stC : LinearCore.LState),
      (pureCommit insts act).2[k]'(by simpa using hk)
          = ⟨Kernels.linearKernel, cfg, ev, stC⟩ ∧
      linearCapOf cfg act = some cap ∧
      0 < LinearCore.holds (Kernels.linearKernel.ingest ev st0) cap ∧
      LinearCore.holds stC cap
        = LinearCore.holds (Kernels.linearKernel.ingest ev st0) cap - 1 := by
  have hmem := pureCommit_mem insts act k hk (by rw [hinst]; exact hg)
  rw [hinst] at hmem
  simp only [CommitInst.ingestPhase, CommitInst.asPure, hg, if_true] at hmem
  obtain ⟨cap, hcap, hpos, hcons⟩ :=
    (pureCommit_allow_closed_algebra insts act hallow).2.2.2.2.1 act cfg ev
      (Kernels.linearKernel.ingest ev st0) hmem
  refine ⟨cap, _, ?_, hcap, hpos, hcons⟩
  rw [pureCommit_allow_committed insts act hallow k hk, hinst]
  simp [CommitInst.ingestPhase, CommitInst.decidePhase, hg]

/-- Allow side at kernel B's COMMITTED state: if a gating budget instance sits
    at position k and the composed gate allows, the committed instance carries
    the fold's output state, and every covering budget admitted this call's
    cost through the proven gate within its cap. -/
theorem pureCommit_allow_budget_committed
    (insts : List CommitInst) (act : CanonicalAction)
    (cfg : Kernels.BudgetConfig) (st0 : Kernels.BudgetState)
    (k : Nat) (hk : k < insts.length)
    (hinst : insts[k] = ⟨Kernels.budgetKernel, cfg, (), st0⟩)
    (hg : Kernels.budgetKernel.gates cfg act = true)
    (hallow : (pureCommit insts act).1 = .allow) :
    ∃ (stC : Kernels.BudgetState),
      (pureCommit insts act).2[k]'(by simpa using hk)
          = ⟨Kernels.budgetKernel, cfg, (), stC⟩ ∧
      ∀ spec ∈ cfg.filter (fun b => b.tools.contains act.tool),
        ∃ (pre : BudgetCore.BState) (cost : Nat),
          Kernels.costFor spec act.argsJson = some cost ∧
          pre.spent + cost ≤ spec.cap ∧
          ((BudgetCore.step spec.cap pre cost).2).spent ≤ spec.cap ∧
          cost ≤ spec.cap := by
  have hmem := pureCommit_mem insts act k hk (by rw [hinst]; exact hg)
  rw [hinst] at hmem
  simp only [CommitInst.ingestPhase, CommitInst.asPure, hg, if_true] at hmem
  have hspecs :=
    (pureCommit_allow_closed_algebra insts act hallow).2.2.2.2.2.1 act cfg st0 hmem
  refine ⟨(Kernels.budgetKernel.decide act cfg ()
      (Kernels.budgetKernel.ingest () st0)).2, ?_, hspecs⟩
  rw [pureCommit_allow_committed insts act hallow k hk, hinst]
  simp [CommitInst.ingestPhase, CommitInst.decidePhase, hg]

/-! ## The committed trace (target 4)

A single kernel instance followed across a SEQUENCE of mediated calls, the
other registered kernels abstracted as their per-call verdict lists. The focal
kernel's own verdict is computed genuinely at its running post-ingest state,
so a self-deny forces the combined deny by construction — this is the same
fail-closed veto as `combine_deny_of_member`. -/

/-- On a non-empty verdict list `combineVerdicts` is the all-allow check. -/
theorem combineVerdicts_ne_nil (vs : List Verdict) (h : vs ≠ []) :
    combineVerdicts vs
      = if vs.all (fun v => v.kind == .allow) then .allow else .deny := by
  cases vs with
  | nil => exact absurd rfl h
  | cons v t => rfl

/-- `combineVerdicts` is position-insensitive: moving one verdict to the end
    changes nothing. Justifies the WLOG head-focal form of the faithfulness
    bridge below. -/
theorem combineVerdicts_middle (l₁ l₂ : List Verdict) (v : Verdict) :
    combineVerdicts (l₁ ++ v :: l₂) = combineVerdicts (l₁ ++ l₂ ++ [v]) := by
  rw [combineVerdicts_ne_nil _ (by simp), combineVerdicts_ne_nil _ (by simp)]
  have hall : ((l₁ ++ v :: l₂).all fun w => w.kind == .allow)
      = ((l₁ ++ l₂ ++ [v]).all fun w => w.kind == .allow) := by
    simp only [List.all_append, List.all_cons, List.all_nil, Bool.and_true]
    rw [Bool.and_comm (v.kind == .allow), Bool.and_assoc]
  rw [hall]

theorem combineVerdicts_rotate (v : Verdict) (l : List Verdict) :
    combineVerdicts (v :: l) = combineVerdicts (l ++ [v]) := by
  simpa using combineVerdicts_middle [] l v

/-- One mediated call, as seen by a single focal kernel instance: the action,
    the evidence gathered for the focal kernel THIS call, and the other
    registered kernels' verdicts for this call (abstract — any registry, any
    order; `combineVerdicts` is position-insensitive). -/
structure PureCall (K : Kernel) where
  act : CanonicalAction
  evidence : K.Evidence
  others : List Verdict

/-- The focal instance's committed state for one call — `pureCommit`'s
    per-instance action (see `pureCommit_head_commitStep`): ingest committed
    unconditionally when gating; the `decide` execution transition committed
    ONLY when the combined verdict (the others' plus the focal kernel's own,
    computed at the running post-ingest state) is allow. -/
def commitStep (K : Kernel) (cfg : K.Config) (c : PureCall K) (st : K.State) :
    K.State :=
  if K.gates cfg c.act then
    if combineVerdicts (c.others
        ++ [(K.decide c.act cfg c.evidence (K.ingest c.evidence st)).1]) = .allow
    then (K.decide c.act cfg c.evidence (K.ingest c.evidence st)).2
    else K.ingest c.evidence st
  else st

/-- The committed state trace: `commitStep` folded over a call sequence. -/
def commitRun (K : Kernel) (cfg : K.Config) :
    List (PureCall K) → K.State → K.State
  | [], st => st
  | c :: calls, st => commitRun K cfg calls (commitStep K cfg c st)

/-- Single-call deny discipline, focal form: a denied call commits ONLY the
    ingest — the `decide` transition is withheld. -/
theorem commitStep_deny (K : Kernel) (cfg : K.Config) (c : PureCall K)
    (st : K.State)
    (hdeny : combineVerdicts (c.others
        ++ [(K.decide c.act cfg c.evidence (K.ingest c.evidence st)).1]) ≠ .allow) :
    commitStep K cfg c st
      = if K.gates cfg c.act then K.ingest c.evidence st else st := by
  unfold commitStep
  by_cases hgate : K.gates cfg c.act
  · simp only [if_pos hgate, if_neg hdeny]
  · simp only [if_neg hgate]

@[simp] theorem ingestAll_cons (i : CommitInst) (rest : List CommitInst)
    (act : CanonicalAction) :
    ingestAll (i :: rest) act = i.ingestPhase act :: ingestAll rest act := rfl

/-- **Faithfulness bridge**: for the head instance, the state `pureCommit`
    commits IS `commitStep`'s committed state, with the other instances'
    verdicts as the abstract `others`. Head position is WLOG —
    `combineVerdicts` is position-insensitive (`combineVerdicts_middle`). -/
theorem pureCommit_head_commitStep (K : Kernel) (cfg : K.Config) (ev : K.Evidence)
    (st : K.State) (rest : List CommitInst) (act : CanonicalAction) :
    ((pureCommit (⟨K, cfg, ev, st⟩ :: rest) act).2).head?
      = some ⟨K, cfg, ev, commitStep K cfg
          ⟨act, ev, pureVerdicts ((ingestAll rest act).map (·.asPure)) act⟩ st⟩ := by
  by_cases hg : K.gates cfg act
  · have hpv : pureVerdicts (((ingestAll (⟨K, cfg, ev, st⟩ :: rest) act)).map (·.asPure)) act
        = (K.decide act cfg ev (K.ingest ev st)).1
            :: pureVerdicts ((ingestAll rest act).map (·.asPure)) act := by
      rw [ingestAll_cons, List.map_cons]
      simp [pureVerdicts, CommitInst.ingestPhase, CommitInst.asPure, hg]
    have hcv : commitVerdict (⟨K, cfg, ev, st⟩ :: rest) act
        = combineVerdicts (pureVerdicts ((ingestAll rest act).map (·.asPure)) act
            ++ [(K.decide act cfg ev (K.ingest ev st)).1]) := by
      rw [commitVerdict, hpv, combineVerdicts_rotate]
    by_cases hcomb : combineVerdicts (pureVerdicts ((ingestAll rest act).map (·.asPure)) act
        ++ [(K.decide act cfg ev (K.ingest ev st)).1]) = .allow
    · simp only [pureCommit]
      rw [hcv, if_pos hcomb, ingestAll_cons, List.map_cons, List.head?_cons]
      simp [commitStep, hg, hcomb, CommitInst.ingestPhase, CommitInst.decidePhase]
    · simp only [pureCommit]
      rw [hcv, if_neg hcomb, ingestAll_cons, List.head?_cons]
      simp [commitStep, hg, hcomb, CommitInst.ingestPhase]
  · simp only [pureCommit]
    by_cases hcomb : commitVerdict (⟨K, cfg, ev, st⟩ :: rest) act = .allow
    · rw [if_pos hcomb, ingestAll_cons, List.map_cons, List.head?_cons]
      simp [commitStep, hg, CommitInst.ingestPhase, CommitInst.decidePhase]
    · rw [if_neg hcomb, ingestAll_cons, List.head?_cons]
      simp [commitStep, hg, CommitInst.ingestPhase]

/-! ## Kernel B over the committed trace (target 4, budget half) -/

@[simp] theorem budget_ingest_id (ev : Unit) (st : Kernels.BudgetState) :
    Kernels.budgetKernel.ingest ev st = st := rfl

/-- **A denied call consumes NO budget.** Kernel B's committed state after a
    combined deny is byte-identical to its pre-call state: its ingest is the
    identity, and the `decide` transition is withheld. -/
theorem budget_commitStep_deny (cfg : Kernels.BudgetConfig)
    (c : PureCall Kernels.budgetKernel) (st : Kernels.BudgetState)
    (hdeny : combineVerdicts (c.others
        ++ [(Kernels.budgetKernel.decide c.act cfg c.evidence st).1]) ≠ .allow) :
    commitStep Kernels.budgetKernel cfg c st = st := by
  rw [commitStep_deny _ _ _ _ hdeny]
  split <;> rfl

/-- `find?` commutes with a `filter` that keeps everything the predicate could
    find. -/
theorem find?_filter_of_imp {α : Type _} (l : List α) (p q : α → Bool)
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

/-- Writing one budget's counter reads back as written. -/
theorem budgetStateFor_set_eq (st : Kernels.BudgetState) (name : String)
    (b : BudgetCore.BState) :
    Kernels.budgetStateFor (Kernels.setBudgetState st name b) name = b := by
  simp [Kernels.budgetStateFor, Kernels.setBudgetState]

/-- Writing one budget's counter leaves every other budget's counter alone. -/
theorem budgetStateFor_set_ne (st : Kernels.BudgetState) (name other : String)
    (b : BudgetCore.BState) (hne : other ≠ name) :
    Kernels.budgetStateFor (Kernels.setBudgetState st name b) other
      = Kernels.budgetStateFor st other := by
  simp only [Kernels.budgetStateFor, Kernels.setBudgetState]
  rw [List.find?_cons_of_neg (by simp [Ne.symm hne]),
      find?_filter_of_imp]
  intro e he
  have : e.1 = other := by simpa using he
  simp [this, hne]

/-- An allowed `BudgetCore.step` lands exactly at `spent + cost`. -/
theorem budget_step_allow_spent (cap : Nat) (pre : BudgetCore.BState) (cost : Nat)
    (h : (BudgetCore.step cap pre cost).1 = .allow) :
    ((BudgetCore.step cap pre cost).2).spent = pre.spent + cost := by
  unfold BudgetCore.step at h ⊢
  by_cases hw : pre.spent + cost ≤ cap
  · simp [hw]
  · simp [hw] at h

/-- One `budgetStepE` step preserves the per-name cap bound, under cap
    domination for shared names. -/
theorem budgetStepE_preserves (act : CanonicalAction) (spec s : Kernels.BudgetSpec)
    (hdom : s.name = spec.name → s.cap ≤ spec.cap)
    (st st1 : Kernels.BudgetState)
    (hstep : budgetStepE act (.ok st) s = .ok st1)
    (hinv : (Kernels.budgetStateFor st spec.name).spent ≤ spec.cap) :
    (Kernels.budgetStateFor st1 spec.name).spent ≤ spec.cap := by
  simp only [budgetStepE, bind, Except.bind] at hstep
  cases hcost : Kernels.costFor s act.argsJson with
  | none => simp [hcost] at hstep
  | some cost =>
      simp only [hcost] at hstep
      cases hbs : BudgetCore.step s.cap (Kernels.budgetStateFor st s.name) cost with
      | mk d b =>
          cases d
          · -- allow: the step admitted within s.cap
            simp only [hbs, pure, Except.pure] at hstep
            injection hstep with hst1
            subst hst1
            have hallow : (BudgetCore.step s.cap
                (Kernels.budgetStateFor st s.name) cost).1 = .allow := by rw [hbs]
            have hspent : b.spent
                = (Kernels.budgetStateFor st s.name).spent + cost := by
              have := budget_step_allow_spent s.cap
                (Kernels.budgetStateFor st s.name) cost hallow
              rwa [hbs] at this
            by_cases hname : s.name = spec.name
            · rw [← hname, budgetStateFor_set_eq, hspent]
              have hw := (BudgetCore.allow_iff_within s.cap
                (Kernels.budgetStateFor st s.name) cost).mp hallow
              exact Nat.le_trans hw (hdom hname)
            · rw [budgetStateFor_set_ne st s.name spec.name b
                (fun h => hname h.symm)]
              exact hinv
          · -- block: the fold vetoed, no ok
            simp only [hbs] at hstep
            cases hstep

/-- The covering-budgets fold preserves the per-name cap bound (state-threading
    companion to `budget_fold_ok_spec`). -/
theorem budget_fold_ok_preserves (act : CanonicalAction) (spec : Kernels.BudgetSpec) :
    ∀ (specs : List Kernels.BudgetSpec),
      (∀ s ∈ specs, s.name = spec.name → s.cap ≤ spec.cap) →
      ∀ (st st1 : Kernels.BudgetState),
        specs.foldl (budgetStepE act) (.ok st) = .ok st1 →
        (Kernels.budgetStateFor st spec.name).spent ≤ spec.cap →
        (Kernels.budgetStateFor st1 spec.name).spent ≤ spec.cap := by
  intro specs
  induction specs with
  | nil =>
      intro _ st st1 hfold hinv
      injection hfold with h
      rwa [← h]
  | cons s rest ih =>
      intro hdom st st1 hfold hinv
      rw [List.foldl_cons] at hfold
      cases hhead : budgetStepE act (.ok st) s with
      | error e => rw [hhead, budgetFold_error] at hfold; cases hfold
      | ok stm =>
          rw [hhead] at hfold
          exact ih (fun s' hs' => hdom s' (List.mem_cons_of_mem _ hs')) stm st1 hfold
            (budgetStepE_preserves act spec s (hdom s List.mem_cons_self)
              st stm hhead hinv)

/-- On an ok fold, kernel B's execution transition IS the fold's output. -/
theorem budget_decide_snd_of_fold_ok (act : CanonicalAction)
    (cfg : Kernels.BudgetConfig) (ev : Unit) (st st1 : Kernels.BudgetState)
    (hfold : (cfg.filter (fun b => b.tools.contains act.tool)).foldl
        (budgetStepE act) (.ok st) = .ok st1) :
    (Kernels.budgetKernel.decide act cfg ev st).2 = st1 := by
  show (match (cfg.filter (fun b => b.tools.contains act.tool)).foldl
      (budgetStepE act) (.ok st) with
    | .ok st' => _
    | .error reason => _ : Verdict × Kernels.BudgetState).2 = st1
  rw [hfold]

/-- **`BudgetCore.run_never_over_budget` AT THE COMMITTED TRACE.** Across ANY
    sequence of mediated calls — including calls denied by ANY kernel — the
    committed spend counter of a budget never exceeds its cap: denied calls
    commit nothing (`budget_commitStep_deny`), allowed calls passed every
    covering budget's proven gate.

    HONEST SCOPE — `hdom`: covering budgets SHARING a name advance one shared
    counter, so a same-name spec with a LARGER cap may legitimately push that
    counter past a smaller cap. The bound therefore holds for a spec whose cap
    dominates its name-sharers; with unique budget names `hdom` is trivial. -/
theorem budget_committed_trace_within_cap (cfg : Kernels.BudgetConfig)
    (spec : Kernels.BudgetSpec)
    (hdom : ∀ s ∈ cfg, s.name = spec.name → s.cap ≤ spec.cap)
    (calls : List (PureCall Kernels.budgetKernel)) (st0 : Kernels.BudgetState)
    (h0 : (Kernels.budgetStateFor st0 spec.name).spent ≤ spec.cap) :
    (Kernels.budgetStateFor (commitRun Kernels.budgetKernel cfg calls st0)
        spec.name).spent ≤ spec.cap := by
  induction calls generalizing st0 with
  | nil => exact h0
  | cons c calls ih =>
      refine ih _ ?_
      unfold commitStep
      simp only [budget_ingest_id]
      by_cases hg : Kernels.budgetKernel.gates cfg c.act
      · rw [if_pos hg]
        by_cases hcomb : combineVerdicts (c.others
            ++ [(Kernels.budgetKernel.decide c.act cfg c.evidence st0).1]) = .allow
        · rw [if_pos hcomb]
          have hkind : (Kernels.budgetKernel.decide c.act cfg c.evidence
              st0).1.kind = .allow :=
            combine_allow_implies_member _ _
              (List.mem_append_right _ List.mem_cons_self) hcomb
          obtain ⟨st', hfold⟩ :=
            (budget_verdict_allow_iff c.act cfg c.evidence st0).mp hkind
          rw [budget_decide_snd_of_fold_ok c.act cfg c.evidence st0 st' hfold]
          exact budget_fold_ok_preserves c.act spec _
            (fun s hs => hdom s (List.mem_of_mem_filter hs)) st0 st' hfold h0
        · rw [if_neg hcomb]
          exact h0
      · rw [if_neg hg]
        exact h0

/-- The committed-trace budget bound from the host's actual initial state. -/
theorem budget_committed_trace_from_init (cfg : Kernels.BudgetConfig)
    (spec : Kernels.BudgetSpec)
    (hdom : ∀ s ∈ cfg, s.name = spec.name → s.cap ≤ spec.cap)
    (calls : List (PureCall Kernels.budgetKernel)) :
    (Kernels.budgetStateFor (commitRun Kernels.budgetKernel cfg calls
        Kernels.budgetKernel.init) spec.name).spent ≤ spec.cap :=
  budget_committed_trace_within_cap cfg spec hdom calls _ (Nat.zero_le _)

/-- The config lint pins caps: in a `budgetCapsConsistent` config, any two
    specs sharing a name carry the SAME cap. This is exactly what the loader
    gate in `parseBudgetSection` enforces fail-closed. -/
theorem budgetCapsConsistent_caps_eq (cfg : Kernels.BudgetConfig)
    (h : Kernels.budgetCapsConsistent cfg = true)
    {s s' : Kernels.BudgetSpec} (hs : s ∈ cfg) (hs' : s' ∈ cfg)
    (hname : s'.name = s.name) : s'.cap = s.cap := by
  unfold Kernels.budgetCapsConsistent at h
  have h2 := List.all_eq_true.mp (List.all_eq_true.mp h s hs) s' hs'
  simp only [Bool.or_eq_true, bne_iff_ne, ne_eq, beq_iff_eq] at h2
  rcases h2 with hne | hcap
  · exact absurd hname hne
  · exact hcap

/-- **`hdom` DISCHARGED FOR DEPLOYED CONFIGS.** For any config the loader
    accepts (`budgetCapsConsistent`, enforced fail-closed by
    `parseBudgetSection`), the committed-trace budget bound holds for EVERY
    spec in the config — the honest-scope hypothesis `hdom` of
    `budget_committed_trace_within_cap` is discharged automatically: name-
    sharers carry equal caps, so every spec dominates its name-sharers. -/
theorem budget_committed_trace_within_cap_of_consistent
    (cfg : Kernels.BudgetConfig) (spec : Kernels.BudgetSpec)
    (hconsist : Kernels.budgetCapsConsistent cfg = true)
    (hspec : spec ∈ cfg)
    (calls : List (PureCall Kernels.budgetKernel)) (st0 : Kernels.BudgetState)
    (h0 : (Kernels.budgetStateFor st0 spec.name).spent ≤ spec.cap) :
    (Kernels.budgetStateFor (commitRun Kernels.budgetKernel cfg calls st0)
        spec.name).spent ≤ spec.cap :=
  budget_committed_trace_within_cap cfg spec
    (fun _s hs hname =>
      Nat.le_of_eq (budgetCapsConsistent_caps_eq cfg hconsist hspec hs hname))
    calls st0 h0

/-! ## Kernel L over the committed trace (target 4, linear half) -/

/-- A denying `decide` of kernel L returns its input state unchanged. -/
theorem linear_decide_deny_snd (act : CanonicalAction) (cfg : Kernels.LinearConfig)
    (ev : List LinearCore.LEvent) (st : LinearCore.LState)
    (hdeny : (Kernels.linearKernel.decide act cfg ev st).1.kind ≠ .allow) :
    (Kernels.linearKernel.decide act cfg ev st).2 = st := by
  simp only [Kernels.linearKernel] at hdeny ⊢
  cases hfind : cfg.tools.find? (fun t => t.tool == act.tool) with
  | none => simp
  | some t =>
      cases hbind : Seal.JsonUtil.atPath act.argsJson t.capArg >>=
          Seal.JsonUtil.jsonScalarToString with
      | none => simp [hbind]
      | some cap =>
          cases hstep : LinearCore.step st (.spend cap) with
          | mk d st' =>
              cases d
              · exact absurd (by simp [hfind, hbind, hstep]) hdeny
              · simp [hbind, hstep]

/-- **A denied call burns NO capability.** Kernel L's committed state after a
    combined deny is the ingest-only state: grants gathered this call survive,
    the spend (the `decide` execution transition) is withheld. -/
theorem linear_commitStep_deny (cfg : Kernels.LinearConfig)
    (c : PureCall Kernels.linearKernel) (st : LinearCore.LState)
    (hdeny : combineVerdicts (c.others
        ++ [(Kernels.linearKernel.decide c.act cfg c.evidence
              (Kernels.linearKernel.ingest c.evidence st)).1]) ≠ .allow) :
    commitStep Kernels.linearKernel cfg c st
      = if Kernels.linearKernel.gates cfg c.act
        then Kernels.linearKernel.ingest c.evidence st else st :=
  commitStep_deny _ _ _ _ hdeny

/-- Committed-trace runner for kernel L that also COUNTS the allowed spends of
    one capability: spends admitted inside the ingest folds (evidence events)
    plus the spend committed by an allowed call. `LinearCore.runCount` lifted
    to the committed trace. -/
def linearCommitCount (cfg : Kernels.LinearConfig) (cap : LinearCore.CapId) :
    List (PureCall Kernels.linearKernel) → LinearCore.LState → LinearCore.LState × Nat
  | [], st => (st, 0)
  | c :: calls, st =>
      if Kernels.linearKernel.gates cfg c.act then
        let st1 := (LinearCore.runCount st cap c.evidence).1
        let kIn := (LinearCore.runCount st cap c.evidence).2
        if combineVerdicts (c.others
            ++ [(Kernels.linearKernel.decide c.act cfg c.evidence st1).1]) = .allow then
          let hit := if (Kernels.linearKernel.decide c.act cfg c.evidence st1).1.kind
                          = .allow ∧ linearCapOf cfg c.act = some cap
                     then 1 else 0
          let r := linearCommitCount cfg cap calls
            (Kernels.linearKernel.decide c.act cfg c.evidence st1).2
          (r.1, kIn + hit + r.2)
        else
          let r := linearCommitCount cfg cap calls st1
          (r.1, kIn + r.2)
      else
        linearCommitCount cfg cap calls st

/-- The counting runner's state IS the committed state trace. -/
theorem linearCommitCount_fst (cfg : Kernels.LinearConfig) (cap : LinearCore.CapId)
    (calls : List (PureCall Kernels.linearKernel)) (st : LinearCore.LState) :
    (linearCommitCount cfg cap calls st).1
      = commitRun Kernels.linearKernel cfg calls st := by
  induction calls generalizing st with
  | nil => rfl
  | cons c calls ih =>
      have hin : Kernels.linearKernel.ingest c.evidence st
          = (LinearCore.runCount st cap c.evidence).1 :=
        (runCount_state_eq_foldl c.evidence st cap).symm
      simp only [linearCommitCount, commitRun, commitStep, ← hin]
      by_cases hg : Kernels.linearKernel.gates cfg c.act
      · rw [if_pos hg, if_pos hg]
        by_cases hcomb : combineVerdicts (c.others
            ++ [(Kernels.linearKernel.decide c.act cfg c.evidence
                  (Kernels.linearKernel.ingest c.evidence st)).1]) = .allow
        · rw [if_pos hcomb, if_pos hcomb]
          exact ih _
        · rw [if_neg hcomb, if_neg hcomb]
          exact ih _
      · rw [if_neg hg, if_neg hg]
        exact ih _

/-- Total capability grants ingested across a call sequence — only gating
    calls gather evidence, mirroring `dispatch`. -/
def traceGrants (cfg : Kernels.LinearConfig) (cap : LinearCore.CapId) :
    List (PureCall Kernels.linearKernel) → Nat
  | [] => 0
  | c :: calls =>
      (if Kernels.linearKernel.gates cfg c.act
       then LinearCore.granted cap c.evidence else 0) + traceGrants cfg cap calls

/-- **Conservation at the committed trace.** Across ANY sequence of mediated
    calls — denies included — grants ingested plus the initial holding equal
    the allowed spends plus what remains committed:
    `LinearCore.granted_plus_initial_eq_spent_plus_remaining` lifted through
    the two-phase commit. A denied call contributes its ingested grants and
    NO spend. -/
theorem linear_committed_trace_conservation (cfg : Kernels.LinearConfig)
    (cap : LinearCore.CapId) (calls : List (PureCall Kernels.linearKernel))
    (st0 : LinearCore.LState) :
    traceGrants cfg cap calls + LinearCore.holds st0 cap
      = (linearCommitCount cfg cap calls st0).2
        + LinearCore.holds (linearCommitCount cfg cap calls st0).1 cap := by
  induction calls generalizing st0 with
  | nil => simp [linearCommitCount, traceGrants]
  | cons c calls ih =>
      have hing := LinearCore.granted_plus_initial_eq_spent_plus_remaining
        c.evidence st0 cap
      simp only [linearCommitCount, traceGrants]
      by_cases hg : Kernels.linearKernel.gates cfg c.act
      · rw [if_pos hg, if_pos hg]
        by_cases hcomb : combineVerdicts (c.others
            ++ [(Kernels.linearKernel.decide c.act cfg c.evidence
                  (LinearCore.runCount st0 cap c.evidence).1).1]) = .allow
        · rw [if_pos hcomb]
          by_cases hkind : (Kernels.linearKernel.decide c.act cfg c.evidence
              (LinearCore.runCount st0 cap c.evidence).1).1.kind = .allow
          · obtain ⟨cap', hcap', hstep, hst2⟩ := linear_decide_allow_spec c.act cfg
              c.evidence (LinearCore.runCount st0 cap c.evidence).1 hkind
            have hpos := (linear_step_spend_allow_iff _ cap').mp hstep
            obtain ⟨n, hn⟩ : ∃ n, LinearCore.holds
                (LinearCore.runCount st0 cap c.evidence).1 cap' = n + 1 :=
              ⟨LinearCore.holds (LinearCore.runCount st0 cap c.evidence).1 cap' - 1,
               by omega⟩
            have hcons := (LinearCore.spend_allow_consumes _ cap' n hn).2
            by_cases hcapeq : cap' = cap
            · subst hcapeq
              rw [if_pos ⟨hkind, hcap'⟩]
              have ih2 := ih (Kernels.linearKernel.decide c.act cfg c.evidence
                (LinearCore.runCount st0 cap' c.evidence).1).2
              rw [hst2] at ih2
              rw [hst2]
              dsimp only
              omega
            · rw [if_neg (by
                  rintro ⟨-, hcapc⟩
                  rw [hcap'] at hcapc
                  exact hcapeq (Option.some.inj hcapc))]
              have hpres := LinearCore.spend_preserves_other
                (LinearCore.runCount st0 cap c.evidence).1 cap' cap hcapeq
              have ih2 := ih (Kernels.linearKernel.decide c.act cfg c.evidence
                (LinearCore.runCount st0 cap c.evidence).1).2
              rw [hst2] at ih2
              rw [hst2]
              dsimp only
              omega
          · rw [if_neg (by rintro ⟨hk, -⟩; exact hkind hk)]
            have hst2 := linear_decide_deny_snd c.act cfg c.evidence
              (LinearCore.runCount st0 cap c.evidence).1 hkind
            have ih2 := ih (Kernels.linearKernel.decide c.act cfg c.evidence
              (LinearCore.runCount st0 cap c.evidence).1).2
            rw [hst2] at ih2
            rw [hst2]
            dsimp only
            omega
        · rw [if_neg hcomb]
          have ih2 := ih (LinearCore.runCount st0 cap c.evidence).1
          dsimp only
          omega
      · rw [if_neg hg, if_neg hg]
        have ih2 := ih st0
        omega

/-- Committed-trace spends never exceed grants plus the initial holding —
    `LinearCore.spends_le_grants` at the committed trace, denies included. -/
theorem linear_committed_trace_spends_le_grants (cfg : Kernels.LinearConfig)
    (cap : LinearCore.CapId) (calls : List (PureCall Kernels.linearKernel))
    (st0 : LinearCore.LState) :
    (linearCommitCount cfg cap calls st0).2
      ≤ traceGrants cfg cap calls + LinearCore.holds st0 cap := by
  have h := linear_committed_trace_conservation cfg cap calls st0
  omega

/-- **`LinearCore.no_double_spend` AT THE COMMITTED TRACE.** A capability
    granted at most once spends at most once across ANY sequence of mediated
    calls containing denies: a denied call burns nothing
    (`linear_commitStep_deny`), and no interleaving of allowed and denied
    calls can double-spend the one grant. -/
theorem linear_committed_trace_no_double_spend (cfg : Kernels.LinearConfig)
    (cap : LinearCore.CapId) (calls : List (PureCall Kernels.linearKernel))
    (st0 : LinearCore.LState)
    (h0 : LinearCore.holds st0 cap = 0)
    (hgr : traceGrants cfg cap calls ≤ 1) :
    (linearCommitCount cfg cap calls st0).2 ≤ 1 := by
  have h := linear_committed_trace_conservation cfg cap calls st0
  omega

end Host

namespace Host

/-! ## Binding the deployed `dispatch` body to the model (target 5)

`dispatch`'s per-kernel loop body delegates its whole state computation to the
pure `Host.phase1Held` (Host/Registry.lean). The three lemmas below identify
its components with the model's phases, so the theorems above speak about the
very function the deployed loop executes — the remaining TCB is only the IO
plumbing itself: `gather`, the `IO.Ref` get/set, the loop, and the allow-only
replay of the held sets. -/

/-- `phase1Held`'s verdict is the verdict `pureVerdicts` contributes for the
    ingested instance — the decide at the post-ingest state. -/
theorem phase1Held_verdict (K : Kernel) (cfg : K.Config) (act : CanonicalAction)
    (ev : K.Evidence) (st0 : K.State) (hg : K.gates cfg act = true) :
    (phase1Held K cfg act ev st0).1
      = (K.decide act cfg ev
          ((⟨K, cfg, ev, st0⟩ : CommitInst).ingestPhase act).state).1 := by
  simp [phase1Held, CommitInst.ingestPhase, hg]

/-- `phase1Held`'s immediately-committed state is the model's `ingestPhase`
    state — what survives a deny. -/
theorem phase1Held_ingest (K : Kernel) (cfg : K.Config) (act : CanonicalAction)
    (ev : K.Evidence) (st0 : K.State) (hg : K.gates cfg act = true) :
    (phase1Held K cfg act ev st0).2.1
      = ((⟨K, cfg, ev, st0⟩ : CommitInst).ingestPhase act).state := by
  simp [phase1Held, CommitInst.ingestPhase, hg]

/-- `phase1Held`'s HELD state is the model's `decidePhase` state — what is
    committed only on a combined allow. -/
theorem phase1Held_held (K : Kernel) (cfg : K.Config) (act : CanonicalAction)
    (ev : K.Evidence) (st0 : K.State) (hg : K.gates cfg act = true) :
    (phase1Held K cfg act ev st0).2.2
      = (((⟨K, cfg, ev, st0⟩ : CommitInst).ingestPhase act).decidePhase act).state := by
  simp [phase1Held, CommitInst.ingestPhase, CommitInst.decidePhase, hg]

end Host

namespace Host

/-! ## The budget × linear × safety composition — deny side, per kernel and
     over the dispatch loop (target 6)

Two pieces close the pinned-known gap:

1. **Per-kernel deny corollaries**: `pureCommit_deny_of_member` makes "ANY
   gating kernel's deny forces the combined deny" literal, and the
   `pureCommit_deny_*_frozen` / `pureCommit_deny_*_ingest_only` corollaries
   state per kernel exactly which state a deny commits: byte-identical for
   the identity-ingest kernels (B budget counters, T temporal trace — and
   C/V/K are stateless, `State = Unit`, nothing to move), and ONLY the
   spec-allowed ingest for S (approval fold) and L (grant fold).
2. **The dispatch loop, purely** (`dispatch_plan`): the three accumulations
   `Host.dispatch` (Host/Registry.lean) computes — the `phase1Held` verdicts
   it combines, the ingest states it writes immediately, the held decide
   states it replays only on allow — are proven equal to `pureCommit`'s
   components, stated in the loop's own vocabulary (the `gates` check and
   the `phase1Held` triple the loop literally calls).

HONEST BOUNDARY (the named IO shell, now REDUCED to its opaque core): the
`for`-loop/`do`-monad desugaring and `mut` accumulators, the allow-branch
executing the queued held writes, gather execution at the deployed registry,
and `stepImpl`'s marshalling of the step input into evidence are now theorems
(`Host.dispatch_spelled`, `Ffi.stepImpl_spelled` and companions). What REMAINS
TCB is only the opaque core: `IO.Ref` get/set value semantics (`ST.Prim.Ref`
externs have nothing to unfold) and the `unsafeBaseIO`/FFI/Rust/OS boundary.
Ref distinctness is typed-runtime trust — the five session refs carry distinct
state types, so aliasing is a type error (the one shared `unitRef`, C/V/K, has
`State = Unit`). See docs/POLICY-ASSURANCE-BOUNDARY.md. -/

/-- Kernel T's ingest is the identity: the temporal trace records only
    EXECUTED calls, never evidence. -/
@[simp] theorem temporal_ingest_id (ev : Unit) (st : Kernels.TemporalState) :
    Kernels.temporalKernel.ingest ev st = st := rfl

/-- Kernel C is stateless (`State = Unit`); its ingest is the identity. -/
@[simp] theorem consensus_ingest_id (ev : Consensus.Checker.Votes) (st : Unit) :
    Kernels.consensusKernel.ingest ev st = st := rfl

/-- Kernel V is stateless (`State = Unit`); its ingest is the identity. -/
@[simp] theorem convergence_ingest_id (ev : Unit) (st : Unit) :
    Kernels.convergenceKernel.ingest ev st = st := rfl

/-- Kernel K is stateless (`State = Unit`); its ingest is the identity. -/
@[simp] theorem calibration_ingest_id (ev : List Kernels.ForecastRecord) (st : Unit) :
    Kernels.calibrationKernel.ingest ev st = st := rfl

/-- **ANY gating kernel's deny forces the combined deny** — the fail-closed
    veto (`combine_deny_of_member`) at the stateful commit model: if the
    instance at position k gates this call and its `decide` at the post-ingest
    state denies, `pureCommit`'s combined verdict is deny. Together with the
    deny-side corollaries below this is "one kernel says no ⇒ no kernel's
    execution state moves". -/
theorem pureCommit_deny_of_member (insts : List CommitInst) (act : CanonicalAction)
    (k : Nat) (hk : k < insts.length)
    (hg : insts[k].kernel.gates insts[k].config act = true)
    (hd : (insts[k].kernel.decide act insts[k].config insts[k].evidence
            ((insts[k].ingestPhase act).state)).1.kind = .deny) :
    (pureCommit insts act).1 = .deny := by
  rw [pureCommit_verdict]
  exact combine_deny_of_member _ _ (pureCommit_mem insts act k hk hg) hd

/-- **A denied call consumes NO budget, at the composed registry.** On a
    combined deny, kernel B's committed instance is byte-identical to its
    pre-call instance: B's ingest is the identity and the `decide` transition
    (the spend) is withheld. -/
theorem pureCommit_deny_budget_frozen (insts : List CommitInst) (act : CanonicalAction)
    (cfg : Kernels.BudgetConfig) (st0 : Kernels.BudgetState)
    (k : Nat) (hk : k < insts.length)
    (hinst : insts[k] = ⟨Kernels.budgetKernel, cfg, (), st0⟩)
    (hdeny : (pureCommit insts act).1 = .deny) :
    (pureCommit insts act).2[k]'(by simpa using hk)
      = ⟨Kernels.budgetKernel, cfg, (), st0⟩ := by
  rw [pureCommit_deny_committed insts act hdeny k hk, hinst]
  simp [CommitInst.ingestPhase]

/-- **A denied call appends NOTHING to the temporal trace.** On a combined
    deny, kernel T's committed instance is byte-identical: T's ingest is the
    identity and the trace-extending `decide` transition is withheld — a
    denied call never executed, so it never enters the executed trace. -/
theorem pureCommit_deny_temporal_frozen (insts : List CommitInst) (act : CanonicalAction)
    (policies : List Kernels.TemporalPolicy) (st0 : Kernels.TemporalState)
    (k : Nat) (hk : k < insts.length)
    (hinst : insts[k] = ⟨Kernels.temporalKernel, policies, (), st0⟩)
    (hdeny : (pureCommit insts act).1 = .deny) :
    (pureCommit insts act).2[k]'(by simpa using hk)
      = ⟨Kernels.temporalKernel, policies, (), st0⟩ := by
  rw [pureCommit_deny_committed insts act hdeny k hk, hinst]
  simp [CommitInst.ingestPhase]

/-- **A denied call commits ONLY kernel S's approval fold** — the spec-allowed
    ingest (approvals read from the control file must survive a deny: the seen
    counter has advanced). The `decide` transition (approval consumption +
    prune) is withheld: the approval is not consumed by a call that never
    executed. S gates every call, so the committed state is exactly
    `ingest ev st0`, never `st0`. -/
theorem pureCommit_deny_safety_ingest_only (insts : List CommitInst) (act : CanonicalAction)
    (pol : Seal.Policy) (ev : Kernels.SafetyEvidence) (st0 : SealCore.State)
    (k : Nat) (hk : k < insts.length)
    (hinst : insts[k] = ⟨Kernels.safetyKernel, pol, ev, st0⟩)
    (hdeny : (pureCommit insts act).1 = .deny) :
    (pureCommit insts act).2[k]'(by simpa using hk)
      = ⟨Kernels.safetyKernel, pol, ev, Kernels.safetyKernel.ingest ev st0⟩ := by
  rw [pureCommit_deny_committed insts act hdeny k hk, hinst]
  rfl

/-- **A denied call consumes NO capability — it commits ONLY kernel L's grant
    fold**, the spec-allowed ingest (grants read from the grants file must
    survive a deny). The `decide` transition (the spend) is withheld. The
    committed state is the grant fold when L gates this call and the untouched
    `st0` when it does not; `linear_ingest_grant_only_holds`
    (Host/CommitRegistry.lean) shows the deployed grant fold can only GROW a
    capability's multiplicity. -/
theorem pureCommit_deny_linear_ingest_only (insts : List CommitInst) (act : CanonicalAction)
    (cfg : Kernels.LinearConfig) (ev : List LinearCore.LEvent) (st0 : LinearCore.LState)
    (k : Nat) (hk : k < insts.length)
    (hinst : insts[k] = ⟨Kernels.linearKernel, cfg, ev, st0⟩)
    (hdeny : (pureCommit insts act).1 = .deny) :
    (pureCommit insts act).2[k]'(by simpa using hk)
      = ⟨Kernels.linearKernel, cfg, ev,
         if Kernels.linearKernel.gates cfg act
         then Kernels.linearKernel.ingest ev st0 else st0⟩ := by
  rw [pureCommit_deny_committed insts act hdeny k hk, hinst]
  rfl

/-! ### The dispatch loop, purely — binding `dispatch`'s accumulations to
     `pureCommit`'s components -/

/-- The verdict list the dispatch loop accumulates — one `phase1Held` verdict
    per gating instance, registry order, nothing for non-gating instances —
    IS the model's verdict list. Gating is stable across `ingestPhase`
    (`gates` never reads state). -/
theorem dispatch_verdicts_plan (insts : List CommitInst) (act : CanonicalAction) :
    (insts.filterMap fun i =>
        if i.kernel.gates i.config act
        then some (phase1Held i.kernel i.config act i.evidence i.state).1
        else none)
      = pureVerdicts ((ingestAll insts act).map (·.asPure)) act := by
  unfold pureVerdicts ingestAll
  rw [List.filterMap_map, List.filterMap_map]
  congr 1
  funext i
  by_cases hg : i.kernel.gates i.config act
  · simp [Function.comp, CommitInst.asPure, CommitInst.ingestPhase, phase1Held, hg]
  · simp [Function.comp, CommitInst.asPure, CommitInst.ingestPhase, hg]

/-- The unconditional write set — `r.stateRef.set st1` with `phase1Held`'s
    `st1` for gating instances, the untouched instance otherwise — IS
    `ingestAll`, the state that survives a deny. -/
theorem dispatch_ingest_plan (insts : List CommitInst) (act : CanonicalAction) :
    (insts.map fun i =>
        if i.kernel.gates i.config act
        then { i with state := (phase1Held i.kernel i.config act i.evidence i.state).2.1 }
        else i)
      = ingestAll insts act := by
  unfold ingestAll
  refine List.map_congr_left fun i _ => ?_
  by_cases hg : i.kernel.gates i.config act
  · simp [phase1Held, CommitInst.ingestPhase, hg]
  · simp [CommitInst.ingestPhase, hg]

/-- The held replay set — the queued `r.stateRef.set st2` with `phase1Held`'s
    `st2` for gating instances, executed only on a combined allow — IS the
    model's decide phase over the ingested registry. -/
theorem dispatch_held_plan (insts : List CommitInst) (act : CanonicalAction) :
    (insts.map fun i =>
        if i.kernel.gates i.config act
        then { i with state := (phase1Held i.kernel i.config act i.evidence i.state).2.2 }
        else i)
      = (ingestAll insts act).map (·.decidePhase act) := by
  unfold ingestAll
  rw [List.map_map]
  refine List.map_congr_left fun i _ => ?_
  by_cases hg : i.kernel.gates i.config act
  · simp [phase1Held, CommitInst.ingestPhase, CommitInst.decidePhase, hg]
  · simp [CommitInst.ingestPhase, CommitInst.decidePhase, hg]

/-- **THE DISPATCH LOOP, PURELY.** Given the per-call snapshot — the evidence
    each `gather` returned and the state each `stateRef.get` read, as the
    instance list — the three accumulations `Host.dispatch` computes are
    exactly `pureCommit`'s components:

    * the combined verdict is `combineVerdicts` over the loop's `phase1Held`
      verdicts (one per gating instance, registry order);
    * on deny, the committed states are exactly the loop's UNCONDITIONAL
      writes (`phase1Held`'s ingest states) — the held writes are never
      applied;
    * on allow, the committed states are exactly the loop's held replay
      (`phase1Held`'s decide states).

    HONEST BOUNDARY: this covers everything the loop computes per call given
    its snapshot. The former IO-shell residuals — the `for`-loop/`do`-monad
    desugaring, the allow branch executing the queued writes, and `stepImpl`'s
    marshalling into evidence — are now theorems (`Host.dispatch_spelled`,
    `Ffi.stepImpl_spelled`). What REMAINS TCB is the opaque core: `IO.Ref`
    get/set value semantics and the `unsafeBaseIO`/FFI/Rust/OS boundary; ref
    distinctness is typed-runtime trust (distinct state types per session ref).
    See docs/POLICY-ASSURANCE-BOUNDARY.md. -/
theorem dispatch_plan (insts : List CommitInst) (act : CanonicalAction) :
    ((pureCommit insts act).1
        = combineVerdicts (insts.filterMap fun i =>
            if i.kernel.gates i.config act
            then some (phase1Held i.kernel i.config act i.evidence i.state).1
            else none)) ∧
    ((pureCommit insts act).1 = .deny →
        (pureCommit insts act).2 = insts.map fun i =>
          if i.kernel.gates i.config act
          then { i with state := (phase1Held i.kernel i.config act i.evidence i.state).2.1 }
          else i) ∧
    ((pureCommit insts act).1 = .allow →
        (pureCommit insts act).2 = insts.map fun i =>
          if i.kernel.gates i.config act
          then { i with state := (phase1Held i.kernel i.config act i.evidence i.state).2.2 }
          else i) := by
  refine ⟨?_, ?_, ?_⟩
  · rw [pureCommit_verdict, dispatch_verdicts_plan]
  · intro hdeny
    rw [pureCommit_deny_no_decide_commit insts act hdeny, dispatch_ingest_plan]
  · intro hallow
    rw [pureCommit_allow_commits_decide insts act hallow, dispatch_held_plan]

end Host

/-! ## Axiom pins — enforced at module build

Every definition and theorem of the commit-discipline model sits on Lean's
three classical axioms at most. No opaque crypto (ed25519 / A3) and no
`sorryAx` appears anywhere in the commit-discipline proofs. These
`#guard_msgs` pins fail the build on drift. -/

/-- info: 'Host.pureCommit' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit
/-- info: 'Host.commitVerdict' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitVerdict
/-- info: 'Host.pureCommit_verdict' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_verdict
/-- info: 'Host.pureCommit_deny_no_decide_commit' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_deny_no_decide_commit
/-- info: 'Host.pureCommit_deny_committed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_deny_committed
/-- info: 'Host.pureCommit_allow_commits_decide' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_allow_commits_decide
/-- info: 'Host.pureCommit_allow_committed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_allow_committed
/-- info: 'Host.pureCommit_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_mem
/-- info: 'Host.pureCommit_allow_closed_algebra' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_allow_closed_algebra
/-- info: 'Host.pureCommit_allow_linear_committed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_allow_linear_committed
/-- info: 'Host.pureCommit_allow_budget_committed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_allow_budget_committed
/-- info: 'Host.combineVerdicts_middle' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.combineVerdicts_middle
/-- info: 'Host.combineVerdicts_rotate' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.combineVerdicts_rotate
/-- info: 'Host.commitStep' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitStep
/-- info: 'Host.commitRun' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitRun
/-- info: 'Host.commitStep_deny' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitStep_deny
/-- info: 'Host.pureCommit_head_commitStep' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_head_commitStep
/-- info: 'Host.budget_commitStep_deny' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.budget_commitStep_deny
/-- info: 'Host.budgetStepE_preserves' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.budgetStepE_preserves
/-- info: 'Host.budget_fold_ok_preserves' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.budget_fold_ok_preserves
/-- info: 'Host.budget_decide_snd_of_fold_ok' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.budget_decide_snd_of_fold_ok
/--
info: 'Host.budget_committed_trace_within_cap' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.budget_committed_trace_within_cap
/--
info: 'Host.budget_committed_trace_from_init' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.budget_committed_trace_from_init
/-- info: 'Host.budgetCapsConsistent_caps_eq' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.budgetCapsConsistent_caps_eq
/--
info: 'Host.budget_committed_trace_within_cap_of_consistent' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.budget_committed_trace_within_cap_of_consistent
/-- info: 'Host.linear_decide_deny_snd' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.linear_decide_deny_snd
/-- info: 'Host.linear_commitStep_deny' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.linear_commitStep_deny
/-- info: 'Host.linearCommitCount' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.linearCommitCount
/-- info: 'Host.linearCommitCount_fst' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.linearCommitCount_fst
/--
info: 'Host.linear_committed_trace_conservation' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.linear_committed_trace_conservation
/--
info: 'Host.linear_committed_trace_spends_le_grants' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.linear_committed_trace_spends_le_grants
/--
info: 'Host.linear_committed_trace_no_double_spend' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.linear_committed_trace_no_double_spend
/-- info: 'Host.pureCommit_deny_of_member' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_deny_of_member
/-- info: 'Host.pureCommit_deny_budget_frozen' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_deny_budget_frozen
/-- info: 'Host.pureCommit_deny_temporal_frozen' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.pureCommit_deny_temporal_frozen
/--
info: 'Host.pureCommit_deny_safety_ingest_only' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.pureCommit_deny_safety_ingest_only
/--
info: 'Host.pureCommit_deny_linear_ingest_only' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.pureCommit_deny_linear_ingest_only
/-- info: 'Host.dispatch_verdicts_plan' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatch_verdicts_plan
/-- info: 'Host.dispatch_ingest_plan' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatch_ingest_plan
/-- info: 'Host.dispatch_held_plan' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatch_held_plan
/-- info: 'Host.dispatch_plan' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.dispatch_plan
