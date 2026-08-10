/- SPDX-License-Identifier: Apache-2.0 -/

import Host.EgressPerimeter

/-!
# The P4 spawn seam — the no-go, machine-checked

`Host/EgressPerimeter.lean` dismisses P4 (operator argv →
`Command::new(...).spawn()`) in PROSE: "the argv is consumed BEFORE the seam
exists … any `spawnEv` would quantify over nothing the model constrains."
This module turns that paragraph into theorems, by doing exactly the thing
the prose says is pointless — extending the alphabet with a `spawnEv` — and
proving, rather than asserting, what the extension yields.

## The one fidelity input

The deployed host spawns the argv-selected child ONCE, at startup, before
reading any client input: `rust/src/main.rs:1228-1233` is the spawn, the
stdin read loop begins at `rust/src/main.rs:1351`. That ORDERING is a fact
about trusted Rust transport code (TCB), not a theorem; it enters the model
as the definition of `srun` — the run starts from the trace `[spawnEv argv]`
and every subsequent step is the egress step, lifted (`sstep` — note no
input constructor produces `spawnEv`; there is no runtime spawn edge).
Everything downstream of that placement is machine-checked.

## What is proved

* **Argv is a run PARAMETER, not an event the semantics touches**
  (`srun_eq`, `srun_argv_parameter`): the spawn-extended run is exactly the
  egress run with `spawnEv argv` pinned at the very bottom of the trace.
  Two runs differing only in argv have identical adapter state and
  identical traces above the spawn event. No gate, adapter, author or
  input stream can observe — hence constrain — the child selection.
* **Strict spawn mediation FAILS, universally**
  (`spawn_non_bypass_fails`): in its weakest form — "the spawn has SOME
  strictly earlier decision, on any line, of any verdict" — mediation
  fails for EVERY argv, adapter, gate, author AND every input stream
  (the P6 relay negative needed a specific run; the spawn negative holds
  on all of them, because the spawn precedes everything).
* **Every guarded-position constraint on argv is VACUOUS**
  (`spawn_constraint_vacuous`, `spawn_constraint_vacuous_false`): any
  candidate obligation of the form "if the spawn sits above a nonempty
  history, its argv satisfies C" holds for EVERY predicate C — including
  `C := fun _ => False`. A property satisfiable by the unsatisfiable
  constraint constrains nothing: a `spawnEv` mediation obligation
  quantifies over an EMPTY set of positions. This is the prose claim
  "would quantify over nothing the model constrains", as a theorem, and
  it is labelled vacuous because vacuity IS the content. Read the scope
  exactly: the vacuity is a property of the GUARDED form, not of every
  conceivable argv property. A direct `C argv`, or `spawnEv v ∈ tr → C v`,
  is NOT vacuous — at `C := False` it is refuted by `srun_spawn_mem`.
* **The widening breaks nothing** (`srun_client_block_mediated`): the P5
  capstone transfers verbatim to spawn-extended runs, for every argv —
  what an argv-controlling operator gets is the child selection and ONLY
  the child selection; every request-side mediation guarantee is
  argv-invariant.

## What this does NOT show

Model-level, exactly as the parent modules. The spawn-at-startup placement
is the P4 row of the trust inventory (`RUST_BRIDGE.md`: "Operator argv: the
command line names the guarded server"), verified by inspection of
`rust/src/main.rs`, not by proof; a host that re-spawned mid-run would need
a different `srun` and would falsify none of the parent theorems. P4
REMAINS a trust assumption — and what these theorems establish is that
THIS MODEL's trace semantics contain no argv constraint of the guarded
form, because argv precedes every event it could be constrained by. That
is a statement about this model, NOT a proof that no model and no deployed
host could constrain argv.

Explicit residuals, none of them discharged anywhere in this module:

* **No refinement to the binary.** No theorem here connects `srun` to the
  deployed Rust execution trace. `srun`'s startup placement is read off
  `rust/src/main.rs` by inspection; the `rust/` ↔ model correspondence
  stays the conformance-bridge obligation.
* **Child-produced inputs are assumed argv-invariant.**
  `srun_argv_parameter` holds `inputs` FIXED. It therefore does NOT model
  that a different executable may emit different child output and hence
  drive a DIFFERENT future input stream. Argv-invariance of the trace above
  the spawn is proved only against one and the same input list.
* **Startup argv validation is not ruled out.** Nothing here proves that
  the deployed host performs no argv check, nor that such a check is
  impossible. The claim is about what the TRACE semantics can express, not
  about what startup code can do before the trace begins.
* **Nothing is claimed about argv safety.** No theorem states that any argv
  is safe, that the spawned child is the intended one, or which executables
  are acceptable. Child identity and argv admissibility remain entirely
  outside the model.
-/

namespace Host.Spawn

open Lean
open Host.Channel
open Host.Perimeter
open Host.Egress

/-! ## The spawn-extended alphabet -/

/-- Spawn-extended seam event: every egress event, plus the P4 startup
    transition — the operator argv selecting WHICH child the run talks to. -/
inductive SEv where
  | spawnEv (argv : List String)
  | eev (e : EEv)
  deriving Repr, BEq

/-- Spawn-extended trace, most-recent-first (the `ChanTrace` convention):
    the startup spawn is therefore the LAST list element. -/
abbrev STrace := List SEv

/-- Lift an egress trace into the spawn alphabet. -/
def liftE (tr : ETrace) : STrace := tr.map SEv.eev

/-- One spawn-extended step: the egress step, lifted. NO input produces
    `spawnEv` — the deployed host has no runtime spawn edge; the spawn
    happens before the first input exists. -/
def sstep (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String)
    (s : A.St × STrace) (i : EIn) : A.St × STrace :=
  ((estep A gate author (s.1, ([] : ETrace)) i).1,
   liftE (estep A gate author (s.1, ([] : ETrace)) i).2 ++ s.2)

/-- A spawn-extended run: the deployed host spawns the argv-selected child
    ONCE, at startup, before reading any input (`rust/src/main.rs:1228-1233`
    spawns; the stdin loop begins at `:1351`) — so the initial trace is
    `[spawnEv argv]` and every subsequent step is `sstep`. -/
def srun (argv : List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    A.St × STrace :=
  inputs.foldl (sstep A gate author) (A.init, [SEv.spawnEv argv])

/-! ## Structure: the spawn-extended run IS the egress run over the spawn -/

/-- No lifted egress event is a spawn event. -/
theorem liftE_no_spawn (v : List String) (tr : ETrace) :
    SEv.spawnEv v ∉ liftE tr := by
  intro h
  obtain ⟨e, -, he⟩ := List.mem_map.mp h
  cases he

/-- The egress step factors over its incoming trace: the new events do not
    depend on it. -/
theorem estep_split (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (st : A.St) (tr : ETrace) (i : EIn) :
    estep A gate author (st, tr) i
      = ((estep A gate author (st, ([] : ETrace)) i).1,
         (estep A gate author (st, ([] : ETrace)) i).2 ++ tr) := by
  cases i with
  | childOut c => rfl
  | clientLine line =>
    cases h : Host.classifyLine line with
    | passthrough => simp [estep, h]
    | refuse => simp [estep, h]
    | act a =>
      cases hg : gate line with
      | Allow out => simp [estep, h, hg]
      | Block => simp [estep, h, hg]

/-- The egress fold factors over its starting trace. -/
theorem efold_split (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) :
    ∀ (inputs : List EIn) (st : A.St) (tr : ETrace),
      inputs.foldl (estep A gate author) (st, tr)
        = ((inputs.foldl (estep A gate author) (st, ([] : ETrace))).1,
           (inputs.foldl (estep A gate author) (st, ([] : ETrace))).2 ++ tr) := by
  intro inputs
  induction inputs with
  | nil => intro st tr; simp
  | cons i rest ih =>
    intro st tr
    rw [List.foldl_cons, List.foldl_cons, estep_split A gate author st tr i]
    generalize estep A gate author (st, ([] : ETrace)) i = e
    obtain ⟨st', tr'⟩ := e
    dsimp only
    rw [ih st' (tr' ++ tr), ih st' tr']
    simp [List.append_assoc]

/-- The spawn-extended fold is the egress fold, lifted over the starting
    trace. -/
theorem sfold_eq (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) :
    ∀ (inputs : List EIn) (st : A.St) (tr : STrace),
      inputs.foldl (sstep A gate author) (st, tr)
        = ((inputs.foldl (estep A gate author) (st, ([] : ETrace))).1,
           liftE (inputs.foldl (estep A gate author) (st, ([] : ETrace))).2
             ++ tr) := by
  intro inputs
  induction inputs with
  | nil => intro st tr; simp [liftE]
  | cons i rest ih =>
    intro st tr
    rw [List.foldl_cons, List.foldl_cons]
    have hstep : sstep A gate author (st, tr) i
        = ((estep A gate author (st, ([] : ETrace)) i).1,
           liftE (estep A gate author (st, ([] : ETrace)) i).2 ++ tr) := rfl
    rw [hstep]
    generalize estep A gate author (st, ([] : ETrace)) i = e
    obtain ⟨st', tr'⟩ := e
    dsimp only
    rw [ih st' (liftE tr' ++ tr), efold_split A gate author rest st' tr']
    dsimp only
    simp [liftE, List.map_append, List.append_assoc]

/-- **The structure theorem.** The spawn-extended run is EXACTLY the egress
    run with the spawn event pinned at the very bottom of the trace: same
    adapter state, same events above the spawn, and the argv appears in the
    spawn event and NOWHERE else. -/
theorem srun_eq (argv : List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    srun argv A gate author inputs
      = ((erun A gate author inputs).1,
         liftE (erun A gate author inputs).2 ++ [SEv.spawnEv argv]) :=
  sfold_eq A gate author inputs A.init [SEv.spawnEv argv]

theorem srun_state_eq (argv : List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    (srun argv A gate author inputs).1 = (erun A gate author inputs).1 := by
  rw [srun_eq]

theorem srun_trace_eq (argv : List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    (srun argv A gate author inputs).2
      = liftE (erun A gate author inputs).2 ++ [SEv.spawnEv argv] := by
  rw [srun_eq]

/-! ## Position: the spawn occurs exactly once, below every event -/

/-- Splitting a spawn-bottomed trace at any spawn event forces the split to
    the bottom: the history below the spawn is EMPTY. -/
theorem liftE_concat_spawn_split (argv : List String) :
    ∀ (E : ETrace) (post : STrace) (v : List String) (pre : STrace),
      liftE E ++ [SEv.spawnEv argv] = post ++ SEv.spawnEv v :: pre →
      post = liftE E ∧ v = argv ∧ pre = [] := by
  intro E
  induction E with
  | nil =>
    intro post v pre h
    simp only [liftE, List.map_nil, List.nil_append] at h
    cases post with
    | nil =>
      rw [List.nil_append] at h
      injection h with h1 h2
      injection h1 with hv
      exact ⟨by simp [liftE], hv.symm, h2.symm⟩
    | cons p ps =>
      rw [List.cons_append] at h
      injection h with h1 h2
      exact absurd h2.symm (by simp)
  | cons x E' ih =>
    intro post v pre h
    simp only [liftE, List.map_cons, List.cons_append] at h
    cases post with
    | nil =>
      rw [List.nil_append] at h
      injection h with h1 h2
      cases h1
    | cons p ps =>
      rw [List.cons_append] at h
      injection h with h1 h2
      obtain ⟨hpost, hv, hpre⟩ := ih ps v pre h2
      subst h1
      exact ⟨by simp [hpost, liftE], hv, hpre⟩

/-- Splitting a spawn-bottomed trace at any LIFTED event lands inside the
    egress part, with the spawn still below the split point. -/
theorem liftE_concat_eev_split (argv : List String) (e : EEv) :
    ∀ (E : ETrace) (post pre : STrace),
      liftE E ++ [SEv.spawnEv argv] = post ++ SEv.eev e :: pre →
      ∃ post' pre', E = post' ++ e :: pre'
        ∧ pre = liftE pre' ++ [SEv.spawnEv argv] := by
  intro E
  induction E with
  | nil =>
    intro post pre h
    simp only [liftE, List.map_nil, List.nil_append] at h
    have hmem : SEv.eev e ∈ ([SEv.spawnEv argv] : STrace) := by
      rw [h]; exact List.mem_append_right _ List.mem_cons_self
    rcases List.mem_cons.mp hmem with h' | h'
    · cases h'
    · cases h'
  | cons x E' ih =>
    intro post pre h
    simp only [liftE, List.map_cons, List.cons_append] at h
    cases post with
    | nil =>
      rw [List.nil_append] at h
      injection h with h1 h2
      injection h1 with hxe
      subst hxe
      exact ⟨[], E', rfl, h2.symm⟩
    | cons p ps =>
      rw [List.cons_append] at h
      injection h with h1 h2
      obtain ⟨post', pre', hE, hpre⟩ := ih ps pre h2
      exact ⟨x :: post', pre', by simp [hE], hpre⟩

/-- **The position pin.** On EVERY spawn-extended run — every argv, adapter,
    gate, author, input stream — every occurrence of a spawn event sits at
    the very bottom of the trace: it is the startup spawn, its argv is the
    operator's, and the history strictly before it is EMPTY. -/
theorem srun_split_spawn (argv : List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn)
    (post : STrace) (v : List String) (pre : STrace)
    (h : (srun argv A gate author inputs).2
      = post ++ SEv.spawnEv v :: pre) :
    post = liftE (erun A gate author inputs).2 ∧ v = argv ∧ pre = [] := by
  rw [srun_trace_eq] at h
  exact liftE_concat_spawn_split argv _ post v pre h

/-- Spawn-event membership: exactly the startup spawn, for every run — the
    event OCCURS (the no-go below is not about an absent event), and only
    with the operator's argv. -/
theorem srun_spawn_mem (argv v : List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    SEv.spawnEv v ∈ (srun argv A gate author inputs).2 ↔ v = argv := by
  rw [srun_trace_eq]
  constructor
  · intro h
    rcases List.mem_append.mp h with h' | h'
    · exact absurd h' (liftE_no_spawn v _)
    · rcases List.mem_cons.mp h' with h'' | h''
      · exact SEv.spawnEv.inj h''
      · cases h''
  · rintro rfl
    exact List.mem_append_right _ List.mem_cons_self

/-! ## The P4 verdict, part one — argv is a parameter -/

/-- **Argv is a run PARAMETER, not a constrained event.** Two spawn-extended
    runs differing ONLY in argv have identical adapter state and identical
    traces above the spawn event. The trace semantics cannot distinguish —
    hence cannot constrain — the child selection: an operator (or an
    attacker holding operator startup authority) selects an ARBITRARY child,
    and nothing any gate, adapter, author or input stream does depends on
    or reacts to the choice. -/
theorem srun_argv_parameter (argv₁ argv₂ : List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    (srun argv₁ A gate author inputs).1 = (srun argv₂ A gate author inputs).1
      ∧ ∃ E : ETrace,
          (srun argv₁ A gate author inputs).2
            = liftE E ++ [SEv.spawnEv argv₁]
          ∧ (srun argv₂ A gate author inputs).2
            = liftE E ++ [SEv.spawnEv argv₂] :=
  ⟨by rw [srun_state_eq, srun_state_eq],
   (erun A gate author inputs).2,
   srun_trace_eq argv₁ A gate author inputs,
   srun_trace_eq argv₂ A gate author inputs⟩

/-! ## The P4 verdict, part two — strict mediation fails universally -/

/-- Spawn mediation, in its WEAKEST form (the `relayMediated` analogue):
    every spawn has SOME strictly earlier decision — on any line, of any
    verdict. Even this fails, on every run. -/
def spawnMediated (tr : STrace) : Prop :=
  ∀ post v pre, tr = post ++ SEv.spawnEv v :: pre →
    ∃ raw d, SEv.eev (EEv.decideEv raw d) ∈ pre

/-- **P4 NO-GO, machine-checked (the negative).** For every argv, every
    adapter, every gate, every author and EVERY input stream: spawn
    mediation fails even in its weakest form — the spawn carries no prior
    decision of any kind, because NOTHING precedes it. The P6 relay
    negative needed a witness run; the spawn negative holds on ALL runs. -/
theorem spawn_non_bypass_fails (argv : List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    ¬ spawnMediated (srun argv A gate author inputs).2 := by
  intro hmed
  obtain ⟨raw, d, hd⟩ :=
    hmed (liftE (erun A gate author inputs).2) argv []
      (by rw [srun_trace_eq])
  cases hd

/-- The P4 negative pinned at the deployed model and the LIVE gate. -/
theorem spawn_non_bypass_fails_live (argv : List String)
    (state : SealV2.ApprovalState)
    (author : CanonicalAction → String) (inputs : List EIn) :
    ¬ spawnMediated
        (srun argv sealAdapter (fun raw => SealV2.decide raw state)
          author inputs).2 :=
  spawn_non_bypass_fails argv sealAdapter _ author inputs

/-! ## The P4 verdict, part three — every candidate constraint is vacuous -/

/-- A candidate argv obligation, guarded on the spawn being an IN-RUN event:
    "wherever the spawn sits above a nonempty history, its argv satisfies
    `C`." This is the shape ANY spawn-mediation property must take — a
    constraint can only bite at a position with history to constrain
    against. -/
def spawnGuardedBy (C : List String → Prop) (tr : STrace) : Prop :=
  ∀ post v pre, tr = post ++ SEv.spawnEv v :: pre → pre ≠ [] → C v

/-- **P4 VACUITY, machine-checked — and labelled as such.** EVERY candidate
    constraint `C` on argv is satisfied by every spawn-extended run,
    because no run contains a spawn event above a nonempty history: the
    obligation quantifies over an EMPTY set of positions. This is
    `EgressPerimeter.lean`'s prose — "any `spawnEv` would quantify over
    nothing the model constrains" — as a theorem. A VACUOUS result by
    design: the vacuity IS the no-go. It certifies nothing about any
    child. -/
theorem spawn_constraint_vacuous (C : List String → Prop)
    (argv : List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    spawnGuardedBy C (srun argv A gate author inputs).2 := by
  intro post v pre heq hne
  exact absurd (srun_split_spawn argv A gate author inputs post v pre
    heq).2.2 hne

/-- The vacuity at its sharpest instantiation: even the UNSATISFIABLE
    constraint `C := fun _ => False` — "no argv is ever acceptable" — is
    "satisfied" by every run. A property family whose impossible member
    holds constrains nothing whatsoever. -/
theorem spawn_constraint_vacuous_false (argv : List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    spawnGuardedBy (fun _ => False) (srun argv A gate author inputs).2 :=
  spawn_constraint_vacuous _ argv A gate author inputs

/-! ## The salvage — the widening breaks nothing, for every child -/

/-- The P5 mediation property over the spawn-extended trace. -/
def blocksPrecededByDecideS (tr : STrace) : Prop :=
  ∀ post raw b pre, tr = post ++ SEv.eev (EEv.blockEv raw b) :: pre →
    SEv.eev (EEv.decideEv raw SealV2.Decision.Block) ∈ pre

/-- **The P5 capstone survives the spawn widening, for EVERY argv.** What
    an argv-controlling operator gets is the child selection and ONLY the
    child selection: every client-bound block emission on a spawn-extended
    run is still preceded by its own `Block` decide, whichever child was
    spawned. The guarantee is argv-invariant — which is exactly why it
    cannot constrain the child. -/
theorem srun_client_block_mediated (argv : List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    blocksPrecededByDecideS (srun argv A gate author inputs).2 := by
  intro post raw b pre heq
  rw [srun_trace_eq] at heq
  obtain ⟨post', pre', hE, hpre⟩ :=
    liftE_concat_eev_split argv (EEv.blockEv raw b) _ post pre heq
  have hdec := client_block_mediated A gate author inputs post' raw b pre' hE
  rw [hpre]
  exact List.mem_append_left _ (List.mem_map_of_mem hdec)

/-! ## Concrete run, compiler-evaluated -/

-- The startup spawn sits at the very bottom; the egress events stack above
-- it exactly as in `EgressPerimeter.lean`'s #guards (allowed act-line, then
-- a verbatim relay):
#guard (srun ["./mcp-server", "--stdio"] sealAdapter allowMediatedGate
    testAuthor
    [EIn.clientLine mediatedWitness, EIn.childOut "{\"result\":1}"]).2
  == [SEv.eev (EEv.relayEv "{\"result\":1}"),
      SEv.eev (EEv.emitEv "OK"),
      SEv.eev (EEv.decideEv mediatedWitness (SealV2.Decision.Allow "OK")),
      SEv.spawnEv ["./mcp-server", "--stdio"]]
-- Two different children, same inputs: identical above the spawn — the
-- argv-parameter theorem, concretely:
#guard ((srun ["./mcp-server"] sealAdapter allowMediatedGate testAuthor
    [EIn.clientLine mediatedWitness]).2.take 2)
  == ((srun ["/bin/evil"] sealAdapter allowMediatedGate testAuthor
    [EIn.clientLine mediatedWitness]).2.take 2)

/-! ## Axiom pins

Classical baseline `[propext, Classical.choice, Quot.sound]` or tighter —
no `sorryAx`, no `native_decide`, no custom axiom. -/

/-- info: 'Host.Spawn.liftE_no_spawn' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms liftE_no_spawn
/-- info: 'Host.Spawn.estep_split' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms estep_split
/-- info: 'Host.Spawn.efold_split' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms efold_split
/-- info: 'Host.Spawn.sfold_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms sfold_eq
/-- info: 'Host.Spawn.srun_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms srun_eq
/-- info: 'Host.Spawn.srun_state_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms srun_state_eq
/-- info: 'Host.Spawn.srun_trace_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms srun_trace_eq
/-- info: 'Host.Spawn.liftE_concat_spawn_split' depends on axioms: [propext] -/
#guard_msgs in #print axioms liftE_concat_spawn_split
/-- info: 'Host.Spawn.liftE_concat_eev_split' depends on axioms: [propext] -/
#guard_msgs in #print axioms liftE_concat_eev_split
/-- info: 'Host.Spawn.srun_split_spawn' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms srun_split_spawn
/-- info: 'Host.Spawn.srun_spawn_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms srun_spawn_mem
/-- info: 'Host.Spawn.srun_argv_parameter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms srun_argv_parameter
/-- info: 'Host.Spawn.spawn_non_bypass_fails' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms spawn_non_bypass_fails
/-- info: 'Host.Spawn.spawn_non_bypass_fails_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms spawn_non_bypass_fails_live
/-- info: 'Host.Spawn.spawn_constraint_vacuous' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms spawn_constraint_vacuous
/-- info: 'Host.Spawn.spawn_constraint_vacuous_false' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms spawn_constraint_vacuous_false
/-- info: 'Host.Spawn.srun_client_block_mediated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms srun_client_block_mediated

end Host.Spawn
