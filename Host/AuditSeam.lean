/- SPDX-License-Identifier: Apache-2.0 -/

import Host.EgressPerimeter

/-!
# The P7 telemetry seam — the no-go, machine-checked

`Host/EgressPerimeter.lean` dismisses P7 (audit / A3 drops / errors →
stderr) in PROSE: "stderr has no input edge into routing, so a faithful
`audEv` would be no-effect by construction and prove nothing new." This
module turns that paragraph into theorems, by doing exactly the thing the
prose says is pointless — extending the alphabet with an `audEv` — and
proving, rather than asserting, what the extension yields. It is the P7
sibling of `Host/SpawnSeam.lean` (the P4 no-go, lane
`proof/p4-argv-nogo`) and follows its shape; the two egress-fold factoring
lemmas (`estep_split`, `efold_split`) are stated here independently so the
lanes carry no cross-branch import.

## The one fidelity input

The deployed host WRITES stderr and never reads it: every P7 emission is an
`eprintln!` driven by something the host just did (a decision written, an
audit record observed, an error), and no code path in `rust/src/main.rs`
reads stderr back — the child's stderr is `Stdio::inherit()`
(`rust/src/main.rs:1232`), shared downward, never captured. That
DIRECTIONALITY is a fact about trusted Rust transport code (TCB), not a
theorem; it enters the model as the definition of `astep` — each step's
audit lines are a fixed function `tel : EEv → List String` of the step's own
seam events, stacked directly above them, and the input alphabet is the
UNCHANGED `EIn` (no constructor lets an audit line re-enter, because the
deployed host has no stderr read edge to model). Everything downstream of
that placement is machine-checked.

## What is proved

* **Telemetry is a POST-PROCESSING of the egress run** (`arun_eq`): the
  audit-extended run is exactly the egress run with each event decorated by
  its `tel` lines — same adapter state, and the trace is `weave tel` of the
  egress trace. The extension factors THROUGH the unextended run: `audEv`
  is a decoration, not a dynamics.
* **The telemetry function is a run PARAMETER** (`arun_tel_parameter`,
  `arun_erase_eq`): two runs differing only in `tel` have identical adapter
  state and weave the SAME egress trace; erasing audit events recovers it
  exactly. IN THIS MODEL, and with the input stream held FIXED, no gate,
  adapter, author or input stream can observe — hence be influenced by —
  what the host tells stderr.
* **No event carries information INTO the mediated decision from stderr**
  (`arun_eev_mem`, `arun_decide_tel_invariant`): every seam-event fact of
  the extended run — in particular every decide — is `tel`-invariant, for
  every adapter, gate, author and input stream. Telemetry-invariance of the
  decisions is a property of THIS model's trace semantics.
* **Every constraint of the GUARDED form `audGuardedBy` is VACUOUS**
  (`aud_constraint_vacuous`, `aud_constraint_vacuous_false`): that form's
  antecedent is a TELEMETRY-FED decision — one present under one telemetry
  function and absent under another — and no decide of any run is
  telemetry-sensitive (`aud_no_fed_decision`), so the obligation "a
  decision stderr fed satisfies C" holds for EVERY predicate C, including
  `C := fun _ _ => False`: it quantifies over an EMPTY set of decisions.
  Read the scope exactly — this is the vacuity of ONE form, not of every
  conceivable stderr property. Constraints of OTHER shapes are NOT vacuous:
  `AEv.audEv s ∈ tr → C s` is refuted at `C := fun _ => False` by the
  `relayTel` witness run of `aud_non_bypass_fails`, whose trace that proof
  pins by `rfl` with `audEv "relay"` in it (and by the compiler-evaluated
  `#guard`s below). This is the prose claim "no input edge into routing",
  as a theorem about the guarded form, and it is labelled vacuous because
  vacuity IS the content.
* **What stderr DOES carry — the honest asymmetry** (`arun_stderr_image`,
  `aud_provenance`): stderr is an OUTPUT channel, and "no input edge" is
  NOT "no leak". The stderr image of a run is exactly `telImage tel` of the
  ENTIRE egress trace — with an injective per-event `tel` (the deployed
  audit lines carry decision paths, judged lines, error details), a reader
  of stderr obtains the run's complete mediation transcript. Conversely,
  every audit line traces to a seam event: stderr says only what the run
  did. P7 buys an attacker who can read stderr the full seam history —
  read-only — and, IN THIS MODEL, zero influence over any decision,
  emission or state.
* **Audit mediation is inherited, never created** (`aud_non_bypass_fails`,
  `aud_decide_tel_mediated`): strict audit mediation FAILS on a witness run
  under relay-driven telemetry (the audit line's driving event is itself
  undecided, exactly the P6 negative propagating) and HOLDS for
  decide-driven telemetry on every run — the extension imposes no new
  obligation of its own; each audit line inherits the mediation status of
  the event that drove it. The failure is a PROVED negative, not a failure
  to prove mediation, and it is NOT vacuous: the same `rfl` that decides
  the witness run's trace places `audEv "relay"` above `eev (relayEv c)`,
  so the audit line whose mediation fails demonstrably occurs.
* **The widening breaks nothing** (`arun_client_block_mediated`): the P5
  capstone transfers verbatim to audit-extended runs, for every telemetry
  function.

## What this does NOT show

Model-level, exactly as the parent modules. `tel` covers SEAM-EVENT-driven
telemetry (the P7 row's audit records and per-decision lines). Stderr lines
the deployed host emits that are NOT driven by seam events — startup config
rejections, `validate`-mode output, and the A3 dropped-approval warnings
driven by evidence-file reads — are outside `tel`; the evidence-driven ones
belong to the P8/P9 gate-state row, over which non-bypass is universally
quantified. In `--channel interactive` the approval PROMPT is written to
stderr and a human answers on `/dev/tty`: that is a feedback loop through
the OPERATOR, and it re-enters the model only as approval state (the same
P8 row), never as a trace edge. The CONTENT discipline of audit records
stays where the prose put it (`Host/NonInterference.lean`,
`record_authView_noninterference`); the Rust stderr writes themselves stay
TCB. P7 REMAINS "telemetry only, no effect" as a trust-inventory row — and
what these theorems establish is that THIS MODEL's trace semantics contain
no telemetry-feedback constraint of the `audGuardedBy` form, because no
decide of any run varies with `tel`. That is a statement about this model,
NOT a proof that no model and no deployed host could constrain the
telemetry, and NOT a claim about properties of other shapes: a property
quantifying over audit events themselves is expressible here and is not
vacuous (`aud_provenance`).

Explicit residuals, none of them discharged anywhere in this module:

* **The vacuity is scoped to one form.** `aud_constraint_vacuous` ranges
  over every predicate `C`, but only inside `audGuardedBy`, whose
  antecedent `audFedDecision` this model makes IMPOSSIBLE
  (`aud_no_fed_decision`). Nothing here shows that every candidate P7
  input-edge property must take that form.
* **No refinement to the binary.** No theorem connects `arun` to the
  deployed Rust stderr writes. `astep`'s placement of audit lines — a fixed
  function of the step's own seam events, never re-entering the input
  alphabet — is read off `rust/src/main.rs` by inspection; the `rust/` ↔
  model correspondence stays the conformance-bridge obligation, and the
  `eprintln!`s themselves stay TCB.
* **Telemetry-invariance of decisions is a property of THIS model.**
  `arun_decide_tel_invariant` and `arun_tel_parameter` say the model's
  trace semantics cannot make a decide depend on `tel`. They do not prove
  that the deployed host has no stderr feedback path; the absence of a
  stderr read edge is the fidelity INPUT above, taken from `rust/`, not a
  theorem. Both also hold `inputs` FIXED, so they do not model a reader of
  stderr whose behaviour changes the future input stream — the interactive
  operator loop noted above is exactly such a path, and it re-enters only
  as gate state (P8), never as a trace edge.
* **Nothing is claimed about audit CONTENT or confidentiality.** No theorem
  states that any audit line is safe to disclose, that `tel` redacts
  anything, or that the leak `arun_stderr_image` bounds is acceptable. The
  content discipline is the NI row's; the confidentiality residual is
  stated, not discharged.
-/

namespace Host.Audit

open Lean
open Host.Channel
open Host.Perimeter
open Host.Egress

/-! ## The audit-extended alphabet -/

/-- Audit-extended seam event: every egress event, plus the P7 stderr
    telemetry line. The INPUT alphabet stays `EIn` — the deployed host has
    no stderr read edge, so there is nothing for an audit input constructor
    to be faithful to. -/
inductive AEv where
  | audEv (line : String)
  | eev (e : EEv)
  deriving Repr, BEq

/-- Audit-extended trace, most-recent-first (the `ChanTrace` convention). -/
abbrev ATrace := List AEv

/-- Decorate an egress trace with its telemetry: each event's audit lines
    sit directly above the event that drove them (the `eprintln!` fires when
    the host does the thing). This is the whole P7 dynamics — a FUNCTION of
    the egress trace. -/
def weave (tel : EEv → List String) : ETrace → ATrace
  | [] => []
  | e :: rest => (tel e).map AEv.audEv ++ AEv.eev e :: weave tel rest

/-- Erase the telemetry, keep the seam events. -/
def eraseAud : ATrace → ETrace
  | [] => []
  | AEv.eev e :: rest => e :: eraseAud rest
  | AEv.audEv _ :: rest => eraseAud rest

/-- Keep the telemetry, erase the seam events: what a reader of stderr
    holds. -/
def audsOnly : ATrace → List String
  | [] => []
  | AEv.audEv s :: rest => s :: audsOnly rest
  | AEv.eev _ :: rest => audsOnly rest

/-- The telemetry image of an egress trace: every event's audit lines, in
    trace order. -/
def telImage (tel : EEv → List String) : ETrace → List String
  | [] => []
  | e :: rest => tel e ++ telImage tel rest

/-- One audit-extended step: the egress step, with the step's new events
    decorated by their telemetry. The state transition IS the egress state
    transition — stderr is written, never read. -/
def astep (tel : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String)
    (s : A.St × ATrace) (i : EIn) : A.St × ATrace :=
  ((estep A gate author (s.1, ([] : ETrace)) i).1,
   weave tel (estep A gate author (s.1, ([] : ETrace)) i).2 ++ s.2)

/-- An audit-extended run: the egress run under a fixed telemetry function
    `tel : EEv → List String` — the model of "each `eprintln!` is driven by
    what the host just did". -/
def arun (tel : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    A.St × ATrace :=
  inputs.foldl (astep tel A gate author) (A.init, ([] : ATrace))

/-! ## Weave algebra -/

theorem weave_append (tel : EEv → List String) :
    ∀ (a b : ETrace), weave tel (a ++ b) = weave tel a ++ weave tel b := by
  intro a b
  induction a with
  | nil => rfl
  | cons x a ih => simp [weave, ih]

theorem eraseAud_audBlock (l : List String) (tr : ATrace) :
    eraseAud (l.map AEv.audEv ++ tr) = eraseAud tr := by
  induction l with
  | nil => rfl
  | cons s l ih => exact ih

theorem audsOnly_audBlock (l : List String) (tr : ATrace) :
    audsOnly (l.map AEv.audEv ++ tr) = l ++ audsOnly tr := by
  induction l with
  | nil => rfl
  | cons s l ih => exact congrArg (List.cons s) ih

/-- Erasure undoes the weave exactly: the audit widening loses nothing and
    invents nothing at the seam-event level. -/
theorem eraseAud_weave (tel : EEv → List String) :
    ∀ E : ETrace, eraseAud (weave tel E) = E := by
  intro E
  induction E with
  | nil => rfl
  | cons x E' ih =>
    show eraseAud ((tel x).map AEv.audEv ++ AEv.eev x :: weave tel E') = x :: E'
    rw [eraseAud_audBlock]
    show x :: eraseAud (weave tel E') = x :: E'
    rw [ih]

/-- The stderr side of the weave is exactly the telemetry image. -/
theorem audsOnly_weave (tel : EEv → List String) :
    ∀ E : ETrace, audsOnly (weave tel E) = telImage tel E := by
  intro E
  induction E with
  | nil => rfl
  | cons x E' ih =>
    show audsOnly ((tel x).map AEv.audEv ++ AEv.eev x :: weave tel E')
        = tel x ++ telImage tel E'
    rw [audsOnly_audBlock]
    show tel x ++ audsOnly (weave tel E') = tel x ++ telImage tel E'
    rw [ih]

/-- Seam-event membership passes through the weave untouched. -/
theorem eev_mem_weave (tel : EEv → List String) (e : EEv) :
    ∀ E : ETrace, AEv.eev e ∈ weave tel E ↔ e ∈ E := by
  intro E
  induction E with
  | nil => simp [weave]
  | cons x E' ih =>
    show AEv.eev e ∈ (tel x).map AEv.audEv ++ AEv.eev x :: weave tel E'
        ↔ e ∈ x :: E'
    constructor
    · intro h
      rcases List.mem_append.mp h with hl | hr
      · obtain ⟨s, -, hs⟩ := List.mem_map.mp hl
        cases hs
      · rcases List.mem_cons.mp hr with heq | hm
        · injection heq with he
          subst he
          exact List.mem_cons_self
        · exact List.mem_cons_of_mem _ (ih.mp hm)
    · intro h
      rcases List.mem_cons.mp h with heq | hm
      · subst heq
        exact List.mem_append_right _ List.mem_cons_self
      · exact List.mem_append_right _
          (List.mem_cons_of_mem _ (ih.mpr hm))

/-- Audit-line membership: every stderr line traces to a seam event that
    drove it. Stderr says only what the run did. -/
theorem aud_mem_weave (tel : EEv → List String) (s : String) :
    ∀ E : ETrace, AEv.audEv s ∈ weave tel E ↔ ∃ e, e ∈ E ∧ s ∈ tel e := by
  intro E
  induction E with
  | nil => simp [weave]
  | cons x E' ih =>
    show AEv.audEv s ∈ (tel x).map AEv.audEv ++ AEv.eev x :: weave tel E'
        ↔ ∃ e, e ∈ x :: E' ∧ s ∈ tel e
    constructor
    · intro h
      rcases List.mem_append.mp h with hl | hr
      · obtain ⟨s', hs', heq⟩ := List.mem_map.mp hl
        injection heq with he
        subst he
        exact ⟨x, List.mem_cons_self, hs'⟩
      · rcases List.mem_cons.mp hr with heq | hm
        · cases heq
        · obtain ⟨e, he, hs⟩ := ih.mp hm
          exact ⟨e, List.mem_cons_of_mem _ he, hs⟩
    · rintro ⟨e, he, hs⟩
      rcases List.mem_cons.mp he with heq | hm
      · subst heq
        exact List.mem_append_left _ (List.mem_map_of_mem hs)
      · exact List.mem_append_right _
          (List.mem_cons_of_mem _ (ih.mpr ⟨e, hm, hs⟩))

/-! ## Structure: the audit-extended run IS the egress run, decorated -/

/-- The egress step factors over its incoming trace: the new events do not
    depend on it. (Also proved on the P4 lane; restated here so the lanes
    stay import-independent.) -/
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

/-- The audit-extended fold is the egress fold, woven. -/
theorem afold_eq (tel : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) :
    ∀ (inputs : List EIn) (st : A.St) (tr : ATrace),
      inputs.foldl (astep tel A gate author) (st, tr)
        = ((inputs.foldl (estep A gate author) (st, ([] : ETrace))).1,
           weave tel (inputs.foldl (estep A gate author)
             (st, ([] : ETrace))).2 ++ tr) := by
  intro inputs
  induction inputs with
  | nil => intro st tr; simp [weave]
  | cons i rest ih =>
    intro st tr
    rw [List.foldl_cons, List.foldl_cons]
    have hstep : astep tel A gate author (st, tr) i
        = ((estep A gate author (st, ([] : ETrace)) i).1,
           weave tel (estep A gate author (st, ([] : ETrace)) i).2 ++ tr) :=
      rfl
    rw [hstep]
    generalize estep A gate author (st, ([] : ETrace)) i = e
    obtain ⟨st', tr'⟩ := e
    dsimp only
    rw [ih st' (weave tel tr' ++ tr), efold_split A gate author rest st' tr']
    dsimp only
    rw [weave_append]
    simp [List.append_assoc]

/-- **The structure theorem.** The audit-extended run is EXACTLY the egress
    run with each seam event decorated by its telemetry lines: same adapter
    state, and the trace is a plain FUNCTION (`weave tel`) of the egress
    trace. The P7 extension factors through the unextended run — telemetry
    is post-processing, not dynamics. -/
theorem arun_eq (tel : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    arun tel A gate author inputs
      = ((erun A gate author inputs).1,
         weave tel (erun A gate author inputs).2) := by
  have h := afold_eq tel A gate author inputs A.init ([] : ATrace)
  simpa [arun, erun] using h

theorem arun_state_eq (tel : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    (arun tel A gate author inputs).1 = (erun A gate author inputs).1 := by
  rw [arun_eq]

theorem arun_trace_eq (tel : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    (arun tel A gate author inputs).2
      = weave tel (erun A gate author inputs).2 := by
  rw [arun_eq]

/-- Erasing the telemetry from any audit-extended run recovers the egress
    trace exactly — for every telemetry function. -/
theorem arun_erase_eq (tel : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    eraseAud (arun tel A gate author inputs).2
      = (erun A gate author inputs).2 := by
  rw [arun_trace_eq]
  exact eraseAud_weave tel _

/-! ## The P7 verdict, part one — telemetry is a run parameter -/

/-- **The telemetry function is a run PARAMETER, not an observed event.**
    Two audit-extended runs differing ONLY in `tel` have identical adapter
    state and weave the SAME egress trace. The trace semantics cannot
    distinguish — hence cannot be influenced by — what the host tells
    stderr: nothing any gate, adapter, author or input stream does depends
    on or reacts to the telemetry. -/
theorem arun_tel_parameter (tel₁ tel₂ : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    (arun tel₁ A gate author inputs).1 = (arun tel₂ A gate author inputs).1
      ∧ ∃ E : ETrace,
          (arun tel₁ A gate author inputs).2 = weave tel₁ E
          ∧ (arun tel₂ A gate author inputs).2 = weave tel₂ E :=
  ⟨by rw [arun_state_eq, arun_state_eq],
   (erun A gate author inputs).2,
   arun_trace_eq tel₁ A gate author inputs,
   arun_trace_eq tel₂ A gate author inputs⟩

/-! ## The P7 verdict, part two — no input edge into the decision -/

/-- Every seam-event fact of the audit-extended run is a fact of the egress
    run: event membership is `tel`-independent. -/
theorem arun_eev_mem (tel : EEv → List String) (e : EEv) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    AEv.eev e ∈ (arun tel A gate author inputs).2
      ↔ e ∈ (erun A gate author inputs).2 := by
  rw [arun_trace_eq]
  exact eev_mem_weave tel e _

/-- **No event carries information INTO the mediated decision from
    stderr.** The decides of an audit-extended run are identical for every
    pair of telemetry functions — on every adapter, gate, author and input
    stream. -/
theorem arun_decide_tel_invariant (tel₁ tel₂ : EEv → List String)
    (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn)
    (raw : SealV2.RawBytes) (d : SealV2.Decision) :
    AEv.eev (EEv.decideEv raw d) ∈ (arun tel₁ A gate author inputs).2
      ↔ AEv.eev (EEv.decideEv raw d) ∈ (arun tel₂ A gate author inputs).2 :=
  (arun_eev_mem tel₁ _ A gate author inputs).trans
    (arun_eev_mem tel₂ _ A gate author inputs).symm

/-! ## The P7 verdict, part three — every constraint of the GUARDED
    `audGuardedBy` form is vacuous. That is the vacuity of ONE form, NOT of
    every stderr property: `audEv s ∈ tr → C s` is refuted at `C := False`
    on the witness run. -/

/-- A telemetry-fed decision: a decide that EXISTS under one telemetry
    function and is ABSENT under another. This is the only way stderr
    content could reach a mediated decision — the telemetry function is
    stderr's sole degree of freedom in the model, so a decision it fed is a
    decision that varies with it. -/
def audFedDecision (tel₁ tel₂ : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn)
    (raw : SealV2.RawBytes) (d : SealV2.Decision) : Prop :=
  AEv.eev (EEv.decideEv raw d) ∈ (arun tel₁ A gate author inputs).2
    ∧ AEv.eev (EEv.decideEv raw d) ∉ (arun tel₂ A gate author inputs).2

/-- No run has a telemetry-fed decision: the set such a constraint would
    quantify over is EMPTY. -/
theorem aud_no_fed_decision (tel₁ tel₂ : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn)
    (raw : SealV2.RawBytes) (d : SealV2.Decision) :
    ¬ audFedDecision tel₁ tel₂ A gate author inputs raw d := fun h =>
  h.2 ((arun_decide_tel_invariant tel₁ tel₂ A gate author inputs raw d).mp
    h.1)

/-- A candidate stderr-feedback obligation: "every decision stderr fed
    satisfies `C`." This is ONE shape a P7 input-edge property can take —
    the shape whose antecedent is a decision that varies with the
    telemetry. That every such property MUST take this shape is not proved
    here; properties of other shapes are expressible and are not vacuous
    (see `aud_provenance`). -/
def audGuardedBy (C : SealV2.RawBytes → SealV2.Decision → Prop)
    (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) : Prop :=
  ∀ tel₁ tel₂ raw d,
    audFedDecision tel₁ tel₂ A gate author inputs raw d → C raw d

/-- **P7 VACUITY, machine-checked — and labelled as such.** EVERY candidate
    constraint `C` on telemetry-fed decisions is satisfied by every run,
    because no decision of any run is telemetry-fed: the obligation
    quantifies over an EMPTY set. This is `EgressPerimeter.lean`'s prose —
    "stderr has no input edge into routing, so a faithful `audEv` would be
    no-effect by construction" — as a theorem. A VACUOUS result by design:
    the vacuity IS the no-go. Read the scope exactly: the vacuity is a
    property of the GUARDED form `audGuardedBy`, not of every conceivable
    stderr property — `AEv.audEv s ∈ tr → C s` is NOT vacuous, being
    refuted at `C := fun _ => False` by the `relayTel` witness run of
    `aud_non_bypass_fails`. It certifies nothing about what stderr carries
    OUT (see `arun_stderr_image` for that). -/
theorem aud_constraint_vacuous (C : SealV2.RawBytes → SealV2.Decision → Prop)
    (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    audGuardedBy C A gate author inputs := fun tel₁ tel₂ raw d h =>
  absurd h (aud_no_fed_decision tel₁ tel₂ A gate author inputs raw d)

/-- The vacuity at its sharpest instantiation: even the UNSATISFIABLE
    constraint `C := fun _ _ => False` — "no decision stderr fed is ever
    acceptable" — is "satisfied" by every run. A property family whose
    impossible member holds constrains nothing whatsoever. -/
theorem aud_constraint_vacuous_false (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    audGuardedBy (fun _ _ => False) A gate author inputs :=
  aud_constraint_vacuous _ A gate author inputs

/-! ## The asymmetry, stated as theorems — what stderr DOES carry -/

/-- **The stderr image.** What a reader of stderr holds is exactly the
    telemetry image of the ENTIRE egress trace — every decide, emission,
    block, refusal, forward and relay, through `tel`. With an injective
    per-event `tel` (the deployed audit lines carry decision paths, judged
    lines and error details) this is the run's complete mediation
    transcript. P7's residual is CONFIDENTIALITY, not mediation: the leak
    is real, read-only, and bounded by `tel`. -/
theorem arun_stderr_image (tel : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    audsOnly (arun tel A gate author inputs).2
      = telImage tel (erun A gate author inputs).2 := by
  rw [arun_trace_eq]
  exact audsOnly_weave tel _

/-- The upper bound of the leak: every audit line of every run traces to a
    seam event that drove it. Stderr can reveal the run — it cannot reveal
    more than the run. -/
theorem aud_provenance (tel : EEv → List String) (s : String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    AEv.audEv s ∈ (arun tel A gate author inputs).2
      ↔ ∃ e, e ∈ (erun A gate author inputs).2 ∧ s ∈ tel e := by
  rw [arun_trace_eq]
  exact aud_mem_weave tel s _

/-! ## Audit mediation is inherited, never created -/

/-- Audit mediation, in its WEAKEST form (the `relayMediated` analogue):
    every audit line has SOME strictly earlier decision — on any line, of
    any verdict. -/
def audMediated (tr : ATrace) : Prop :=
  ∀ post s pre, tr = post ++ AEv.audEv s :: pre →
    ∃ raw d, AEv.eev (EEv.decideEv raw d) ∈ pre

/-- Relay-driven telemetry: the audit line for a P6 relay (the deployed
    host's per-frame observability idiom). -/
def relayTel : EEv → List String := fun
  | EEv.relayEv _ => ["relay"]
  | _ => []

/-- Decide-driven telemetry: the audit line for a gate decision (the
    deployed host's `authorization_decision` stderr line). -/
def decideTel : EEv → List String := fun
  | EEv.decideEv _ _ => ["decide"]
  | _ => []

/-- **The negative, witness-form** (the P6 shape, NOT the P4 universal:
    audit adjacency depends on which event drove the line). Under
    relay-driven telemetry, audit mediation fails even in its weakest form:
    the audit line's driving event is itself undecided, and the telemetry
    inherits exactly that — extending the alphabet with `audEv` creates no
    new mediated channel. -/
theorem aud_non_bypass_fails (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (c : String) :
    ¬ audMediated (arun relayTel A gate author [EIn.childOut c]).2 := by
  intro hmed
  obtain ⟨raw, d, hd⟩ :=
    hmed [] "relay" [AEv.eev (EEv.relayEv c)] rfl
  rcases List.mem_cons.mp hd with heq | h0
  · injection heq with he
    cases he
  · cases h0

/-- The negative pinned at the deployed model and the LIVE gate. -/
theorem aud_non_bypass_fails_live (state : SealV2.ApprovalState)
    (author : CanonicalAction → String) (c : String) :
    ¬ audMediated
        (arun relayTel sealAdapter (fun raw => SealV2.decide raw state)
          author [EIn.childOut c]).2 :=
  aud_non_bypass_fails sealAdapter _ author c

/-- Splitting a weave at an audit line lands inside the audit block of the
    event that drove it: the driving event sits strictly below the line. -/
theorem audBlock_split_aud (s : String) :
    ∀ (l : List String) (rest post pre : ATrace),
      l.map AEv.audEv ++ rest = post ++ AEv.audEv s :: pre →
      (∃ l₂ : List String, s ∈ l ∧ pre = l₂.map AEv.audEv ++ rest)
      ∨ (∃ post', post = l.map AEv.audEv ++ post'
          ∧ rest = post' ++ AEv.audEv s :: pre) := by
  intro l
  induction l with
  | nil =>
    intro rest post pre h
    exact Or.inr ⟨post, by simp, by simpa using h⟩
  | cons t l ih =>
    intro rest post pre h
    simp only [List.map_cons, List.cons_append] at h
    cases post with
    | nil =>
      rw [List.nil_append] at h
      injection h with h1 h2
      injection h1 with hts
      subst hts
      exact Or.inl ⟨l, List.mem_cons_self, h2.symm⟩
    | cons p ps =>
      rw [List.cons_append] at h
      injection h with h1 h2
      rcases ih rest ps pre h2 with ⟨l₂, hs, hpre⟩ | ⟨post', hps, hrest⟩
      · exact Or.inl ⟨l₂, List.mem_cons_of_mem _ hs, hpre⟩
      · subst h1
        exact Or.inr ⟨post', by simp [hps], hrest⟩

/-- Splitting any weave at any audit line: the line belongs to some event
    `e`, and `e` sits strictly below it in the trace. -/
theorem weave_split_aud (tel : EEv → List String) (s : String) :
    ∀ (E : ETrace) (post pre : ATrace),
      weave tel E = post ++ AEv.audEv s :: pre →
      ∃ (e : EEv) (E₂ : ETrace) (l₂ : List String), s ∈ tel e
        ∧ pre = l₂.map AEv.audEv ++ AEv.eev e :: weave tel E₂ := by
  intro E
  induction E with
  | nil =>
    intro post pre h
    cases post <;> simp [weave] at h
  | cons x E' ih =>
    intro post pre h
    have h' : (tel x).map AEv.audEv ++ (AEv.eev x :: weave tel E')
        = post ++ AEv.audEv s :: pre := h
    rcases audBlock_split_aud s (tel x) _ post pre h' with
      ⟨l₂, hs, hpre⟩ | ⟨post', -, hrest⟩
    · exact ⟨x, E', l₂, hs, hpre⟩
    · cases post' with
      | nil =>
        rw [List.nil_append] at hrest
        injection hrest with h1 h2
        cases h1
      | cons q qs =>
        rw [List.cons_append] at hrest
        injection hrest with h1 h2
        exact ih qs pre h2

/-- **The positive counterpoint.** Under decide-driven telemetry, audit
    mediation HOLDS on every run, at every adapter, gate, author and input
    stream: the audit line sits directly above the decide that drove it.
    Together with `aud_non_bypass_fails`: whether telemetry is
    decision-preceded is a property of the DRIVING EVENT, not of the stderr
    channel — the P7 widening imposes nothing and forbids nothing of its
    own. -/
theorem aud_decide_tel_mediated (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    audMediated (arun decideTel A gate author inputs).2 := by
  intro post s pre heq
  rw [arun_trace_eq] at heq
  obtain ⟨e, E₂, l₂, hmem, hpre⟩ :=
    weave_split_aud decideTel s _ post pre heq
  cases e with
  | decideEv raw d =>
    exact ⟨raw, d, by
      rw [hpre]
      exact List.mem_append_right _ List.mem_cons_self⟩
  | emitEv b => exact absurd hmem (by simp [decideTel])
  | fwdEv r => exact absurd hmem (by simp [decideTel])
  | refuseEv r => exact absurd hmem (by simp [decideTel])
  | blockEv r b => exact absurd hmem (by simp [decideTel])
  | relayEv cb => exact absurd hmem (by simp [decideTel])

/-! ## The salvage — the widening breaks nothing, for every telemetry -/

/-- An audit block contains no seam event: a split at a seam event must
    skip past it whole. -/
theorem audBlock_skip_eev (e : EEv) :
    ∀ (l : List String) (rest post pre : ATrace),
      l.map AEv.audEv ++ rest = post ++ AEv.eev e :: pre →
      ∃ post', post = l.map AEv.audEv ++ post'
        ∧ rest = post' ++ AEv.eev e :: pre := by
  intro l
  induction l with
  | nil =>
    intro rest post pre h
    exact ⟨post, by simp, by simpa using h⟩
  | cons t l ih =>
    intro rest post pre h
    simp only [List.map_cons, List.cons_append] at h
    cases post with
    | nil =>
      rw [List.nil_append] at h
      injection h with h1 h2
      cases h1
    | cons p ps =>
      rw [List.cons_append] at h
      injection h with h1 h2
      obtain ⟨post', hps, hrest⟩ := ih rest ps pre h2
      subst h1
      exact ⟨post', by simp [hps], hrest⟩

/-- Splitting a weave at a seam event: the split lands between two egress
    events, with the weave of the lower part intact (the event's own audit
    lines sit ABOVE it, on the `post` side). -/
theorem weave_split_eev (tel : EEv → List String) (e : EEv) :
    ∀ (E : ETrace) (post pre : ATrace),
      weave tel E = post ++ AEv.eev e :: pre →
      ∃ post' pre', E = post' ++ e :: pre' ∧ pre = weave tel pre' := by
  intro E
  induction E with
  | nil =>
    intro post pre h
    cases post <;> simp [weave] at h
  | cons x E' ih =>
    intro post pre h
    have h' : (tel x).map AEv.audEv ++ (AEv.eev x :: weave tel E')
        = post ++ AEv.eev e :: pre := h
    obtain ⟨post₂, -, hrest⟩ := audBlock_skip_eev e (tel x) _ post pre h'
    cases post₂ with
    | nil =>
      rw [List.nil_append] at hrest
      injection hrest with h1 h2
      injection h1 with hxe
      exact ⟨[], E', by simp [hxe], h2.symm⟩
    | cons q qs =>
      rw [List.cons_append] at hrest
      injection hrest with h1 h2
      obtain ⟨post', pre', hE, hpre⟩ := ih qs pre h2
      exact ⟨x :: post', pre', by simp [hE], hpre⟩

/-- The P5 mediation property over the audit-extended trace. -/
def blocksPrecededByDecideA (tr : ATrace) : Prop :=
  ∀ post raw b pre, tr = post ++ AEv.eev (EEv.blockEv raw b) :: pre →
    AEv.eev (EEv.decideEv raw SealV2.Decision.Block) ∈ pre

/-- **The P5 capstone survives the audit widening, for EVERY telemetry
    function.** Every client-bound block emission on an audit-extended run
    is still preceded by its own `Block` decide, whatever the host tells
    stderr. The guarantee is `tel`-invariant — which is exactly why the
    telemetry cannot constrain, or be constrained by, the decision. -/
theorem arun_client_block_mediated (tel : EEv → List String) (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    blocksPrecededByDecideA (arun tel A gate author inputs).2 := by
  intro post raw b pre heq
  rw [arun_trace_eq] at heq
  obtain ⟨post', pre', hE, hpre⟩ :=
    weave_split_eev tel (EEv.blockEv raw b) _ post pre heq
  have hdec := client_block_mediated A gate author inputs post' raw b pre' hE
  rw [hpre]
  exact (eev_mem_weave tel _ pre').mpr hdec

/-- The capstone transfer at the deployed model and the LIVE gate. -/
theorem arun_client_block_mediated_live (tel : EEv → List String)
    (state : SealV2.ApprovalState)
    (author : CanonicalAction → String) (inputs : List EIn) :
    blocksPrecededByDecideA
      (arun tel sealAdapter (fun raw => SealV2.decide raw state)
        author inputs).2 :=
  arun_client_block_mediated tel sealAdapter _ author inputs

/-! ## Concrete runs, compiler-evaluated -/

/-- Test telemetry: one distinct audit line per event class, so the
    `#guard`s can pin placement and image. -/
def testTel : EEv → List String := fun
  | EEv.decideEv _ _ => ["aud:decide"]
  | EEv.emitEv _ => ["aud:emit"]
  | EEv.fwdEv _ => ["aud:fwd"]
  | EEv.refuseEv _ => ["aud:refuse"]
  | EEv.blockEv _ _ => ["aud:block"]
  | EEv.relayEv _ => ["aud:relay"]

/-- Silent telemetry: the host that says nothing. -/
def silentTel : EEv → List String := fun _ => []

-- Each audit line sits directly above the event that drove it; the seam
-- events stack exactly as in `EgressPerimeter.lean`'s #guards:
#guard (arun testTel sealAdapter allowMediatedGate testAuthor
    [EIn.clientLine mediatedWitness, EIn.childOut "{\"result\":1}"]).2
  == [AEv.audEv "aud:relay", AEv.eev (EEv.relayEv "{\"result\":1}"),
      AEv.audEv "aud:emit", AEv.eev (EEv.emitEv "OK"),
      AEv.audEv "aud:decide",
      AEv.eev (EEv.decideEv mediatedWitness (SealV2.Decision.Allow "OK"))]
-- The silent host: the audit widening degenerates to the bare egress run:
#guard (arun silentTel sealAdapter allowMediatedGate testAuthor
    [EIn.clientLine mediatedWitness]).2
  == [AEv.eev (EEv.emitEv "OK"),
      AEv.eev (EEv.decideEv mediatedWitness (SealV2.Decision.Allow "OK"))]
-- Two different telemetry functions, same inputs: identical after erasure —
-- the tel-parameter theorem, concretely:
#guard eraseAud (arun testTel sealAdapter allowMediatedGate testAuthor
    [EIn.clientLine mediatedWitness, EIn.childOut "{\"result\":1}"]).2
  == eraseAud (arun silentTel sealAdapter allowMediatedGate testAuthor
    [EIn.clientLine mediatedWitness, EIn.childOut "{\"result\":1}"]).2
-- The stderr image of a blocked act-line: the reader of stderr sees the
-- block and its decide — the leak is the seam history, nothing else:
#guard audsOnly (arun testTel sealAdapter blockGate testAuthor
    [EIn.clientLine mediatedWitness]).2
  == ["aud:block", "aud:decide"]

/-! ## Axiom pins

Classical baseline `[propext, Classical.choice, Quot.sound]` or tighter —
no `sorryAx`, no `native_decide`, no custom axiom. -/

/-- info: 'Host.Audit.estep_split' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms estep_split
/-- info: 'Host.Audit.efold_split' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms efold_split
/-- info: 'Host.Audit.weave_append' depends on axioms: [propext] -/
#guard_msgs in #print axioms weave_append
/-- info: 'Host.Audit.eraseAud_audBlock' does not depend on any axioms -/
#guard_msgs in #print axioms eraseAud_audBlock
/-- info: 'Host.Audit.audsOnly_audBlock' does not depend on any axioms -/
#guard_msgs in #print axioms audsOnly_audBlock
/-- info: 'Host.Audit.eraseAud_weave' does not depend on any axioms -/
#guard_msgs in #print axioms eraseAud_weave
/-- info: 'Host.Audit.audsOnly_weave' does not depend on any axioms -/
#guard_msgs in #print axioms audsOnly_weave
/-- info: 'Host.Audit.eev_mem_weave' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms eev_mem_weave
/-- info: 'Host.Audit.aud_mem_weave' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms aud_mem_weave
/-- info: 'Host.Audit.afold_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms afold_eq
/-- info: 'Host.Audit.arun_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms arun_eq
/-- info: 'Host.Audit.arun_state_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms arun_state_eq
/-- info: 'Host.Audit.arun_trace_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms arun_trace_eq
/-- info: 'Host.Audit.arun_erase_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms arun_erase_eq
/-- info: 'Host.Audit.arun_tel_parameter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms arun_tel_parameter
/-- info: 'Host.Audit.arun_eev_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms arun_eev_mem
/-- info: 'Host.Audit.arun_decide_tel_invariant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms arun_decide_tel_invariant
/-- info: 'Host.Audit.aud_no_fed_decision' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms aud_no_fed_decision
/-- info: 'Host.Audit.aud_constraint_vacuous' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms aud_constraint_vacuous
/-- info: 'Host.Audit.aud_constraint_vacuous_false' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms aud_constraint_vacuous_false
/-- info: 'Host.Audit.arun_stderr_image' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms arun_stderr_image
/-- info: 'Host.Audit.aud_provenance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms aud_provenance
/-- info: 'Host.Audit.aud_non_bypass_fails' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms aud_non_bypass_fails
/-- info: 'Host.Audit.aud_non_bypass_fails_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms aud_non_bypass_fails_live
/-- info: 'Host.Audit.audBlock_split_aud' depends on axioms: [propext] -/
#guard_msgs in #print axioms audBlock_split_aud
/-- info: 'Host.Audit.weave_split_aud' depends on axioms: [propext] -/
#guard_msgs in #print axioms weave_split_aud
/-- info: 'Host.Audit.aud_decide_tel_mediated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms aud_decide_tel_mediated
/-- info: 'Host.Audit.audBlock_skip_eev' depends on axioms: [propext] -/
#guard_msgs in #print axioms audBlock_skip_eev
/-- info: 'Host.Audit.weave_split_eev' depends on axioms: [propext] -/
#guard_msgs in #print axioms weave_split_eev
/-- info: 'Host.Audit.arun_client_block_mediated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms arun_client_block_mediated
/-- info: 'Host.Audit.arun_client_block_mediated_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms arun_client_block_mediated_live

end Host.Audit
