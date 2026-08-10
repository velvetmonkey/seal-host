/- SPDX-License-Identifier: Apache-2.0 -/

import Host.PassthroughPerimeter

/-!
# Option A, measured: the strict perimeter closes the P1 forward

`Host/PassthroughPerimeter.lean` proves the honest negative: at the deployed
router, EVERY escaping line breaks `mediatedChildBound` — the passthrough IS a
bypass of the child-input link (`widened_non_bypass_fails`). `CLAIMS.md`
records the open fork: Option A refuses every escaping line before it reaches
the child, paying a protocol-compatibility cost; Option B keeps the relay.
Nobody had established whether Option A actually CLOSES the gap. This module
answers that.

## The strict variant

`strictStep`/`strictRun` are NEW definitions alongside `wstep`/`wrun` —
nothing existing is modified. The router is still the deployed
`Host.classifyLine`; the ONLY change is the `.passthrough` branch, which now
refuses (client-bound block, `refuseEv`) instead of forwarding (`fwdEv`).
`.refuse` and `.act` are byte-identical to `wstep`.

## The verdict, in one paragraph

**Option A closes the child-input gap, and the closure is machine-checked
here.** On strict runs no `fwdEv` ever exists (`strictRun_no_fwd` — every
adapter, every gate), so the forward half of `mediatedChildBound` holds
universally; the emission half holds for every adapter satisfying the O1∧O2
gated-sink obligations (`strict_mediatedChildBound`), discharged at the
deployed model and the live gate by `strict_mediatedChildBound_live`. The
O1∧O2 hypothesis is NOT removable: `strict_fails_for_rogue_adapter` proves a
one-line rogue adapter (emits unlicensed bytes) breaks `mediatedChildBound`
even under the strict host — Option A closes the P1 forward leg and ONLY
that leg; the gated-sink obligations remain load-bearing exactly as before.

## Non-vacuity (mandatory here, witness discipline as in the parent module)

The strict variant does not refuse everything. `strictRun_decide_iff` proves
it still gate-decides EXACTLY the perimeter S (`inPerimeter`), for every
adapter and gate — the same decide surface as the deployed `wrun` — and
`strictRun_refuse_iff` proves it refuses EXACTLY `R ∪ escapes`, which
quantifies Option A's compatibility cost: the newly-refused class is
precisely `escapes`, nothing more. `Lean.Json.parse` is `partial`, so
concrete classifications are compiler-evaluated `#guard`s (the parent
module's witness discipline): the mediated witness still decides and emits,
each escaping witness is refused not forwarded, and a mixed stream shows
both behaviours side by side.

## HONESTY

Model-level only, exactly like the parent module: P1 is closed IN THE MODEL;
P4–P9 stay uncovered, and the `rust/` ↔ model byte refinement remains the
conformance-bridge obligation. No deployed binary implements `strictStep`
today — this module is the evidence FOR the fork decision, not a claim about
shipped behaviour.
-/

namespace Host.Perimeter

open Lean
open Host.Channel

/-! ## The strict variant (Option A) -/

/-- **Option A as a transition system.** Identical to `wstep` except the
    `.passthrough` branch: an escaping line is REFUSED (client-bound block,
    nothing forwarded) instead of relayed child-bound. The router is still
    the deployed `Host.classifyLine`; only the P1 disposition changes. -/
def strictStep (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (s : A.St × WTrace) (line : String) : A.St × WTrace :=
  match Host.classifyLine line with
  | .passthrough => (s.1, WEv.refuseEv line :: s.2)
  | .refuse => (s.1, WEv.refuseEv line :: s.2)
  | .act _ =>
      let st' := A.onVerdict s.1 line (gate line)
      (st', (A.emitsOn st').map WEv.emitEv ++ WEv.decideEv line (gate line) :: s.2)

/-- A strict run over an input stream, from the adapter's initial state and
    the empty trace. -/
def strictRun (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (inputs : List String) : A.St × WTrace :=
  inputs.foldl (strictStep A gate) (A.init, ([] : WTrace))

/-- Perimeter membership excludes the refused class (the missing third
    exclusion lemma; the parent module has the other direction). -/
theorem refusedClass_eq_false_of_inPerimeter {line : String}
    (h : inPerimeter line = true) : refusedClass line = false := by
  unfold inPerimeter at h
  unfold refusedClass
  have h2 := (Bool.and_eq_true _ _).mp h
  simp [h2.1]

/-! ## No forward exists — the closed leg, every adapter, every gate -/

/-- A strict step NEVER adds a forward event: forward membership is
    untouched, whatever the line's class. -/
theorem strictStep_fwd_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (s : A.St × WTrace)
    (line raw : String) :
    WEv.fwdEv raw ∈ (strictStep A gate s line).2 ↔ WEv.fwdEv raw ∈ s.2 := by
  unfold strictStep
  cases h : Host.classifyLine line with
  | passthrough => simp [List.mem_cons]
  | refuse => simp [List.mem_cons]
  | act a => simp [List.mem_append, List.mem_map, List.mem_cons]

/-- Forward membership over a strict fold from any start state. -/
theorem strictRun_from_fwd_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (raw : String) :
    ∀ (inputs : List String) (s : A.St × WTrace),
      WEv.fwdEv raw ∈ (inputs.foldl (strictStep A gate) s).2 ↔
        WEv.fwdEv raw ∈ s.2 := by
  intro inputs
  induction inputs with
  | nil => intro s; simp
  | cons line rest ih =>
    intro s
    rw [List.foldl_cons, ih (strictStep A gate s line), strictStep_fwd_mem]

/-- **The closed leg.** A strict run contains NO forward event at all — for
    EVERY adapter and EVERY gate. Under Option A nothing is ever child-bound
    undecided; contrast `wrun_fwd_iff`, where every input in `escapes` is. -/
theorem strictRun_no_fwd (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (inputs : List String)
    (raw : String) :
    WEv.fwdEv raw ∉ (strictRun A gate inputs).2 := by
  unfold strictRun
  rw [strictRun_from_fwd_mem]
  simp

/-! ## The decide surface is unchanged — non-vacuity, theorem layer -/

/-- A strict step adds a decide event for `raw` iff `raw` is the line
    processed AND that line lies in S — byte-identical statement to
    `wstep_decide_mem`: strictening the passthrough does not move the
    decide surface. -/
theorem strictStep_decide_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (s : A.St × WTrace)
    (line raw : String) (d : SealV2.Decision) :
    WEv.decideEv raw d ∈ (strictStep A gate s line).2 ↔
      WEv.decideEv raw d ∈ s.2
        ∨ (raw = line ∧ d = gate line ∧ inPerimeter line = true) := by
  unfold strictStep
  cases h : Host.classifyLine line with
  | passthrough =>
    have hip : inPerimeter line = false :=
      inPerimeter_eq_false_of_escapes ((classifyLine_passthrough_iff line).mp h)
    simp [List.mem_cons, hip]
  | refuse =>
    have hip : inPerimeter line = false :=
      inPerimeter_eq_false_of_refused ((classifyLine_refuse_iff line).mp h)
    simp [List.mem_cons, hip]
  | act a =>
    have hip : inPerimeter line = true :=
      (classifyLine_act_iff line).mp ⟨a, h⟩
    constructor
    · intro hmem
      rcases List.mem_append.mp hmem with hl | hr
      · obtain ⟨b, -, hbe⟩ := List.mem_map.mp hl
        cases hbe
      · rcases List.mem_cons.mp hr with heq | hmem'
        · injection heq with h1 h2
          subst h1; subst h2
          exact Or.inr ⟨rfl, rfl, hip⟩
        · exact Or.inl hmem'
    · rintro (hmem' | ⟨rfl, rfl, -⟩)
      · exact List.mem_append_right _ (List.mem_cons_of_mem _ hmem')
      · exact List.mem_append_right _ List.mem_cons_self

/-- Decide membership over a strict fold from any start state. -/
theorem strictRun_from_decide_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (raw : String)
    (d : SealV2.Decision) :
    ∀ (inputs : List String) (s : A.St × WTrace),
      WEv.decideEv raw d ∈ (inputs.foldl (strictStep A gate) s).2 ↔
        WEv.decideEv raw d ∈ s.2
          ∨ (raw ∈ inputs ∧ d = gate raw ∧ inPerimeter raw = true) := by
  intro inputs
  induction inputs with
  | nil => intro s; simp
  | cons line rest ih =>
    intro s
    rw [List.foldl_cons, ih (strictStep A gate s line), strictStep_decide_mem]
    constructor
    · rintro ((hmem | ⟨rfl, rfl, hip⟩) | ⟨hin, rfl, hip⟩)
      · exact Or.inl hmem
      · exact Or.inr ⟨List.mem_cons_self, rfl, hip⟩
      · exact Or.inr ⟨List.mem_cons_of_mem _ hin, rfl, hip⟩
    · rintro (hmem | ⟨hin, rfl, hip⟩)
      · exact Or.inl (Or.inl hmem)
      · rcases List.mem_cons.mp hin with rfl | hin'
        · exact Or.inl (Or.inr ⟨rfl, rfl, hip⟩)
        · exact Or.inr ⟨hin', rfl, hip⟩

/-- **Non-vacuity, decide side.** A strict run gate-decides a line iff it
    was input AND lies in S — the SAME decide surface as the deployed
    `wrun_decide_iff`, for every adapter and every gate. Option A does not
    refuse everything: ordinary `tools/call` traffic is still decided. -/
theorem strictRun_decide_iff (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (inputs : List String)
    (raw : String) :
    (∃ d, WEv.decideEv raw d ∈ (strictRun A gate inputs).2) ↔
      raw ∈ inputs ∧ inPerimeter raw = true := by
  unfold strictRun
  constructor
  · rintro ⟨d, hd⟩
    rcases (strictRun_from_decide_mem A gate raw d inputs _).mp hd with
      h0 | ⟨hin, -, hip⟩
    · nomatch h0
    · exact ⟨hin, hip⟩
  · rintro ⟨hin, hip⟩
    exact ⟨gate raw, (strictRun_from_decide_mem A gate raw (gate raw) inputs _).mpr
      (Or.inr ⟨hin, rfl, hip⟩)⟩

/-! ## The refusal surface — the compatibility cost, exactly -/

/-- A strict step adds a refusal for `raw` iff `raw` is the line processed
    AND that line is refused-or-escaping. -/
theorem strictStep_refuse_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (s : A.St × WTrace)
    (line raw : String) :
    WEv.refuseEv raw ∈ (strictStep A gate s line).2 ↔
      WEv.refuseEv raw ∈ s.2
        ∨ (raw = line ∧ (refusedClass line || escapes line) = true) := by
  unfold strictStep
  cases h : Host.classifyLine line with
  | passthrough =>
    have hesc := (classifyLine_passthrough_iff line).mp h
    rw [List.mem_cons]
    simp only [WEv.refuseEv.injEq, hesc, Bool.or_true, and_true]
    exact or_comm
  | refuse =>
    have hrf := (classifyLine_refuse_iff line).mp h
    rw [List.mem_cons]
    simp only [WEv.refuseEv.injEq, hrf, Bool.true_or, and_true]
    exact or_comm
  | act a =>
    have hip : inPerimeter line = true :=
      (classifyLine_act_iff line).mp ⟨a, h⟩
    have hrf : refusedClass line = false :=
      refusedClass_eq_false_of_inPerimeter hip
    have hesc : escapes line = false := escapes_eq_false_of_inPerimeter hip
    simp [List.mem_append, List.mem_map, List.mem_cons, hrf, hesc]

/-- Refusal membership over a strict fold from any start state. -/
theorem strictRun_from_refuse_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (raw : String) :
    ∀ (inputs : List String) (s : A.St × WTrace),
      WEv.refuseEv raw ∈ (inputs.foldl (strictStep A gate) s).2 ↔
        WEv.refuseEv raw ∈ s.2
          ∨ (raw ∈ inputs ∧ (refusedClass raw || escapes raw) = true) := by
  intro inputs
  induction inputs with
  | nil => intro s; simp
  | cons line rest ih =>
    intro s
    rw [List.foldl_cons, ih (strictStep A gate s line), strictStep_refuse_mem]
    constructor
    · rintro ((hmem | ⟨rfl, hcl⟩) | ⟨hin, hcl⟩)
      · exact Or.inl hmem
      · exact Or.inr ⟨List.mem_cons_self, hcl⟩
      · exact Or.inr ⟨List.mem_cons_of_mem _ hin, hcl⟩
    · rintro (hmem | ⟨hin, hcl⟩)
      · exact Or.inl (Or.inl hmem)
      · rcases List.mem_cons.mp hin with rfl | hin'
        · exact Or.inl (Or.inr ⟨rfl, hcl⟩)
        · exact Or.inr ⟨hin', hcl⟩

/-- **The compatibility cost, exactly.** A strict run refuses a line iff it
    was input AND lies in `R ∪ escapes` — so the class Option A newly
    refuses (relative to the deployed host, which refuses exactly R) is
    PRECISELY `escapes`, nothing more. For every adapter and every gate. -/
theorem strictRun_refuse_iff (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (inputs : List String)
    (raw : String) :
    WEv.refuseEv raw ∈ (strictRun A gate inputs).2 ↔
      raw ∈ inputs ∧ (refusedClass raw || escapes raw) = true := by
  unfold strictRun
  rw [strictRun_from_refuse_mem]
  simp

/-! ## Single-line shapes (used by the no-go and the escape-closure) -/

/-- An escaping line under the strict host: refused, nothing forwarded,
    nothing decided — for every adapter and gate. Contrast
    `wrun_single_passthrough`. -/
theorem strictRun_single_escape (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (line : String)
    (hesc : escapes line = true) :
    (strictRun A gate [line]).2 = [WEv.refuseEv line] := by
  have h : Host.classifyLine line = .passthrough :=
    (classifyLine_passthrough_iff line).mpr hesc
  simp [strictRun, strictStep, h]

/-- An act-classified line at an allowing gate behaves under the strict host
    EXACTLY as under the deployed one: decided, then emitted — the mediated
    path is untouched (compare `wrun_single_act_allow`). -/
theorem strictRun_single_act_allow (gate : SealV2.RawBytes → SealV2.Decision)
    (line : String) (a : CanonicalAction) (out : SealV2.CanonicalBytes)
    (h : Host.classifyLine line = .act a) (hg : gate line = .Allow out) :
    (strictRun sealAdapter gate [line]).2
      = [WEv.emitEv out, WEv.decideEv line (.Allow out)] := by
  simp [strictRun, strictStep, h, hg, sealAdapter]

/-- **The exact sentence the deployed host falsifies, made true.** For the
    same escaping lines that break `mediatedChildBound` under `wrun`
    (`widened_non_bypass_fails`), the strict host SATISFIES it — for every
    adapter and every gate: the lone refusal event carries no emission and
    no forward, so both obligations hold. -/
theorem strict_escape_closed (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (line : String)
    (hesc : escapes line = true) :
    mediatedChildBound (strictRun A gate [line]).2 := by
  rw [strictRun_single_escape A gate line hesc]
  constructor
  · intro post b pre heq
    have hmem : WEv.emitEv b ∈ [WEv.refuseEv line] := by
      rw [heq]; exact List.mem_append_right post List.mem_cons_self
    cases List.mem_singleton.mp hmem
  · intro post r pre heq
    have hmem : WEv.fwdEv r ∈ [WEv.refuseEv line] := by
      rw [heq]; exact List.mem_append_right post List.mem_cons_self
    cases List.mem_singleton.mp hmem

/-! ## The capstone: Option A closes the full child-input link -/

/-- The license invariant and guardedness survive every STRICT step — the
    refusal (of either the refused class or an escaping line) touches
    neither the adapter state nor the emission obligations. Mirror of
    `wrun_invariant`. -/
theorem strictRun_invariant (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (hO1 : O1 A) (hO2 : O2 A) :
    ∀ (inputs : List String) (s : A.St × WTrace),
      (∀ p ∈ A.licensed s.1,
        WEv.decideEv p.1 (SealV2.Decision.Allow p.2) ∈ s.2) →
      GuardedW s.2 →
      (∀ p ∈ A.licensed (inputs.foldl (strictStep A gate) s).1,
        WEv.decideEv p.1 (SealV2.Decision.Allow p.2)
          ∈ (inputs.foldl (strictStep A gate) s).2) ∧
      GuardedW (inputs.foldl (strictStep A gate) s).2 := by
  intro inputs
  induction inputs with
  | nil => intro s h1 h2; exact ⟨h1, h2⟩
  | cons line rest ih =>
    intro s h1 h2
    rw [List.foldl_cons]
    cases h : Host.classifyLine line with
    | passthrough =>
      apply ih
      · intro p hp
        simp only [strictStep, h] at hp ⊢
        exact List.mem_cons_of_mem _ (h1 p hp)
      · simp only [strictStep, h]
        exact h2
    | refuse =>
      apply ih
      · intro p hp
        simp only [strictStep, h] at hp ⊢
        exact List.mem_cons_of_mem _ (h1 p hp)
      · simp only [strictStep, h]
        exact h2
    | act a =>
      apply ih
      · intro p hp
        simp only [strictStep, h] at hp ⊢
        rcases hO2.2 s.1 line (gate line) p hp with hold | ⟨out, hd, rfl⟩
        · exact List.mem_append_right _ (List.mem_cons_of_mem _ (h1 p hold))
        · refine List.mem_append_right _ ?_
          rw [hd]
          exact List.mem_cons_self
      · simp only [strictStep, h]
        apply guardedW_append_emits
        · intro b hb
          obtain ⟨raw', hlic⟩ :=
            hO1 (A.onVerdict s.1 line (gate line)) b hb
          rcases hO2.2 s.1 line (gate line) (raw', b) hlic with
            hold | ⟨out, hd, hpair⟩
          · exact ⟨raw', List.mem_cons_of_mem _ (h1 _ hold)⟩
          · have hb2 : b = out := congrArg Prod.snd hpair
            refine ⟨line, ?_⟩
            rw [hb2, hd]
            exact List.mem_cons_self
        · exact h2

/-- Gated-sink mediation on every strict run, for any O1∧O2 adapter at any
    gate — the emission half of the capstone. -/
theorem strict_gated_sink_non_bypass (A : Adapter)
    (hO1 : O1 A) (hO2 : O2 A)
    (gate : SealV2.RawBytes → SealV2.Decision) (inputs : List String) :
    emitsPrecededByAllowW (strictRun A gate inputs).2 := by
  have h := strictRun_invariant A gate hO1 hO2 inputs (A.init, [])
    (fun p hp => nomatch (hO2.1 ▸ hp)) trivial
  exact guardedW_precededByAllow _ h.2

/-- **THE ANSWER: Option A closes the gap.** For every adapter satisfying
    the gated-sink obligations O1∧O2, at EVERY gate, over EVERY input
    stream, the strict run satisfies `mediatedChildBound` — the very
    property `widened_non_bypass_fails` proves NO gate can give the deployed
    host. Both halves of the full child-input link: every emission is
    Allow-preceded (O1∧O2 leg), and the forward obligation holds because no
    forward event exists at all (`strictRun_no_fwd`, adapter-free). -/
theorem strict_mediatedChildBound (A : Adapter) (hO1 : O1 A) (hO2 : O2 A)
    (gate : SealV2.RawBytes → SealV2.Decision) (inputs : List String) :
    mediatedChildBound (strictRun A gate inputs).2 :=
  ⟨fun post b pre heq =>
      strict_gated_sink_non_bypass A hO1 hO2 gate inputs post b pre heq,
   fun post r pre heq =>
      absurd
        (by rw [heq]; exact List.mem_append_right post List.mem_cons_self)
        (strictRun_no_fwd A gate inputs r)⟩

/-- The capstone at the deployed adapter model and the LIVE gate — the
    strict counterpart of `widened_non_bypass_fails_live`, with the verdict
    inverted. -/
theorem strict_mediatedChildBound_live (state : SealV2.ApprovalState)
    (inputs : List String) :
    mediatedChildBound
      (strictRun sealAdapter (fun raw => SealV2.decide raw state) inputs).2 :=
  strict_mediatedChildBound sealAdapter sealAdapter_O1 sealAdapter_O2 _ inputs

/-! ## The proven no-go: "every adapter" is FALSE, and exactly why -/

/-- A one-line rogue adapter: ignores every verdict and emits fixed
    unlicensed bytes. Violates O1 (emits without a license) — the point of
    the no-go below. -/
def rogueAdapter : Adapter where
  St := Unit
  init := ()
  onVerdict := fun _ _ _ => ()
  emitsOn := fun _ => ["ROGUE"]
  licensed := fun _ => []

/-- **The residual, machine-checked.** `mediatedChildBound` does NOT hold
    for every adapter under the strict host: the rogue adapter breaks it on
    any perimeter line at the blocking gate — its unlicensed emission has no
    prior Allow. So Option A closes the P1 forward leg and ONLY that leg;
    the O1∧O2 hypothesis in the capstone is not removable, exactly as in the
    pre-existing gated-sink salvage. -/
theorem strict_fails_for_rogue_adapter (line : String)
    (hip : inPerimeter line = true) :
    ¬ mediatedChildBound (strictRun rogueAdapter blockGate [line]).2 := by
  obtain ⟨a, ha⟩ := (classifyLine_act_iff line).mpr hip
  intro h
  have htr : (strictRun rogueAdapter blockGate [line]).2
      = [WEv.emitEv "ROGUE", WEv.decideEv line SealV2.Decision.Block] := by
    simp [strictRun, strictStep, ha, rogueAdapter, blockGate]
  obtain ⟨raw, hraw⟩ :=
    h.1 [] "ROGUE" [WEv.decideEv line SealV2.Decision.Block]
      (by rw [htr]; rfl)
  have := List.mem_singleton.mp hraw
  simp at this

/-! ## Non-vacuity witnesses (compiler-evaluated, the parent module's
    witness discipline: `Json.parse` is `partial`, so the kernel cannot
    reduce concrete classifications — `#guard`s pin them, theorems carry
    the generic shape) -/

/-- Non-vacuity at the theorem layer: any perimeter line is still decided by
    the strict host, at every adapter and every gate. Instantiated
    concretely by the `#guard`s below (`inPerimeter mediatedWitness` is
    compiler-pinned in the parent module and re-pinned here). -/
theorem strict_option_a_nonvacuous (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (line : String)
    (hip : inPerimeter line = true) :
    ∃ d, WEv.decideEv line d ∈ (strictRun A gate [line]).2 :=
  (strictRun_decide_iff A gate [line] line).mpr ⟨List.mem_cons_self, hip⟩

-- The perimeter witness is still in S (re-pinned; also pinned in the parent):
#guard inPerimeter mediatedWitness
-- Ordinary traffic still decides and emits under the strict host — the run
-- is byte-identical to the deployed `wrun` on mediated input:
#guard (strictRun sealAdapter allowMediatedGate [mediatedWitness]).2
  == [WEv.emitEv "OK",
      WEv.decideEv mediatedWitness (SealV2.Decision.Allow "OK")]
#guard (strictRun sealAdapter blockGate [mediatedWitness]).2
  == [WEv.decideEv mediatedWitness SealV2.Decision.Block]
-- Every Step-0 escaping witness is now REFUSED, not forwarded — zero
-- child-bound events, zero decide events:
#guard (strictRun sealAdapter allowMediatedGate [malformedWitness]).2
  == [WEv.refuseEv malformedWitness]
#guard (strictRun sealAdapter allowMediatedGate [bomWitness]).2
  == [WEv.refuseEv bomWitness]
#guard (strictRun sealAdapter allowMediatedGate [misspelledWitness]).2
  == [WEv.refuseEv misspelledWitness]
#guard (strictRun sealAdapter allowMediatedGate [batchWitness]).2
  == [WEv.refuseEv batchWitness]
-- The pre-parse refused class is untouched:
#guard (strictRun sealAdapter allowMediatedGate [monsterExponentWitness]).2
  == [WEv.refuseEv monsterExponentWitness]
-- Mixed stream: the strict host refuses the batch AND still serves the
-- mediated call in the same run — refusal is per-line, not a shutdown:
#guard (strictRun sealAdapter allowMediatedGate
    [batchWitness, mediatedWitness]).2
  == [WEv.emitEv "OK",
      WEv.decideEv mediatedWitness (SealV2.Decision.Allow "OK"),
      WEv.refuseEv batchWitness]

/-! ## Axiom pins

Every theorem in this module sits on the classical baseline
`[propext, Classical.choice, Quot.sound]` or tighter — no `sorryAx`, no
`native_decide`/`Lean.ofReduceBool`, no custom axiom. Pinned with
`#guard_msgs` so any drift fails the build here. -/

/-- info: 'Host.Perimeter.refusedClass_eq_false_of_inPerimeter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms refusedClass_eq_false_of_inPerimeter
/-- info: 'Host.Perimeter.strictStep_fwd_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictStep_fwd_mem
/-- info: 'Host.Perimeter.strictRun_from_fwd_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictRun_from_fwd_mem
/-- info: 'Host.Perimeter.strictRun_no_fwd' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictRun_no_fwd
/-- info: 'Host.Perimeter.strictStep_decide_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictStep_decide_mem
/-- info: 'Host.Perimeter.strictRun_from_decide_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictRun_from_decide_mem
/-- info: 'Host.Perimeter.strictRun_decide_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictRun_decide_iff
/-- info: 'Host.Perimeter.strictStep_refuse_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictStep_refuse_mem
/-- info: 'Host.Perimeter.strictRun_from_refuse_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictRun_from_refuse_mem
/-- info: 'Host.Perimeter.strictRun_refuse_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictRun_refuse_iff
/-- info: 'Host.Perimeter.strictRun_single_escape' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictRun_single_escape
/-- info: 'Host.Perimeter.strictRun_single_act_allow' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictRun_single_act_allow
/-- info: 'Host.Perimeter.strict_escape_closed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strict_escape_closed
/-- info: 'Host.Perimeter.strictRun_invariant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strictRun_invariant
/-- info: 'Host.Perimeter.strict_gated_sink_non_bypass' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strict_gated_sink_non_bypass
/-- info: 'Host.Perimeter.strict_mediatedChildBound' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strict_mediatedChildBound
/-- info: 'Host.Perimeter.strict_mediatedChildBound_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strict_mediatedChildBound_live
/-- info: 'Host.Perimeter.strict_fails_for_rogue_adapter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strict_fails_for_rogue_adapter
/-- info: 'Host.Perimeter.strict_option_a_nonvacuous' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms strict_option_a_nonvacuous

end Host.Perimeter
