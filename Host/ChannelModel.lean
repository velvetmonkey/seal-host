/- SPDX-License-Identifier: Apache-2.0 -/

import SealV2.DecideTheorems

/-!
# W2-T6 — Channel non-bypass: the adapter obligation set (CAPSTONE)

`step_forward_non_bypass` (L0) governs the routing core. This module governs
the layer the wave brief calls "the channel": an ADAPTER sitting between the
gate and a downstream sink. It answers: *what must an adapter satisfy so that
every downstream emission is mediated?* — and proves the obligation set is
exactly enough.

**Symbol binding.** No symbol named `sealDecide` exists in this stack; the
binding decide entrypoint is `SealV2.decide : RawBytes → ApprovalState →
Decision` with `Decision = Block | Allow (out : CanonicalBytes)` — the
canonical-bytes decision path. "sealDecide" in the wave brief = `SealV2.decide`
here.

**Model.** The adapter is a transition machine with a ghost license buffer
(`Adapter.licensed`). The RUN semantics performs the gate call itself and
records it in the trace, so verdict genuineness is structural
(`run_decide_genuine`); the adapter only REACTS to verdicts. The run is
generic over the gate function and the shipped capstone instantiates
`gate := (SealV2.decide · state)` — the same generic-core + deploy-instance
discipline as `tamper_evident`/`chainHash`: a REAL `SealV2.decide … = .Allow`
requires an Ed25519-validated capability and is not kernel-evaluable, so
concrete witnesses run on cheap test gates while the shipped theorems bind the
live symbol.

**Obligations (step-local — they quantify over single states/transitions
only, never over traces; this is what keeps the separation non-circular):**

* **O1** — the adapter emits only bytes its license buffer covers;
* **O2** — licenses are never manufactured: the buffer starts empty and grows
  only by the exact `(raw, out)` pair of the `Allow` verdict just received;
* **O3** — byte fidelity is carried by the license PAIR: an emit of `b`
  licensed by `(raw, out)` forces `b = out` (`obligation_O3`).

**Conclusion (trace-global).** `channel_preserves_non_bypass`: on every run of
a compliant adapter, every emission is preceded (strictly earlier in the
trace) by a `decide` event carrying `Allow` of byte-identical output. The
bridge from step-local obligations to the trace-global existential is the
run induction with the license invariant — the induction is load-bearing;
no single obligation entails the conclusion (see the separation witnesses:
`rogueAdapter` violates exactly O1, `forgerAdapter` exactly O2, and mediation
provably fails on both).

**Composed payoff.** `channel_emits_only_validated`: at the live gate, every
byte string a compliant adapter emits is the canonical serialization of a
capability that VALIDATED against the approval state (`SealV2.non_bypass`).

TRUST BOUNDARY (stated loud): this governs the adapter-to-gate composition IN
THE MODEL only. The deployed Rust adapter (`rust/src/main.rs`, P1–P6 path
inventory, gated sink `child_in.write_all`) is NOT proven to satisfy O1–O3 —
refinement of `rust/` against these obligations is a separate
conformance-bridge job, named future work. The canonical-bytes clause aligns
with the `SealV2.decide`/canonicalL0 path; the deployed profile is
`compatible` and does not gate on canonical bytes (CLAIMS.md). What the
theorem buys today: O1–O3 are the precise, minimal, machine-checked
obligations an adapter audit must establish.
-/

namespace Host.Channel

/-- One event on the adapter↔gate seam: the gate deciding on raw bytes, or
    the adapter emitting bytes downstream. -/
inductive ChanEv where
  | decideEv (raw : SealV2.RawBytes) (d : SealV2.Decision)
  | emitEv (bytes : SealV2.CanonicalBytes)
  deriving Repr, BEq

/-- Adapter trace, MOST-RECENT-FIRST (the `Host.Record.Log` convention):
    "earlier than position i" = further toward the list tail. -/
abbrev ChanTrace := List ChanEv

/-- An adapter: a transition machine reacting to gate verdicts. `licensed` is
    the ghost buffer of `(raw, allowed-bytes)` pairs the adapter believes it
    may act on — the obligations constrain how it evolves. -/
structure Adapter where
  St : Type
  init : St
  onVerdict : St → SealV2.RawBytes → SealV2.Decision → St
  emitsOn : St → List SealV2.CanonicalBytes
  licensed : St → List (SealV2.RawBytes × SealV2.CanonicalBytes)

/-- **O1 (step-local).** The adapter emits only bytes its license buffer
    covers — no unlicensed emission, in ANY state. -/
def O1 (A : Adapter) : Prop :=
  ∀ st, ∀ b ∈ A.emitsOn st, ∃ raw, (raw, b) ∈ A.licensed st

/-- **O2 (step-local).** Licenses are never manufactured: empty at init, and
    a transition adds at most the exact `(raw, out)` pair of the `Allow`
    verdict just received — a `Block` licenses nothing new. -/
def O2 (A : Adapter) : Prop :=
  A.licensed A.init = [] ∧
  ∀ st raw d p, p ∈ A.licensed (A.onVerdict st raw d) →
    p ∈ A.licensed st ∨ ∃ out, d = SealV2.Decision.Allow out ∧ p = (raw, out)

/-- **O3 (byte fidelity), named.** Under O1, every emitted byte string equals
    the decided-output component of some license pair — emitted bytes ARE
    decided canonical bytes, never a rewrite of them. -/
theorem obligation_O3 (A : Adapter) (hO1 : O1 A) :
    ∀ st, ∀ b ∈ A.emitsOn st,
      ∃ raw out, (raw, out) ∈ A.licensed st ∧ b = out :=
  fun st b hb => let ⟨raw, h⟩ := hO1 st b hb; ⟨raw, b, h, rfl⟩

/-- One step of the composed system on input `raw`: the GATE decides (the
    model performs the call — an adapter cannot fake it), the trace records
    the decide event, the adapter transitions on the verdict, and its
    emissions in the new state are recorded newest-first. -/
def step (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (s : A.St × ChanTrace) (raw : SealV2.RawBytes) : A.St × ChanTrace :=
  (A.onVerdict s.1 raw (gate raw),
   ((A.emitsOn (A.onVerdict s.1 raw (gate raw))).map ChanEv.emitEv)
     ++ ChanEv.decideEv raw (gate raw) :: s.2)

/-- A run of the composed system over an input stream, from the adapter's
    initial state and the empty trace. -/
def run (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (inputs : List SealV2.RawBytes) : A.St × ChanTrace :=
  inputs.foldl (step A gate) (A.init, ([] : ChanTrace))

/-- **The trace-global mediation property.** Every emission in the trace is
    preceded (strictly earlier = in its tail) by a decide event that returned
    `Allow` of exactly the emitted bytes. -/
def precededByAllow (tr : ChanTrace) : Prop :=
  ∀ post b pre, tr = post ++ ChanEv.emitEv b :: pre →
    ∃ raw, ChanEv.decideEv raw (SealV2.Decision.Allow b) ∈ pre

/-- Positional form of the mediation property, convenient for induction:
    each emit is licensed by a decide in ITS OWN tail. -/
def Guarded : ChanTrace → Prop
  | [] => True
  | ChanEv.emitEv b :: rest =>
      (∃ raw, ChanEv.decideEv raw (SealV2.Decision.Allow b) ∈ rest) ∧ Guarded rest
  | ChanEv.decideEv _ _ :: rest => Guarded rest

/-- Splitting a guarded trace at any emission yields its licensing decide. -/
theorem guarded_split (post : ChanTrace) :
    ∀ (b : SealV2.CanonicalBytes) (pre : ChanTrace),
      Guarded (post ++ ChanEv.emitEv b :: pre) →
      ∃ raw, ChanEv.decideEv raw (SealV2.Decision.Allow b) ∈ pre := by
  induction post with
  | nil => intro b pre h; exact h.1
  | cons e post ih =>
      intro b pre h
      cases e with
      | emitEv b' => exact ih b pre h.2
      | decideEv r d => exact ih b pre h

theorem guarded_precededByAllow (tr : ChanTrace) (h : Guarded tr) :
    precededByAllow tr :=
  fun post b pre heq => guarded_split post b pre (heq ▸ h)

/-- Prepending licensed emissions preserves guardedness. -/
theorem guarded_append_emits (l : List SealV2.CanonicalBytes) (tr : ChanTrace)
    (h : ∀ b ∈ l, ∃ raw, ChanEv.decideEv raw (SealV2.Decision.Allow b) ∈ tr)
    (htr : Guarded tr) : Guarded (l.map ChanEv.emitEv ++ tr) := by
  induction l with
  | nil => simpa using htr
  | cons b bs ih =>
      refine ⟨?_, ih (fun b' hb' => h b' (List.mem_cons_of_mem _ hb'))⟩
      obtain ⟨raw, hmem⟩ := h b (List.mem_cons_self)
      exact ⟨raw, List.mem_append_right _ hmem⟩

/-- **The run induction (load-bearing).** The license invariant — every
    licensed pair's `Allow`-decide event is already in the trace — plus
    guardedness survive every step, given the step-local obligations. This
    is the bridge from O1∧O2 to the trace-global conclusion. -/
theorem run_invariant (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (hO1 : O1 A) (hO2 : O2 A) :
    ∀ (inputs : List SealV2.RawBytes) (s : A.St × ChanTrace),
      (∀ p ∈ A.licensed s.1,
        ChanEv.decideEv p.1 (SealV2.Decision.Allow p.2) ∈ s.2) →
      Guarded s.2 →
      (∀ p ∈ A.licensed (inputs.foldl (step A gate) s).1,
        ChanEv.decideEv p.1 (SealV2.Decision.Allow p.2)
          ∈ (inputs.foldl (step A gate) s).2) ∧
      Guarded (inputs.foldl (step A gate) s).2 := by
  intro inputs
  induction inputs with
  | nil => intro s h1 h2; exact ⟨h1, h2⟩
  | cons raw rest ih =>
      intro s h1 h2
      simp only [List.foldl_cons]
      apply ih
      · -- license invariant survives the step
        intro p hp
        rcases hO2.2 s.1 raw (gate raw) p hp with hold | ⟨out, hd, rfl⟩
        · exact List.mem_append_right _ (List.mem_cons_of_mem _ (h1 p hold))
        · refine List.mem_append_right _ ?_
          rw [hd]
          exact List.mem_cons_self
      · -- guardedness survives the step
        apply guarded_append_emits
        · intro b hb
          obtain ⟨raw', hlic⟩ := hO1 (A.onVerdict s.1 raw (gate raw)) b hb
          rcases hO2.2 s.1 raw (gate raw) (raw', b) hlic with hold | ⟨out, hd, hpair⟩
          · exact ⟨raw', List.mem_cons_of_mem _ (h1 _ hold)⟩
          · have hb2 : b = out := congrArg Prod.snd hpair
            refine ⟨raw, ?_⟩
            rw [hb2, hd]
            exact List.mem_cons_self
        · exact h2

/-- **Verdict genuineness is structural.** Every decide event a run records
    carries exactly what the gate returned on those raw bytes — the adapter
    has no way to write a manufactured verdict into the trace. -/
theorem run_decide_genuine_from (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) :
    ∀ (inputs : List SealV2.RawBytes) (s : A.St × ChanTrace),
      (∀ raw d, ChanEv.decideEv raw d ∈ s.2 → d = gate raw) →
      ∀ raw d, ChanEv.decideEv raw d ∈ (inputs.foldl (step A gate) s).2 →
        d = gate raw := by
  intro inputs
  induction inputs with
  | nil => intro s h; exact h
  | cons raw0 rest ih =>
      intro s h
      simp only [List.foldl_cons]
      apply ih
      intro raw d hmem
      rcases List.mem_append.mp hmem with hml | hmr
      · obtain ⟨b, -, hbeq⟩ := List.mem_map.mp hml
        cases hbeq
      · cases hmr with
        | head => rfl
        | tail _ htail => exact h raw d htail

/-- Genuineness over a full run from the initial (empty-trace) state. -/
theorem run_decide_genuine (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (inputs : List SealV2.RawBytes) :
    ∀ raw d, ChanEv.decideEv raw d ∈ (run A gate inputs).2 → d = gate raw :=
  run_decide_genuine_from A gate inputs (A.init, [])
    (fun _ _ h => nomatch h)

/-- **Channel non-bypass, generic gate.** Any adapter meeting the step-local
    obligations O1 ∧ O2 mediates every action on every run: each emission has
    a strictly earlier decide event returning `Allow` of byte-identical
    output. -/
theorem channel_preserves_non_bypass_gen (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (hO1 : O1 A) (hO2 : O2 A) (inputs : List SealV2.RawBytes) :
    precededByAllow (run A gate inputs).2 := by
  have h := run_invariant A gate hO1 hO2 inputs (A.init, [])
    (fun p hp => nomatch (hO2.1 ▸ hp)) trivial
  exact guarded_precededByAllow _ h.2

/-- **W2-T6 CAPSTONE — `channel_preserves_non_bypass`.** At the live gate
    (`SealV2.decide` against an approval state): any channel whose adapter
    satisfies the obligation set O1 ∧ O2 (with O3 carried by the license
    pairs, `obligation_O3`) mediates every action — every downstream emission
    has a preceding ALLOW decision on matching canonical bytes. -/
theorem channel_preserves_non_bypass (A : Adapter)
    (hO1 : O1 A) (hO2 : O2 A)
    (state : SealV2.ApprovalState) (inputs : List SealV2.RawBytes) :
    precededByAllow (run A (fun raw => SealV2.decide raw state) inputs).2 :=
  channel_preserves_non_bypass_gen A _ hO1 hO2 inputs

/-- **Composed payoff.** Every byte string a compliant adapter emits at the
    live gate is the canonical serialization of a capability that VALIDATED
    against the approval state — `SealV2.non_bypass` through the channel. -/
theorem channel_emits_only_validated (A : Adapter)
    (hO1 : O1 A) (hO2 : O2 A)
    (state : SealV2.ApprovalState) (inputs : List SealV2.RawBytes)
    (post : ChanTrace) (b : SealV2.CanonicalBytes) (pre : ChanTrace)
    (hsplit : (run A (fun raw => SealV2.decide raw state) inputs).2
      = post ++ ChanEv.emitEv b :: pre) :
    ∃ (raw : SealV2.RawBytes) (ast : SealV2.AST),
      SealV2.parse raw = some ast ∧
      ∃ w : SealV2.ValidApproval ast state,
        b = SealV2.serialize (Sigma.mk ast w) := by
  obtain ⟨raw, hmem⟩ :=
    channel_preserves_non_bypass A hO1 hO2 state inputs post b pre hsplit
  have hmem' : ChanEv.decideEv raw (SealV2.Decision.Allow b)
      ∈ (run A (fun raw => SealV2.decide raw state) inputs).2 := by
    rw [hsplit]
    exact List.mem_append_right _ (List.mem_cons_of_mem _ hmem)
  have hgen := run_decide_genuine A _ inputs raw _ hmem'
  exact ⟨raw, SealV2.non_bypass raw state b hgen.symm⟩

/-! ## Witnesses: compliance is satisfiable, obligations are load-bearing

Concrete adapters over cheap test gates (constant / literal-equality — no
kernel evaluation of real crypto; the live-gate binding is the generic-core
instantiation above).

Separation (anti-circularity): the obligations quantify over single
states/transitions and never mention traces; the conclusion quantifies over
whole runs. Each obligation is independently load-bearing — `rogueAdapter`
violates exactly O1 (O2 holds), `forgerAdapter` violates exactly O2 (O1
holds), and on both the conclusion provably FAILS on a concrete run. -/

/-- Test gate: allows the literal `"ok"` with output `"OK"`. -/
def okGate : SealV2.RawBytes → SealV2.Decision :=
  fun raw => if raw = "ok" then .Allow "OK" else .Block

/-- Test gate: blocks everything (used where the witness must not depend on
    any string comparison). -/
def blockGate : SealV2.RawBytes → SealV2.Decision := fun _ => .Block

/-- The compliant adapter: its state IS its license list; an `Allow` verdict
    appends its pair, a `Block` adds nothing; it emits exactly its licensed
    bytes. -/
def compliantAdapter : Adapter where
  St := List (SealV2.RawBytes × SealV2.CanonicalBytes)
  init := []
  onVerdict := fun st raw d =>
    match d with
    | .Allow out => (raw, out) :: st
    | .Block => st
  emitsOn := fun st => st.map (·.2)
  licensed := fun st => st

theorem compliantAdapter_O1 : O1 compliantAdapter := by
  intro st b hb
  simp only [compliantAdapter, List.mem_map] at hb
  obtain ⟨p, hp, rfl⟩ := hb
  exact ⟨p.1, hp⟩

theorem compliantAdapter_O2 : O2 compliantAdapter := by
  refine ⟨rfl, ?_⟩
  intro st raw d p hp
  cases d with
  | Block => exact Or.inl hp
  | Allow out =>
      rcases List.mem_cons.mp hp with rfl | hmem
      · exact Or.inr ⟨out, rfl, rfl⟩
      · exact Or.inl hmem

-- The compliant run on a live allow really EMITS (the conclusion below is
-- about a non-empty emission set): trace = [emit "OK", decide "ok" Allow "OK"].
#guard (run compliantAdapter okGate ["ok"]).2
  == [ChanEv.emitEv "OK", ChanEv.decideEv "ok" (SealV2.Decision.Allow "OK")]

/-- Mediation HOLDS on the compliant adapter's live run (non-vacuous: per the
    `#guard` above, that run contains an actual emission). -/
theorem compliant_run_mediated :
    precededByAllow (run compliantAdapter okGate ["ok"]).2 :=
  channel_preserves_non_bypass_gen compliantAdapter okGate
    compliantAdapter_O1 compliantAdapter_O2 ["ok"]

/-- The rogue adapter — violates EXACTLY O1: emits `"EXFIL"` with an empty
    license buffer. (O2 holds: the buffer is always empty.) -/
def rogueAdapter : Adapter where
  St := Unit
  init := ()
  onVerdict := fun _ _ _ => ()
  emitsOn := fun _ => ["EXFIL"]
  licensed := fun _ => []

theorem rogueAdapter_not_O1 : ¬ O1 rogueAdapter := by
  intro h
  obtain ⟨raw, hmem⟩ := h () "EXFIL" (by simp [rogueAdapter])
  simp [rogueAdapter] at hmem

theorem rogueAdapter_O2 : O2 rogueAdapter :=
  ⟨rfl, fun _ _ _ _ hp => nomatch hp⟩

-- Its run emits without any licensing decide:
#guard (run rogueAdapter blockGate ["x"]).2
  == [ChanEv.emitEv "EXFIL", ChanEv.decideEv "x" SealV2.Decision.Block]

/-- Mediation FAILS on the rogue adapter's run: the emitted `"EXFIL"` has no
    preceding `Allow` — the O1 obligation is load-bearing. -/
theorem rogue_mediation_fails :
    ¬ precededByAllow (run rogueAdapter blockGate ["x"]).2 := by
  intro h
  obtain ⟨raw, hmem⟩ :=
    h [] "EXFIL" [ChanEv.decideEv "x" SealV2.Decision.Block] rfl
  simp at hmem

/-- The forger adapter — violates EXACTLY O2: a self-stocked license buffer
    no gate ever granted. (O1 holds: it emits only "licensed" bytes.) -/
def forgerAdapter : Adapter where
  St := Unit
  init := ()
  onVerdict := fun _ _ _ => ()
  emitsOn := fun _ => ["FORGED"]
  licensed := fun _ => [("f", "FORGED")]

theorem forgerAdapter_O1 : O1 forgerAdapter := by
  intro st b hb
  simp only [forgerAdapter, List.mem_singleton] at hb
  subst hb
  exact ⟨"f", by simp [forgerAdapter]⟩

theorem forgerAdapter_not_O2 : ¬ O2 forgerAdapter :=
  fun h => nomatch h.1

/-- Mediation FAILS on the forger adapter's run: the manufactured license let
    `"FORGED"` out with no `Allow` anywhere — the O2 obligation is
    load-bearing. -/
theorem forger_mediation_fails :
    ¬ precededByAllow (run forgerAdapter blockGate ["x"]).2 := by
  intro h
  obtain ⟨raw, hmem⟩ :=
    h [] "FORGED" [ChanEv.decideEv "x" SealV2.Decision.Block] rfl
  simp at hmem

end Host.Channel
