/- SPDX-License-Identifier: Apache-2.0 -/

import Host.EgressPerimeter

/-!
# Strengthening the P5 capstone to cover adapter emissions

A cold frisk of `Host/EgressPerimeter.lean` established, correctly, that
`client_block_mediated` is a genuinely weaker property than Option A's
`strict_mediatedChildBound`: it constrains ONLY the client-bound `blockEv`
channel. An arbitrary malicious adapter may produce unlicensed `emitEv`s and
`client_block_mediated` still holds — that theorem needs no O1/O2 hypothesis
BECAUSE it asks for less. This module answers the question that finding
raises: can the P5 capstone be strengthened to cover adapter emissions, the
way Option A's property does?

## The verdict, in one paragraph

**YES for adapter emissions, under O1∧O2 — and the hypothesis is not
removable; NO for forwarded events, under any hypothesis at all.**
`clientEgressMediated` is the strengthened property: every P5 block emission
is preceded by its `Block` decide AND every adapter emission is preceded by
an `Allow` decide of byte-identical output. `client_egress_mediated` proves
it for every O1∧O2 adapter at every gate and author, discharged at the
deployed model and the live gate by `client_egress_mediated_live`. The O1∧O2
hypothesis is load-bearing: `client_egress_fails_for_rogue_adapter` is the
machine-checked no-go — the rogue adapter of `Host/ChannelModel.lean`
(which SATISFIES O2, `rogueAdapter_O2`, and violates exactly O1,
`rogueAdapter_not_O1`) breaks the strengthened property on any perimeter
line, so even O2 alone is insufficient: O1 is the irremovable piece.
`rogue_separates_block_from_emit` pins the frisk's
asymmetry as a theorem: on the SAME run the weak `blocksPrecededByDecide`
holds while `clientEgressMediated` fails. Going further is impossible:
`egress_full_childBound_fails` proves the FULL Option-A-strength property
(adding the forwarded-event leg) fails on the deployed egress host for EVERY
adapter and EVERY gate — no hypothesis on the adapter can save it, because
the P1 escape forward carries no decision by construction. That leg is
closed only by changing the host (Option A), not by strengthening the
theorem.

## What is NEW here and what is not

`blocksPrecededByDecide` and `emitsPrecededByAllowE` both already exist in
`Host/EgressPerimeter.lean`, and each is separately proved there. What did
NOT exist: the conjunction as a named property, the theorem that the
conjunction holds (the strengthened capstone the frisk asked for), the
machine-checked no-go showing O1∧O2 is exactly the price, the separation
theorem, and the proof that the forwarded-event leg is not strengthenable at
this host. Nothing existing is modified.

## Non-vacuity (witness discipline of the parent modules)

`Lean.Json.parse` is `partial`, so concrete classifications are
compiler-evaluated `#guard`s and the ∃-witnesses are conditional on the
classification. `client_egress_block_nonvacuous_of_act` /
`client_egress_emit_nonvacuous_of_act` exhibit runs satisfying the
strengthened property with an ACTUAL block emission and an ACTUAL licensed
adapter emission; the `#guard`s below pin one single run containing BOTH,
plus the rogue counterexample run and the escape-forward counterexample run
— every no-go witness is a reachable, evaluated trace, not a hypothetical.

## HONESTY

Model-level, exactly as the parent modules: the `rust/` ↔ model byte
refinement remains the conformance-bridge obligation. O1∧O2 are facts about
the ADAPTER MODEL (`sealAdapter_O1`/`sealAdapter_O2`); that the compiled
binary implements them is part of that same bridge, not proven here.
-/

namespace Host.Egress

open Host.Channel
open Host.Perimeter

/-! ## The strengthened property -/

/-- **The strengthened P5 property.** Client-egress mediation over the
    extended trace: every client-bound block emission is preceded strictly
    earlier by a `Block` decide of the same line (the original
    `client_block_mediated` obligation), AND every adapter emission is
    preceded strictly earlier by an `Allow` decide of byte-identical output
    (the obligation Option A's `mediatedChildBound` carries and the original
    P5 capstone did not). Both conjuncts range over one and the same
    extended run trace. -/
def clientEgressMediated (tr : ETrace) : Prop :=
  blocksPrecededByDecide tr ∧ emitsPrecededByAllowE tr

/-- **The strengthened capstone: CLOSED under O1∧O2.** For every adapter
    satisfying the gated-sink obligations, at every gate and every author,
    over every input stream: block emissions are Block-decide-preceded and
    adapter emissions are Allow-decide-preceded. The block half is
    host-structural (no hypothesis); the emission half is exactly where
    O1∧O2 is spent — the same price Option A's capstone pays. -/
theorem client_egress_mediated (A : Adapter) (hO1 : O1 A) (hO2 : O2 A)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    clientEgressMediated (erun A gate author inputs).2 :=
  ⟨client_block_mediated A gate author inputs,
   egress_gated_sink_non_bypass A hO1 hO2 gate author inputs⟩

/-- The strengthened capstone at the deployed adapter model and the LIVE
    gate, hypotheses discharged. -/
theorem client_egress_mediated_live (state : SealV2.ApprovalState)
    (author : CanonicalAction → String) (inputs : List EIn) :
    clientEgressMediated
      (erun sealAdapter (fun raw => SealV2.decide raw state)
        author inputs).2 :=
  client_egress_mediated sealAdapter sealAdapter_O1 sealAdapter_O2
    _ author inputs

/-! ## The no-go: O1∧O2 is exactly the price -/

/-- **The machine-checked no-go.** The strengthened property does NOT hold
    for every adapter: the rogue adapter (unlicensed fixed `"EXFIL"`
    emission, `Host/ChannelModel.lean`) breaks it on any act-classified line
    at the blocking gate — its `emitEv "EXFIL"` has no prior `Allow` of
    those bytes. The rogue adapter SATISFIES O2 (`rogueAdapter_O2`) and
    violates exactly O1 (`rogueAdapter_not_O1`), so the no-go is sharp
    twice over: without the O1∧O2 hypothesis the strengthening is FALSE,
    and O2 alone cannot replace it — O1 is the irremovable piece. -/
theorem client_egress_fails_for_rogue_adapter (line : String)
    (a : CanonicalAction) (h : Host.classifyLine line = .act a)
    (author : CanonicalAction → String) :
    ¬ clientEgressMediated
        (erun Channel.rogueAdapter blockGate author
          [EIn.clientLine line]).2 := by
  intro hmed
  have htr : (erun Channel.rogueAdapter blockGate author
        [EIn.clientLine line]).2
      = [EEv.emitEv "EXFIL", EEv.blockEv line (author a),
         EEv.decideEv line SealV2.Decision.Block] := by
    simp [erun, estep, h, Channel.rogueAdapter, blockGate]
  obtain ⟨raw, hraw⟩ := hmed.2 [] "EXFIL"
    [EEv.blockEv line (author a), EEv.decideEv line SealV2.Decision.Block]
    (by rw [htr]; rfl)
  rcases List.mem_cons.mp hraw with heq | hraw'
  · cases heq
  · rcases List.mem_cons.mp hraw' with heq2 | hraw''
    · injection heq2 with h1 h2
      cases h2
    · nomatch hraw''

/-- **The frisk's asymmetry, as a theorem.** On one and the same rogue run,
    the ORIGINAL P5 capstone property holds (block emissions are still
    decide-preceded — it never constrained the adapter) while the
    STRENGTHENED property fails (the unlicensed emission survives). This is
    the separation the cold frisk stated in prose, machine-checked: the two
    capstones are provably not the same strength. -/
theorem rogue_separates_block_from_emit (line : String)
    (a : CanonicalAction) (h : Host.classifyLine line = .act a)
    (author : CanonicalAction → String) :
    blocksPrecededByDecide
        (erun Channel.rogueAdapter blockGate author
          [EIn.clientLine line]).2
      ∧ ¬ clientEgressMediated
        (erun Channel.rogueAdapter blockGate author
          [EIn.clientLine line]).2 :=
  ⟨client_block_mediated Channel.rogueAdapter blockGate author
      [EIn.clientLine line],
   client_egress_fails_for_rogue_adapter line a h author⟩

/-! ## The ceiling: the forwarded-event leg cannot be added -/

/-- The FULL Option-A-strength property over the extended trace: the
    strengthened client-egress mediation AND every forwarded line carries
    some strictly earlier decision (the `mediatedChildBound` forward leg,
    in its weakest reading — any decision at all). -/
def egressChildBoundFull (tr : ETrace) : Prop :=
  clientEgressMediated tr ∧
  (∀ post r pre, tr = post ++ EEv.fwdEv r :: pre →
    ∃ d, EEv.decideEv r d ∈ pre)

/-- **The ceiling, machine-checked.** The full property fails on the
    deployed egress host for EVERY adapter, EVERY gate and EVERY author: any
    escaping line is forwarded with no prior decision of any kind. No
    adapter-side hypothesis can repair this — the forward is emitted by the
    host's `.passthrough` branch before any gate is consulted. Covering the
    forward leg requires changing the HOST (Option A, `strictStep`), not
    strengthening the theorem. This bounds the strengthening exactly:
    adapter emissions yes (under O1∧O2), forwarded events no. -/
theorem egress_full_childBound_fails (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (line : String)
    (hesc : escapes line = true) :
    ¬ egressChildBoundFull
        (erun A gate author [EIn.clientLine line]).2 := by
  intro hfull
  have htr : (erun A gate author [EIn.clientLine line]).2
      = [EEv.fwdEv line] :=
    erun_single_passthrough A gate author line
      ((classifyLine_passthrough_iff line).mpr hesc)
  obtain ⟨d, hd⟩ := hfull.2 [] line [] (by rw [htr]; rfl)
  nomatch hd

/-- The ceiling pinned at the deployed model and the LIVE gate. -/
theorem egress_full_childBound_fails_live (state : SealV2.ApprovalState)
    (author : CanonicalAction → String) (line : String)
    (hesc : escapes line = true) :
    ¬ egressChildBoundFull
        (erun sealAdapter (fun raw => SealV2.decide raw state)
          author [EIn.clientLine line]).2 :=
  egress_full_childBound_fails sealAdapter _ author line hesc

/-! ## Non-vacuity (conditional existentials; concrete runs `#guard`ed) -/

/-- Non-vacuity, block side: any act-classified line yields a run whose
    trace contains an ACTUAL client-bound block emission AND satisfies the
    strengthened property — not the degenerate never-blocking alphabet. -/
theorem client_egress_block_nonvacuous_of_act (line : String)
    (a : CanonicalAction) (h : Host.classifyLine line = .act a) :
    ∃ (gate : SealV2.RawBytes → SealV2.Decision)
      (author : CanonicalAction → String) (b : String),
      EEv.blockEv line b
          ∈ (erun sealAdapter gate author [EIn.clientLine line]).2
        ∧ clientEgressMediated
            (erun sealAdapter gate author [EIn.clientLine line]).2 := by
  refine ⟨blockGate, testAuthor, testAuthor a, ?_, ?_⟩
  · rw [erun_single_act_block blockGate testAuthor line a h rfl]
    exact List.mem_cons_self
  · exact client_egress_mediated sealAdapter sealAdapter_O1 sealAdapter_O2
      blockGate testAuthor [EIn.clientLine line]

/-- Non-vacuity, emission side: any act-classified line yields a run whose
    trace contains an ACTUAL gated-sink emission AND satisfies the
    strengthened property — the emission conjunct is not the always-deny
    vacuum. -/
theorem client_egress_emit_nonvacuous_of_act (line : String)
    (a : CanonicalAction) (h : Host.classifyLine line = .act a) :
    ∃ (gate : SealV2.RawBytes → SealV2.Decision)
      (author : CanonicalAction → String) (out : SealV2.CanonicalBytes),
      EEv.emitEv out
          ∈ (erun sealAdapter gate author [EIn.clientLine line]).2
        ∧ clientEgressMediated
            (erun sealAdapter gate author [EIn.clientLine line]).2 := by
  refine ⟨allowGate, testAuthor, "OK", ?_, ?_⟩
  · rw [erun_single_act_allow allowGate testAuthor line a "OK" h rfl]
    exact List.mem_cons_self
  · exact client_egress_mediated sealAdapter sealAdapter_O1 sealAdapter_O2
      allowGate testAuthor [EIn.clientLine line]

/-- A second concrete perimeter line (a strict `tools/call` naming a
    different tool), so ONE run can show a licensed emission and a P5 block
    side by side under `allowMediatedGate`. -/
def strengthWitness : String :=
  "{\"method\":\"tools/call\",\"params\":{\"name\":\"delete_file\",\"arguments\":{\"path\":\"README.md\"}}}"

-- The second witness is in S and distinct from the mediated witness:
#guard inPerimeter strengthWitness
#guard strengthWitness != mediatedWitness
-- Re-pin the parent's witness (also pinned there):
#guard inPerimeter mediatedWitness
-- ONE run containing BOTH a licensed adapter emission and a P5 block
-- emission — the two conjuncts of the strengthened property are exercised
-- side by side in a single reachable trace (which `client_egress_mediated`
-- covers, since `sealAdapter` is O1∧O2):
#guard (erun sealAdapter allowMediatedGate testAuthor
    [EIn.clientLine mediatedWitness, EIn.clientLine strengthWitness]).2
  == [EEv.blockEv strengthWitness "BLOCKED:delete_file",
      EEv.decideEv strengthWitness SealV2.Decision.Block,
      EEv.emitEv "OK",
      EEv.decideEv mediatedWitness (SealV2.Decision.Allow "OK")]
-- The rogue counterexample run is REACHABLE and looks exactly as the no-go
-- proof says: an unlicensed emission above a decide-preceded block:
#guard (erun Channel.rogueAdapter blockGate testAuthor
    [EIn.clientLine mediatedWitness]).2
  == [EEv.emitEv "EXFIL",
      EEv.blockEv mediatedWitness "BLOCKED:read_file",
      EEv.decideEv mediatedWitness SealV2.Decision.Block]
-- The ceiling counterexample run is REACHABLE: the escape forward, no
-- decision anywhere (the P1 transition the full property trips over):
#guard (erun sealAdapter allowMediatedGate testAuthor
    [EIn.clientLine malformedWitness]).2
  == [EEv.fwdEv malformedWitness]

/-! ## Axiom pins

Classical baseline `[propext, Classical.choice, Quot.sound]` or tighter —
no `sorryAx`, no `native_decide`, no custom axiom. `#guard_msgs`-pinned so
drift fails the build here. -/

/-- info: 'Host.Egress.client_egress_mediated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms client_egress_mediated
/-- info: 'Host.Egress.client_egress_mediated_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms client_egress_mediated_live
/-- info: 'Host.Egress.client_egress_fails_for_rogue_adapter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms client_egress_fails_for_rogue_adapter
/-- info: 'Host.Egress.rogue_separates_block_from_emit' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms rogue_separates_block_from_emit
/-- info: 'Host.Egress.egress_full_childBound_fails' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms egress_full_childBound_fails
/-- info: 'Host.Egress.egress_full_childBound_fails_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms egress_full_childBound_fails_live
/-- info: 'Host.Egress.client_egress_block_nonvacuous_of_act' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms client_egress_block_nonvacuous_of_act
/-- info: 'Host.Egress.client_egress_emit_nonvacuous_of_act' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms client_egress_emit_nonvacuous_of_act

end Host.Egress
