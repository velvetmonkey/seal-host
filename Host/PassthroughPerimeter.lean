/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Canonical
import Host.SealAdapter

/-!
# The passthrough perimeter — widening the channel alphabet to include P1

`Host/ChannelModel.lean` (W2-T6) and `Host/SealAdapter.lean` (W2-T6.1) prove
non-bypass over an alphabet that DELIBERATELY excludes the P1
classify-passthrough transition: their `run` pipes EVERY input line through
the gate. The deployed host does not. `Host.classifyLine`
(`Host/Canonical.lean`) forwards a line that fails `Lean.Json.parse`, carries
a leading BOM, or spells the method `"TOOLS/CALL"` to the child UNDECIDED —
admitted in prose by `RUST_BRIDGE.md` ("A-strict-child") but absent from the
proved model. This module widens the model so the passthrough transition is
IN the alphabet, and then characterises exactly which byte class escapes.

## The perimeter classes (byte predicates, stated without the adapter)

Three mutually exclusive classes of wire line, each a decidable predicate on
the INPUT BYTES only — none is defined as "whatever the router returns";
the router/byte-class correspondence is a THEOREM
(`classifyLine_act_iff` / `classifyLine_passthrough_iff` /
`classifyLine_refuse_iff`), not a definition:

* `inPerimeter` — **S, the mediation perimeter**: the trimmed line passes
  all seven pre-parse raw-wire guards (`Host.JsonWire.safe`), `Lean.Json.parse`
  accepts it, and the JSON has the strict `tools/call` shape
  (`toolsCallShape`: method is byte-exactly `"tools/call"` and
  `params.name` is a string). These lines are gate-decided before anything
  is forwarded.
* `refusedClass` — **R**: any of the seven pre-parse raw-wire guards rejects
  the line (`Host.JsonWire.safe = false`: monster exponent, duplicate/escaped object
  key, Unicode canonical-equivalent key, over-long mantissa, a number
  outside binary64 round-trip agreement, unpaired surrogate escape, or
  over-deep nesting). Blocked; never forwarded, never gate-decided.
* `escapes` — **the complement**: everything else. Forwarded child-bound
  with NO decision. This class is non-empty (witnesses below) — the
  passthrough IS a bypass of the child-input link, and the widened model
  says so instead of hiding the transition from the alphabet.

## Widened seam alphabet

`WEv` extends `Host.Channel.ChanEv` with the two host transitions the
W2-T6 alphabet excluded: `fwdEv` (P1 classify-passthrough — raw bytes to
the child, no decide event) and `refuseEv` (pre-parse refusal — client-bound
block, nothing forwarded). The widened step `wstep` routes by the DEPLOYED
router `Host.classifyLine` — the router is a derived observer of the
existing definition, never a new primitive — and only the `.act` branch
consults the gate.

## STEP 0 — non-vacuity on BOTH sides (this commit, before any
## characterisation proof)

* Inside S, genuinely mediated: `mediatedWitness` (a strict `tools/call`) —
  its widened run emits ONLY after a decide event, and when the gate blocks
  it, nothing is forwarded at all.
* Outside S, genuinely forwarded undecided: `malformedWitness` (invalid
  JSON), `bomWitness` (BOM-prefixed JSON), `misspelledWitness`
  (`"TOOLS/CALL"`) — each widened run is exactly `[fwdEv w]`: child-bound
  bytes, zero decide events.

## HONESTY

The widened alphabet covers P1 (classify passthrough), P2/P3 (gated
forward / retry as further decide steps) and the pre-parse refusal. It
still does NOT cover: P4 operator argv, P5 kernel-block client-stdout
egress, P6 response egress, P7–P9 telemetry/evidence. Model-level only;
the `rust/` ↔ model byte refinement remains the conformance-bridge
obligation, exactly as for `sealAdapter`.
-/

namespace Host.Perimeter

open Lean
open Host.Channel

/-! ## The byte classes -/

/-- The seam's unit of judgment: the line with ASCII whitespace trimmed —
    the same framing transformation `Host.classifyLine` applies. A byte
    function, prior to any parsing. -/
def trimmed (line : String) : String := line.trimAscii.toString

/-- Strict `tools/call` SHAPE, stated structurally on the parsed JSON value:
    the `method` field is a string byte-equal to `"tools/call"` and
    `params.name` is a string. Stated WITHOUT `Seal.toolsCall?`; the bridge
    to the router's matcher is the lemma `toolsCallShape_eq_toolsCall?`. -/
def toolsCallShape (j : Json) : Bool :=
  ((j.getObjVal? "method").toOption.bind (·.getStr?.toOption)
      == some "tools/call")
    && ((j.getObjVal? "params").toOption.bind
          (fun p => (p.getObjVal? "name").toOption.bind (·.getStr?.toOption))).isSome

/-- **The pre-parse stage.** All SEVEN raw-wire guards the router runs before
    `Json.parse`, in its order: the monster-exponent number guard, the
    byte-level duplicate/escaped object-key guard, the Unicode
    canonical-equivalence key guard, the pinned significant-digit bound, the
    binary64 round-trip agreement guard, the unpaired-surrogate-escape
    guard, and the nesting-depth bound.
    A line reaches the parser iff every one of them passes.

    Originally this module modelled `wireNumbersSafe` ALONE, which was the
    whole pre-parse stage at the time it was written. The next three guards
    landed on 2026-07-24/25, and the binary64-agreement guard and the
    surrogate/depth pair (A2 classes (b), (a) and (c)) on 2026-07-30; the
    refused class grew with each. The corresponding router theorems are
    `classifyLine_refuse_of_unsafe_keys`, `_unsafe_unicode_keys`,
    `_unsafe_digits`, `_unsafe_agreement`, `_unsafe_surrogates` and
    `_unsafe_depth` in `Host/Canonical.lean`. The guard list lives only in
    `Host.JsonWire.safe`; this perimeter wrapper adds the router's trimming. -/
def wireSafe (line : String) : Bool :=
  Host.JsonWire.safe (trimmed line)

/-- **R — the refused class.** Any of the seven pre-parse raw-wire guards
    rejects the line. A pure fold over the characters — bytes in, Bool out.
    These lines are blocked: never forwarded, never gate-decided. -/
def refusedClass (line : String) : Bool :=
  !(wireSafe line)

/-- **S — the mediation perimeter.** A decidable predicate on the input
    bytes, stated independently of the adapter: the trimmed line passes all
    seven pre-parse raw-wire guards (`Host.JsonWire.safe`), `Lean.Json.parse` accepts
    it, and the value has the strict
    `tools/call` shape. The characterisation theorems prove: a line is
    gate-decided before forwarding IFF it lies in S. -/
def inPerimeter (line : String) : Bool :=
  wireSafe line
    && (match Json.parse (trimmed line) with
        | .error _ => false
        | .ok j => toolsCallShape j)

/-- **The escaping class.** Neither refused nor in the perimeter: the line
    is forwarded child-bound with NO decision — malformed JSON,
    BOM-prefixed JSON, mis-spelled methods (`"TOOLS/CALL"`), and every
    other non-`tools/call` line. Non-empty (witnesses below): the
    passthrough is a real bypass of the child-input link. -/
def escapes (line : String) : Bool :=
  !refusedClass line && !inPerimeter line

/-- **Any top-level JSON array is outside the `tools/call` shape** — the
    batch case, proved structurally (no `Json.parse` needed: the value is
    given). `getObjVal?` on an `arr` is `none`, so `method` is absent and
    `toolsCallShape` is `false`. A batch of a thousand calls, or of one, is
    equally outside S. This is why S being "top-level objects only" is a
    theorem, not an accident. -/
theorem toolsCallShape_arr (elems : Array Json) :
    toolsCallShape (Json.arr elems) = false := by
  simp [toolsCallShape, Json.getObjVal?, Except.toOption]

/-- Consequence for S: a wire line whose trimmed bytes parse to a top-level
    array is never in the perimeter — it is forwarded, not mediated. -/
theorem inPerimeter_eq_false_of_parse_arr {line : String} (elems : Array Json)
    (h : Json.parse (trimmed line) = .ok (Json.arr elems)) :
    inPerimeter line = false := by
  simp [inPerimeter, h, toolsCallShape_arr]

/-- The three classes partition every line (definitional, but pinned so the
    trichotomy cannot drift). -/
theorem classes_partition (line : String) :
    (refusedClass line = true ∧ inPerimeter line = false ∧ escapes line = false)
    ∨ (refusedClass line = false ∧ inPerimeter line = true ∧ escapes line = false)
    ∨ (refusedClass line = false ∧ inPerimeter line = false ∧ escapes line = true) := by
  unfold escapes refusedClass inPerimeter
  cases wireSafe line
  · simp
  · cases Json.parse (trimmed line) with
    | error e => simp
    | ok j => cases htc : toolsCallShape j <;> simp [htc]

/-- Escaping excludes the perimeter. -/
theorem inPerimeter_eq_false_of_escapes {line : String}
    (h : escapes line = true) : inPerimeter line = false := by
  unfold escapes at h
  have h2 := (Bool.and_eq_true _ _).mp h
  simp only [Bool.not_eq_eq_eq_not, Bool.not_true] at h2
  exact h2.2

/-- Refusal excludes the perimeter. -/
theorem inPerimeter_eq_false_of_refused {line : String}
    (h : refusedClass line = true) : inPerimeter line = false := by
  unfold refusedClass at h
  unfold inPerimeter
  simp only [Bool.not_eq_true'] at h
  simp [h]

/-- The perimeter excludes escaping. -/
theorem escapes_eq_false_of_inPerimeter {line : String}
    (h : inPerimeter line = true) : escapes line = false := by
  unfold escapes; simp [h]

/-- Refusal excludes escaping. -/
theorem escapes_eq_false_of_refused {line : String}
    (h : refusedClass line = true) : escapes line = false := by
  unfold escapes; simp [h]

/-! ## The widened seam alphabet and run -/

/-- Widened seam event: `decideEv`/`emitEv` as in `Host.Channel.ChanEv`,
    plus the two transitions the W2-T6 alphabet excluded —
    `fwdEv` = P1 classify-passthrough (raw bytes CHILD-BOUND, no decision),
    `refuseEv` = pre-parse refusal (client-bound block, nothing forwarded). -/
inductive WEv where
  | decideEv (raw : SealV2.RawBytes) (d : SealV2.Decision)
  | emitEv (bytes : SealV2.CanonicalBytes)
  | fwdEv (raw : SealV2.RawBytes)
  | refuseEv (raw : SealV2.RawBytes)
  deriving Repr, BEq

/-- Widened trace, most-recent-first (the `ChanTrace` convention). -/
abbrev WTrace := List WEv

/-- One widened step. The ROUTER is the deployed `Host.classifyLine` — a
    derived observer of the existing definition, not a new primitive. Only
    the `.act` branch consults the gate; `.passthrough` forwards the raw
    line child-bound with NO decide event (the P1 transition, now inside
    the model); `.refuse` blocks with nothing forwarded. -/
def wstep (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (s : A.St × WTrace) (line : String) : A.St × WTrace :=
  match Host.classifyLine line with
  | .passthrough => (s.1, WEv.fwdEv line :: s.2)
  | .refuse => (s.1, WEv.refuseEv line :: s.2)
  | .act _ =>
      let st' := A.onVerdict s.1 line (gate line)
      (st', (A.emitsOn st').map WEv.emitEv ++ WEv.decideEv line (gate line) :: s.2)

/-- A widened run over an input stream, from the adapter's initial state
    and the empty trace. -/
def wrun (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (inputs : List String) : A.St × WTrace :=
  inputs.foldl (wstep A gate) (A.init, ([] : WTrace))

/-! ## STEP 0 — non-vacuity witnesses, BOTH sides

Concrete wire lines, with their widened runs computed and build-gated
(`#guard`): neither the mediated side nor the escaping side of the
perimeter is empty. See "Witness discipline" below for why the concrete
evaluations are `#guard`s and not `rfl` theorems. -/

/-- Inside S: a strict `tools/call` request. -/
def mediatedWitness : String :=
  "{\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"README.md\"}}}"

/-- Outside S, case 1: malformed JSON — `Lean.Json.parse` fails. -/
def malformedWitness : String := "{oops"

/-- Outside S, case 2: BOM-prefixed JSON. U+FEFF is not ASCII whitespace, so
    `trimAscii` keeps it and `Lean.Json.parse` fails on it. The payload
    behind the BOM is a byte-perfect `tools/call`. -/
def bomWitness : String :=
  "\uFEFF{\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\"}}"

/-- Outside S, case 3: the method spelled `"TOOLS/CALL"` — valid JSON, but
    the strict matcher is byte-exact, so it is not a `tools/call`. -/
def misspelledWitness : String :=
  "{\"method\":\"TOOLS/CALL\",\"params\":{\"name\":\"read_file\"}}"

/-- Outside S, case 4 — **the serious one: a JSON-RPC 2.0 BATCH**, a
    top-level JSON ARRAY. Unlike cases 1–3 this is NOT malformed: it is a
    well-formed, spec-compliant JSON-RPC request. `Seal.toolsCall?` calls
    `getObjVal? "method"` on the top-level value; on an array that is `none`,
    so `Host.classifyLine` returns `.passthrough` and the whole batch is
    relayed to the child undecided (`Ffi.lean` route `passthrough`,
    `rust/src/main.rs` relay). If the child honours batching, EVERY call in
    the array executes with no decision — a full mediation bypass on
    legitimate input. `toolsCallShape` inspects `method` on the top-level
    value too, so a batch is provably outside S BY CONSTRUCTION, not by
    accident: S is not silently "top-level objects only". -/
def batchWitness : String :=
  "[{\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"a\"}}},"
    ++ "{\"method\":\"tools/call\",\"params\":{\"name\":\"delete_all\",\"arguments\":{}}}]"

-- Class membership, computed on the bytes (build-gated):
#guard inPerimeter mediatedWitness
#guard !refusedClass mediatedWitness && !escapes mediatedWitness
#guard escapes malformedWitness
#guard escapes bomWitness
#guard escapes misspelledWitness
-- The batch array: well-formed JSON, parses fine, passes the number guard —
-- and is STILL outside S (not a `tools/call` shape at the top level), so it
-- escapes to the child undecided:
#guard escapes batchWitness
#guard !refusedClass batchWitness && !inPerimeter batchWitness

/-- Test gate: allows exactly the mediated witness with output `"OK"`. -/
def allowMediatedGate : SealV2.RawBytes → SealV2.Decision :=
  fun raw => if raw = mediatedWitness then .Allow "OK" else .Block

-- The widened runs, evaluated (build-gated). Inside S: the emit happens
-- ONLY after (strictly later in most-recent-first order than) the decide.
#guard (wrun sealAdapter allowMediatedGate [mediatedWitness]).2
  == [WEv.emitEv "OK",
      WEv.decideEv mediatedWitness (SealV2.Decision.Allow "OK")]
-- Inside S with a blocking gate: DECIDED, and nothing forwarded at all.
#guard (wrun sealAdapter blockGate [mediatedWitness]).2
  == [WEv.decideEv mediatedWitness SealV2.Decision.Block]
-- Outside S: child-bound bytes with ZERO decide events — forwarded
-- undecided, whatever the gate. All three real cases:
#guard (wrun sealAdapter allowMediatedGate [malformedWitness]).2
  == [WEv.fwdEv malformedWitness]
#guard (wrun sealAdapter allowMediatedGate [bomWitness]).2
  == [WEv.fwdEv bomWitness]
#guard (wrun sealAdapter allowMediatedGate [misspelledWitness]).2
  == [WEv.fwdEv misspelledWitness]
-- The JSON-RPC batch escapes the same way — child-bound, zero decide events:
#guard (wrun sealAdapter allowMediatedGate [batchWitness]).2
  == [WEv.fwdEv batchWitness]

/-! ### Witness discipline, stated honestly

`Lean.Json.parse` is a `partial` parser: the kernel CANNOT reduce it, so no
concrete classification of a specific wire line is provable by `rfl` or
`decide` without `native_decide` (banned here). The concrete witnesses are
therefore the build-gated `#guard`s above — compiler-evaluated, the build
goes red if any is wrong — and the THEOREM layer carries the run shape
generically: what a run does to a line of each class, for every gate. The
`#guard`s pin the class membership of the concrete messages; the theorems
pin what membership means. Neither is dressed up as the other. -/

/-- A passthrough-classified line is forwarded child-bound with NO decide
    event — for EVERY adapter and EVERY gate (the gate is never consulted:
    that is what "undecided" means). -/
theorem wrun_single_passthrough (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (line : String)
    (h : Host.classifyLine line = .passthrough) :
    (wrun A gate [line]).2 = [WEv.fwdEv line] := by
  simp [wrun, wstep, h]

/-- An act-classified line at an allowing gate: the emission exists and sits
    STRICTLY AFTER the decide event (most-recent-first order) — decided
    before forwarding. -/
theorem wrun_single_act_allow (gate : SealV2.RawBytes → SealV2.Decision)
    (line : String) (a : CanonicalAction) (out : SealV2.CanonicalBytes)
    (h : Host.classifyLine line = .act a) (hg : gate line = .Allow out) :
    (wrun sealAdapter gate [line]).2
      = [WEv.emitEv out, WEv.decideEv line (.Allow out)] := by
  simp [wrun, wstep, h, hg, sealAdapter]

/-- An act-classified line at a blocking gate: decided, and NOTHING is
    child-bound — a mediated line never leaks past a Block. -/
theorem wrun_single_act_block (gate : SealV2.RawBytes → SealV2.Decision)
    (line : String) (a : CanonicalAction)
    (h : Host.classifyLine line = .act a) (hg : gate line = .Block) :
    (wrun sealAdapter gate [line]).2 = [WEv.decideEv line .Block] := by
  simp [wrun, wstep, h, hg, sealAdapter]

/-- A refuse-classified line: blocked with nothing forwarded and nothing
    decided — for every adapter and gate. -/
theorem wrun_single_refuse (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (line : String)
    (h : Host.classifyLine line = .refuse) :
    (wrun A gate [line]).2 = [WEv.refuseEv line] := by
  simp [wrun, wstep, h]

/-- The refuse class HAS a kernel-checkable concrete member (the pre-parse
    number guard is a total fold, so the kernel can evaluate it — unlike
    `Json.parse`): a monster decimal exponent classifies `.refuse` by
    `Host.classifyLine_refuse_of_unsafe`, with the guard value pinned by
    `#guard` below. -/
def monsterExponentWitness : String := "{\"n\":1e99999999999}"

#guard refusedClass monsterExponentWitness
#guard (wrun sealAdapter allowMediatedGate [monsterExponentWitness]).2
  == [WEv.refuseEv monsterExponentWitness]

/-! ## The characterisation — router ↔ byte classes

The connecting theorems the anti-tautology kill line demands: the byte
classes were DEFINED without the router; these lemmas PROVE the deployed
router realises exactly them. -/

-- The `<;>` applies one shared `simp` set to both `by_cases` branches, so
-- some lemmas are unused in one branch — silence the resulting lint here.
set_option linter.unusedSimpArgs false in
/-- The independent shape predicate coincides with the router's matcher:
    `toolsCallShape` (stated structurally on the JSON value) is exactly
    `Seal.toolsCall?` success. This is the bridge that keeps S from being
    "whatever the adapter decides". -/
theorem toolsCallShape_eq_toolsCall? (j : Json) :
    toolsCallShape j = (Seal.toolsCall? j).isSome := by
  unfold toolsCallShape Seal.toolsCall?
  cases hm : (j.getObjVal? "method").toOption with
  | none => simp [hm]
  | some mj =>
    cases hs : mj.getStr?.toOption with
    | none => simp [hm, hs]
    | some m =>
      cases hp : (j.getObjVal? "params").toOption with
      | none => by_cases he : m = "tools/call" <;> simp [hm, hs, hp, he, bne]
      | some p =>
        cases hn : (p.getObjVal? "name").toOption with
        | none => by_cases he : m = "tools/call" <;> simp [hm, hs, hp, hn, he, bne]
        | some nj =>
          cases hns : nj.getStr?.toOption with
          | none =>
            by_cases he : m = "tools/call" <;> simp [hm, hs, hp, hn, hns, he, bne]
          | some n =>
            by_cases he : m = "tools/call" <;> simp [hm, hs, hp, hn, hns, he, bne]

/-- The router refuses EXACTLY the refused class R. -/
theorem classifyLine_refuse_iff (line : String) :
    Host.classifyLine line = .refuse ↔ refusedClass line = true := by
  simp only [Host.classifyLine, refusedClass, wireSafe, trimmed]
  cases hg : Host.JsonWire.safe line.trimAscii.toString <;> simp
  cases hp : Json.parse line.trimAscii.toString with
  | error e => simp
  | ok j =>
    cases ht : Seal.toolsCall? j with
    | none => simp [ht]
    | some p => cases p with | mk n a => simp [ht]

/-- The router gate-decides EXACTLY the perimeter S. -/
theorem classifyLine_act_iff (line : String) :
    (∃ a, Host.classifyLine line = .act a) ↔ inPerimeter line = true := by
  simp only [Host.classifyLine, inPerimeter, wireSafe, trimmed]
  cases hg : Host.JsonWire.safe line.trimAscii.toString <;> simp
  cases hp : Json.parse line.trimAscii.toString with
  | error e => simp
  | ok j =>
    cases ht : Seal.toolsCall? j with
    | none => simp [ht, toolsCallShape_eq_toolsCall?]
    | some p =>
      cases p with | mk n a => simp [ht, toolsCallShape_eq_toolsCall?]

/-- The router passes through EXACTLY the escaping class. -/
theorem classifyLine_passthrough_iff (line : String) :
    Host.classifyLine line = .passthrough ↔ escapes line = true := by
  simp only [Host.classifyLine, escapes, refusedClass, inPerimeter, wireSafe,
    trimmed]
  cases hg : Host.JsonWire.safe line.trimAscii.toString <;> simp
  cases hp : Json.parse line.trimAscii.toString with
  | error e => simp
  | ok j =>
    cases ht : Seal.toolsCall? j with
    | none => simp [ht, toolsCallShape_eq_toolsCall?]
    | some p =>
      cases p with | mk n a => simp [ht, toolsCallShape_eq_toolsCall?]

/-! ## The characterisation — runs

Decide/forward membership in a widened run, characterised by the byte
classes. Step lemma first, then the fold, then the capstone. -/

/-- One widened step adds a decide event for `raw` iff `raw` is the line
    processed AND that line lies in S (and the verdict is the gate's). -/
theorem wstep_decide_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (s : A.St × WTrace)
    (line raw : String) (d : SealV2.Decision) :
    WEv.decideEv raw d ∈ (wstep A gate s line).2 ↔
      WEv.decideEv raw d ∈ s.2
        ∨ (raw = line ∧ d = gate line ∧ inPerimeter line = true) := by
  unfold wstep
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

/-- One widened step adds a forward event for `raw` iff `raw` is the line
    processed AND that line escapes. -/
theorem wstep_fwd_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (s : A.St × WTrace)
    (line raw : String) :
    WEv.fwdEv raw ∈ (wstep A gate s line).2 ↔
      WEv.fwdEv raw ∈ s.2 ∨ (raw = line ∧ escapes line = true) := by
  unfold wstep
  cases h : Host.classifyLine line with
  | passthrough =>
    have hesc := (classifyLine_passthrough_iff line).mp h
    rw [List.mem_cons]
    simp only [WEv.fwdEv.injEq, hesc, and_true]
    exact or_comm
  | refuse =>
    have hesc : escapes line = false :=
      escapes_eq_false_of_refused ((classifyLine_refuse_iff line).mp h)
    simp [List.mem_cons, hesc]
  | act a =>
    have hesc : escapes line = false :=
      escapes_eq_false_of_inPerimeter ((classifyLine_act_iff line).mp ⟨a, h⟩)
    simp [List.mem_append, List.mem_map, List.mem_cons, hesc]

/-- Decide membership over a fold from any start state. -/
theorem wrun_from_decide_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (raw : String)
    (d : SealV2.Decision) :
    ∀ (inputs : List String) (s : A.St × WTrace),
      WEv.decideEv raw d ∈ (inputs.foldl (wstep A gate) s).2 ↔
        WEv.decideEv raw d ∈ s.2
          ∨ (raw ∈ inputs ∧ d = gate raw ∧ inPerimeter raw = true) := by
  intro inputs
  induction inputs with
  | nil => intro s; simp
  | cons line rest ih =>
    intro s
    rw [List.foldl_cons, ih (wstep A gate s line), wstep_decide_mem]
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

/-- Forward membership over a fold from any start state. -/
theorem wrun_from_fwd_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (raw : String) :
    ∀ (inputs : List String) (s : A.St × WTrace),
      WEv.fwdEv raw ∈ (inputs.foldl (wstep A gate) s).2 ↔
        WEv.fwdEv raw ∈ s.2 ∨ (raw ∈ inputs ∧ escapes raw = true) := by
  intro inputs
  induction inputs with
  | nil => intro s; simp
  | cons line rest ih =>
    intro s
    rw [List.foldl_cons, ih (wstep A gate s line), wstep_fwd_mem]
    constructor
    · rintro ((hmem | ⟨rfl, hesc⟩) | ⟨hin, hesc⟩)
      · exact Or.inl hmem
      · exact Or.inr ⟨List.mem_cons_self, hesc⟩
      · exact Or.inr ⟨List.mem_cons_of_mem _ hin, hesc⟩
    · rintro (hmem | ⟨hin, hesc⟩)
      · exact Or.inl (Or.inl hmem)
      · rcases List.mem_cons.mp hin with rfl | hin'
        · exact Or.inl (Or.inr ⟨rfl, hesc⟩)
        · exact Or.inr ⟨hin', hesc⟩

/-- **A widened run gate-decides a line iff it was input AND lies in S.**
    Holds for EVERY adapter and EVERY gate: S is a property of the bytes. -/
theorem wrun_decide_iff (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (inputs : List String)
    (raw : String) :
    (∃ d, WEv.decideEv raw d ∈ (wrun A gate inputs).2) ↔
      raw ∈ inputs ∧ inPerimeter raw = true := by
  unfold wrun
  constructor
  · rintro ⟨d, hd⟩
    rcases (wrun_from_decide_mem A gate raw d inputs _).mp hd with
      h0 | ⟨hin, -, hip⟩
    · nomatch h0
    · exact ⟨hin, hip⟩
  · rintro ⟨hin, hip⟩
    exact ⟨gate raw, (wrun_from_decide_mem A gate raw (gate raw) inputs _).mpr
      (Or.inr ⟨hin, rfl, hip⟩)⟩

/-- **A widened run forwards a line child-bound undecided iff it was input
    AND escapes.** Holds for every adapter and every gate. -/
theorem wrun_fwd_iff (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (inputs : List String)
    (raw : String) :
    WEv.fwdEv raw ∈ (wrun A gate inputs).2 ↔
      raw ∈ inputs ∧ escapes raw = true := by
  unfold wrun
  rw [wrun_from_fwd_mem]
  simp

/-- **THE MEDIATION PERIMETER (K4 characterisation).** For every input line
    of every widened run, at every adapter and every gate: the line is
    gate-decided IFF it lies in S (`inPerimeter`, a decidable predicate on
    the input bytes, stated independently of the adapter), and it is
    forwarded child-bound without any decision IFF it escapes
    (outside S and not refused). -/
theorem mediation_perimeter (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (inputs : List String)
    (line : String) (hin : line ∈ inputs) :
    ((∃ d, WEv.decideEv line d ∈ (wrun A gate inputs).2)
        ↔ inPerimeter line = true)
    ∧ (WEv.fwdEv line ∈ (wrun A gate inputs).2 ↔ escapes line = true) := by
  refine ⟨?_, ?_⟩
  · rw [wrun_decide_iff]; simp [hin]
  · rw [wrun_fwd_iff]; simp [hin]

/-- Exclusivity: a decided line is NEVER forwarded undecided (and vice
    versa, by `classes_partition`). -/
theorem decided_never_forwarded (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (inputs : List String)
    (line : String)
    (hdec : ∃ d, WEv.decideEv line d ∈ (wrun A gate inputs).2) :
    WEv.fwdEv line ∉ (wrun A gate inputs).2 := by
  intro hfwd
  have hip := ((wrun_decide_iff A gate inputs line).mp hdec).2
  have hesc := ((wrun_fwd_iff A gate inputs line).mp hfwd).2
  rw [escapes_eq_false_of_inPerimeter hip] at hesc
  cases hesc

/-! ## The verdict: non-bypass over the widened alphabet

`channel_preserves_non_bypass` survives the widening ONLY for the gated
sink. Over the whole child-input link it FAILS — as expected: passthrough
IS a bypass. Both halves stated and proved. -/

/-- Widened-channel mediation, the property W2-T6 would need over the full
    child-input link: every gated emission has a strictly earlier Allow of
    its bytes, and every passthrough forward has a strictly earlier decision
    on its line — the WEAKEST possible reading (any decision at all, not
    even an Allow, would do). -/
def mediatedChildBound (tr : WTrace) : Prop :=
  (∀ post b pre, tr = post ++ WEv.emitEv b :: pre →
      ∃ raw, WEv.decideEv raw (SealV2.Decision.Allow b) ∈ pre) ∧
  (∀ post r pre, tr = post ++ WEv.fwdEv r :: pre →
      ∃ d, WEv.decideEv r d ∈ pre)

/-- **NON-BYPASS FAILS OVER THE WIDENED ALPHABET.** For EVERY adapter and
    EVERY gate — including the live `SealV2.decide` — any escaping line
    breaks widened mediation, even in its weakest form: the forward carries
    no prior decision of any kind. The escaping class is witnessed
    non-empty by the Step-0 `#guard`s (malformed JSON, BOM-prefixed JSON,
    `"TOOLS/CALL"`). This is the honest verdict, not a rescued theorem. -/
theorem widened_non_bypass_fails (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision) (line : String)
    (hesc : escapes line = true) :
    ¬ mediatedChildBound (wrun A gate [line]).2 := by
  intro h
  have htr : (wrun A gate [line]).2 = [WEv.fwdEv line] :=
    wrun_single_passthrough A gate line
      ((classifyLine_passthrough_iff line).mpr hesc)
  obtain ⟨d, hd⟩ := h.2 [] line [] (by simp [htr])
  nomatch hd

/-- The failure pinned at the deployed model and the LIVE gate. -/
theorem widened_non_bypass_fails_live (state : SealV2.ApprovalState)
    (line : String) (hesc : escapes line = true) :
    ¬ mediatedChildBound
        (wrun sealAdapter (fun raw => SealV2.decide raw state) [line]).2 :=
  widened_non_bypass_fails sealAdapter _ line hesc

/-! ## The salvage: what survives the widening

The GATED SINK keeps its theorem: for any O1∧O2 adapter, on every widened
run, every `emitEv` is still preceded strictly earlier by an Allow decide
of byte-identical output. So the widening breaks mediation EXACTLY at the
P1 forward and nowhere else — and `sealAdapter_O1`/`sealAdapter_O2` are
not made vacuous: they are re-discharged here over the widened runs. -/

/-- Gated-sink mediation over the widened trace. -/
def emitsPrecededByAllowW (tr : WTrace) : Prop :=
  ∀ post b pre, tr = post ++ WEv.emitEv b :: pre →
    ∃ raw, WEv.decideEv raw (SealV2.Decision.Allow b) ∈ pre

/-- Positional form for the induction (the `Guarded` convention, widened:
    fwd/refuse events carry no emission obligation). -/
def GuardedW : WTrace → Prop
  | [] => True
  | WEv.emitEv b :: rest =>
      (∃ raw, WEv.decideEv raw (SealV2.Decision.Allow b) ∈ rest) ∧ GuardedW rest
  | WEv.decideEv _ _ :: rest => GuardedW rest
  | WEv.fwdEv _ :: rest => GuardedW rest
  | WEv.refuseEv _ :: rest => GuardedW rest

theorem guardedW_split (post : WTrace) :
    ∀ (b : SealV2.CanonicalBytes) (pre : WTrace),
      GuardedW (post ++ WEv.emitEv b :: pre) →
      ∃ raw, WEv.decideEv raw (SealV2.Decision.Allow b) ∈ pre := by
  induction post with
  | nil => intro b pre h; exact h.1
  | cons e post ih =>
    intro b pre h
    cases e with
    | emitEv b' => exact ih b pre h.2
    | decideEv r d => exact ih b pre h
    | fwdEv r => exact ih b pre h
    | refuseEv r => exact ih b pre h

theorem guardedW_precededByAllow (tr : WTrace) (h : GuardedW tr) :
    emitsPrecededByAllowW tr :=
  fun post b pre heq => guardedW_split post b pre (heq ▸ h)

theorem guardedW_append_emits (l : List SealV2.CanonicalBytes) (tr : WTrace)
    (h : ∀ b ∈ l, ∃ raw, WEv.decideEv raw (SealV2.Decision.Allow b) ∈ tr)
    (htr : GuardedW tr) : GuardedW (l.map WEv.emitEv ++ tr) := by
  induction l with
  | nil => simpa using htr
  | cons b bs ih =>
    refine ⟨?_, ih (fun b' hb' => h b' (List.mem_cons_of_mem _ hb'))⟩
    obtain ⟨raw, hmem⟩ := h b List.mem_cons_self
    exact ⟨raw, List.mem_append_right _ hmem⟩

/-- The license invariant and guardedness survive every WIDENED step: the
    P1 forward and the refusal touch neither the adapter state nor the
    emission obligations. -/
theorem wrun_invariant (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (hO1 : O1 A) (hO2 : O2 A) :
    ∀ (inputs : List String) (s : A.St × WTrace),
      (∀ p ∈ A.licensed s.1,
        WEv.decideEv p.1 (SealV2.Decision.Allow p.2) ∈ s.2) →
      GuardedW s.2 →
      (∀ p ∈ A.licensed (inputs.foldl (wstep A gate) s).1,
        WEv.decideEv p.1 (SealV2.Decision.Allow p.2)
          ∈ (inputs.foldl (wstep A gate) s).2) ∧
      GuardedW (inputs.foldl (wstep A gate) s).2 := by
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
        simp only [wstep, h] at hp ⊢
        exact List.mem_cons_of_mem _ (h1 p hp)
      · simp only [wstep, h]
        exact h2
    | refuse =>
      apply ih
      · intro p hp
        simp only [wstep, h] at hp ⊢
        exact List.mem_cons_of_mem _ (h1 p hp)
      · simp only [wstep, h]
        exact h2
    | act a =>
      apply ih
      · intro p hp
        simp only [wstep, h] at hp ⊢
        rcases hO2.2 s.1 line (gate line) p hp with hold | ⟨out, hd, rfl⟩
        · exact List.mem_append_right _ (List.mem_cons_of_mem _ (h1 p hold))
        · refine List.mem_append_right _ ?_
          rw [hd]
          exact List.mem_cons_self
      · simp only [wstep, h]
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

/-- **The salvage.** Any O1∧O2 adapter keeps gated-sink mediation on every
    WIDENED run, at every gate: emissions are still Allow-preceded. The
    widened failure above is therefore exactly the P1 forward. -/
theorem wchannel_gated_sink_non_bypass (A : Adapter)
    (hO1 : O1 A) (hO2 : O2 A)
    (gate : SealV2.RawBytes → SealV2.Decision) (inputs : List String) :
    emitsPrecededByAllowW (wrun A gate inputs).2 := by
  have h := wrun_invariant A gate hO1 hO2 inputs (A.init, [])
    (fun p hp => nomatch (hO2.1 ▸ hp)) trivial
  exact guardedW_precededByAllow _ h.2

/-- The salvage at the deployed model and the live gate. -/
theorem widened_gated_sink_survives (state : SealV2.ApprovalState)
    (inputs : List String) :
    emitsPrecededByAllowW
      (wrun sealAdapter (fun raw => SealV2.decide raw state) inputs).2 :=
  wchannel_gated_sink_non_bypass sealAdapter sealAdapter_O1 sealAdapter_O2
    _ inputs

/-! ## Axiom pins

Every theorem in this module sits on the classical baseline
`[propext, Classical.choice, Quot.sound]` or tighter — no `sorryAx`, no
`native_decide`/`Lean.ofReduceBool`, no custom axiom. Pinned with
`#guard_msgs` so any drift fails the build here. -/

/-- info: 'Host.Perimeter.classes_partition' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms classes_partition
/-- info: 'Host.Perimeter.toolsCallShape_arr' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms toolsCallShape_arr
/-- info: 'Host.Perimeter.inPerimeter_eq_false_of_parse_arr' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms inPerimeter_eq_false_of_parse_arr
/-- info: 'Host.Perimeter.inPerimeter_eq_false_of_escapes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms inPerimeter_eq_false_of_escapes
/-- info: 'Host.Perimeter.inPerimeter_eq_false_of_refused' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms inPerimeter_eq_false_of_refused
/-- info: 'Host.Perimeter.escapes_eq_false_of_inPerimeter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms escapes_eq_false_of_inPerimeter
/-- info: 'Host.Perimeter.escapes_eq_false_of_refused' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms escapes_eq_false_of_refused
/-- info: 'Host.Perimeter.wrun_single_passthrough' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wrun_single_passthrough
/-- info: 'Host.Perimeter.wrun_single_act_allow' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wrun_single_act_allow
/-- info: 'Host.Perimeter.wrun_single_act_block' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wrun_single_act_block
/-- info: 'Host.Perimeter.wrun_single_refuse' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wrun_single_refuse
/-- info: 'Host.Perimeter.toolsCallShape_eq_toolsCall?' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms toolsCallShape_eq_toolsCall?
/-- info: 'Host.Perimeter.classifyLine_refuse_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms classifyLine_refuse_iff
/-- info: 'Host.Perimeter.classifyLine_act_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms classifyLine_act_iff
/-- info: 'Host.Perimeter.classifyLine_passthrough_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms classifyLine_passthrough_iff
/-- info: 'Host.Perimeter.wstep_decide_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wstep_decide_mem
/-- info: 'Host.Perimeter.wstep_fwd_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wstep_fwd_mem
/-- info: 'Host.Perimeter.wrun_from_decide_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wrun_from_decide_mem
/-- info: 'Host.Perimeter.wrun_from_fwd_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wrun_from_fwd_mem
/-- info: 'Host.Perimeter.wrun_decide_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wrun_decide_iff
/-- info: 'Host.Perimeter.wrun_fwd_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wrun_fwd_iff
/-- info: 'Host.Perimeter.mediation_perimeter' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms mediation_perimeter
/-- info: 'Host.Perimeter.decided_never_forwarded' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms decided_never_forwarded
/-- info: 'Host.Perimeter.widened_non_bypass_fails' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms widened_non_bypass_fails
/-- info: 'Host.Perimeter.widened_non_bypass_fails_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms widened_non_bypass_fails_live
/-- info: 'Host.Perimeter.guardedW_split' does not depend on any axioms -/
#guard_msgs in #print axioms guardedW_split
/-- info: 'Host.Perimeter.guardedW_precededByAllow' does not depend on any axioms -/
#guard_msgs in #print axioms guardedW_precededByAllow
/-- info: 'Host.Perimeter.guardedW_append_emits' does not depend on any axioms -/
#guard_msgs in #print axioms guardedW_append_emits
/-- info: 'Host.Perimeter.wrun_invariant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wrun_invariant
/-- info: 'Host.Perimeter.wchannel_gated_sink_non_bypass' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms wchannel_gated_sink_non_bypass
/-- info: 'Host.Perimeter.widened_gated_sink_survives' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms widened_gated_sink_survives

end Host.Perimeter
