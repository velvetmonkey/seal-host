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

* `inPerimeter` — **S, the mediation perimeter**: the trimmed line has no
  pathological numeric exponent, `Lean.Json.parse` accepts it, and the JSON
  has the strict `tools/call` shape (`toolsCallShape`: method is
  byte-exactly `"tools/call"` and `params.name` is a string). These lines
  are gate-decided before anything is forwarded.
* `refusedClass` — **R**: the pre-parse number guard rejects the line
  (`Seal.JsonUtil.wireNumbersSafe = false`). Blocked; never forwarded,
  never gate-decided.
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

/-- **R — the refused class.** The pre-parse number guard rejects the line:
    an unquoted JSON number carries a decimal exponent longer than
    `Seal.JsonUtil.maxExponentDigits`. A pure fold over the characters —
    bytes in, Bool out. These lines are blocked: never forwarded, never
    gate-decided. -/
def refusedClass (line : String) : Bool :=
  !(Seal.JsonUtil.wireNumbersSafe (trimmed line))

/-- **S — the mediation perimeter.** A decidable predicate on the input
    bytes, stated independently of the adapter: the trimmed line passes the
    number guard, `Lean.Json.parse` accepts it, and the value has the strict
    `tools/call` shape. The characterisation theorems prove: a line is
    gate-decided before forwarding IFF it lies in S. -/
def inPerimeter (line : String) : Bool :=
  Seal.JsonUtil.wireNumbersSafe (trimmed line)
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

/-- The three classes partition every line (definitional, but pinned so the
    trichotomy cannot drift). -/
theorem classes_partition (line : String) :
    (refusedClass line = true ∧ inPerimeter line = false ∧ escapes line = false)
    ∨ (refusedClass line = false ∧ inPerimeter line = true ∧ escapes line = false)
    ∨ (refusedClass line = false ∧ inPerimeter line = false ∧ escapes line = true) := by
  unfold escapes refusedClass inPerimeter
  cases h : Seal.JsonUtil.wireNumbersSafe (trimmed line) <;>
    simp [h] <;> cases hp : Json.parse (trimmed line) <;> simp [hp]

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

-- Class membership, computed on the bytes (build-gated):
#guard inPerimeter mediatedWitness
#guard !refusedClass mediatedWitness && !escapes mediatedWitness
#guard escapes malformedWitness
#guard escapes bomWitness
#guard escapes misspelledWitness

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

end Host.Perimeter
