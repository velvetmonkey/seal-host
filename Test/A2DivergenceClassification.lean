/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Canonical
import Host.Step

/-!
# A2 divergence classification: the criterion, the fail-closed class, and the
# per-case pins

`CLAIMS.md` names assumption **A2**: two nominally strict parsers may disagree,
so the non-bypass theorem can hold of the host's parsed event while the child
executes a different one. Eighteen concrete Rust(serde)/Lean parser
disagreements are recorded by `rust/tests/external_json_corpus.rs` over the
JSONTestSuite `i_*` class. This module states the classification criterion
formally, proves what is provable inside the Lean model, and pins every
concrete per-line fact as a build-gated `#guard`.

## The criterion

The deployed routing decision factors through `Host.classifyLine`
(`Host/Step.lean`: `stepImpl`'s route is exactly
`stepRoute (classifyLine line) verdicts`). Write

  `outcome line verdicts = stepRoute (classifyLine line) verdicts`.

For a wire line `ℓ` on which the Lean view and another parser disagree, the
disagreement is classified by how it can move `outcome` and whether it can
decouple the judged event from the executed one:

* **inert** — `outcome` is unchanged under both readings AND every conformant
  child parser that accepts the forwarded bytes extracts the same
  `(tool, arguments)` the kernel judged. Purely representational.
* **fail-closed** — `classifyLine ℓ = .refuse`. Then `outcome ℓ v = .block`
  for EVERY verdict list `v` (`refuse_fail_closed` below): the line is never
  forwarded and never passed through, so the disagreement can only move the
  outcome toward refusal. Nothing reaches the child, so no judged/executed
  pair exists to decouple.
* **consequential** — `classifyLine ℓ = .act a` while another parser rejects
  `ℓ` or reads a different event from the same bytes. The outcome can be
  `.forward` (under an all-allow verdict list, `stepRoute_act_forward_iff`),
  i.e. it moves toward acceptance relative to the stricter reading, and the
  child's execution of the raw forwarded bytes is bound to `a` only by
  assumption A2 — the exact gap the assumption names.

Of the eighteen recorded divergences at this revision, fourteen are
consequential (`rust=NotAct lean=Act`) and four are fail-closed
(`rust=Act lean=Refuse`). The inert class is EMPTY: every recorded case is an
act/non-act split, never a representational difference.

## Proof discipline on this toolchain

Evaluating a `String` function in kernel whnf blows the recursion budget on
this toolchain (byte-backed `String`), so a concrete-string guard fact cannot
be a kernel theorem without `native_decide` — which this module excludes.
Following the repo convention (`Seal/NumberGuardTheorems.lean`,
`Host/CanonicalL0Liveness.lean`):

* every GENERAL statement (criterion, guard ⇒ refuse ⇒ block-under-all-
  verdicts) is a kernel THEOREM, axiom-pinned by `#print axioms` below;
* every CONCRETE per-line fact is a `#guard` — the compiler evaluates the
  production classifier on the exact wire line at elaboration time; a failing
  guard fails the build; no axiom is introduced.
-/

namespace Host.A2Classify

open Lean Host

/-! ## The criterion, formal part -/

/-- The deployed mediation outcome of one wire line as a function of the
    kernel verdict list. Not a new decision procedure: it restates the
    factoring `Host/Step.lean` documents — `Ffi.stepImpl` routes by exactly
    `stepRoute (classifyLine line) verdicts`. The Rust serde view appears
    nowhere: the production gating decision depends only on the Lean parse. -/
def outcome (line : String) (verdicts : List Verdict) : StepRoute :=
  stepRoute (classifyLine line) verdicts

@[simp] theorem outcome_factors (line : String) (verdicts : List Verdict) :
    outcome line verdicts = stepRoute (classifyLine line) verdicts := rfl

/-- **Fail-closed** (criterion, formal): the line's outcome is `.block` under
    every verdict list — the strongest refusal-direction statement expressible
    in the routing core. -/
def FailClosed (line : String) : Prop :=
  ∀ verdicts : List Verdict, outcome line verdicts = .block

/-- A refused classification is fail-closed: blocked for every verdict list,
    independent of policy, kernels, and approvals. -/
theorem refuse_fail_closed {line : String}
    (h : classifyLine line = .refuse) : FailClosed line := by
  intro verdicts
  rw [outcome_factors, h, stepRoute_refuse]

/-- A fail-closed line never forwards — no verdict list reaches the child. -/
theorem failClosed_never_forwards {line : String} (h : FailClosed line)
    (verdicts : List Verdict) : outcome line verdicts ≠ .forward := by
  rw [h verdicts]; exact fun hc => StepRoute.noConfusion hc

/-- A fail-closed line is never passed through — the fail-open direction is
    closed as well. -/
theorem failClosed_never_passes_through {line : String} (h : FailClosed line)
    (verdicts : List Verdict) : outcome line verdicts ≠ .passthrough := by
  rw [h verdicts]; exact fun hc => StepRoute.noConfusion hc

/-! ## The eighteen concrete wire lines

Each is the exact line `rust/tests/external_json_corpus.rs` builds: the fixed
`tools/call` envelope (`CALL_PREFIX`/`CALL_SUFFIX`, byte-identical below)
around the byte-exact JSONTestSuite vector. Every vector is pure ASCII with no
trailing newline, so the literals below are byte-for-byte the harness lines
(cross-checked against the corpus files at build review time). -/

/-- `rust/tests/external_json_corpus.rs:24` `CALL_PREFIX`. -/
def callPrefix : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"external.json_corpus\",\"arguments\":"

/-- `rust/tests/external_json_corpus.rs:26` `CALL_SUFFIX`. -/
def callSuffix : String := "}}"

def envelope (vector : String) : String := callPrefix ++ vector ++ callSuffix

-- The four `rust=Act lean=Refuse` lines (the fail-closed class).
def underflowLine  : String := envelope "[123e-10000000]"
def tooBigPosLine  : String := envelope "[100000000000000000000]"
def tooBigNegLine  : String := envelope "[-123123123123123123123123123123]"
def veryBigNegLine : String := envelope
  "[-237462374673276894279832749832423479823246327846]"

-- The fourteen `rust=NotAct lean=Act` lines (the consequential class).
def negIntHugeExpLine    : String := envelope "[-1e+9999]"
def posDoubleHugeExpLine : String := envelope "[1.5e+9999]"
def realNegOverflowLine  : String := envelope "[-123123e100000]"
def realPosOverflowLine  : String := envelope "[123123e100000]"
def nested500Line        : String := envelope
  (String.ofList (List.replicate 500 '[' ++ List.replicate 500 ']'))
def surrogate2ndMissingLine   : String := envelope "[\"\\uDADA\"]"
def surrogate2ndInvalidLine   : String := envelope "[\"\\uD888\\u1234\"]"
def surrogateEscapeValidLine  : String := envelope "[\"\\uD800\\n\"]"
def surrogatePairLine         : String := envelope "[\"\\uDd1ea\"]"
def surrogatesEscapeValidLine : String := envelope "[\"\\uD800\\uD800\\n\"]"
def lonelySurrogateLine       : String := envelope "[\"\\ud800\"]"
def invalidSurrogateLine      : String := envelope "[\"\\ud800abc\"]"
def invertedSurrogatesLine    : String := envelope "[\"\\uDd1e\\uD834\"]"
def loneSecondSurrogateLine   : String := envelope "[\"\\uDFAA\"]"

/-! ## Discriminators (no `DecidableEq` on `LineClass`; these are total and
    transparent) -/

def isRefuse : LineClass → Bool
  | .refuse => true
  | _ => false

def isActOn (tool : String) : LineClass → Bool
  | .act a => a.tool == tool
  | _ => false

def actArgs? : LineClass → Option String
  | .act a => some a.argsJson.compress
  | _ => none

/-! ## Per-line pins, fail-closed class

For each of the four lines: (a) the exact raw-wire guard that fires, and
(b) the resulting classification. `[123e-10000000]` carries an 8-digit
exponent run, over `maxExponentDigits = 6` (`Seal/JsonUtil.lean`
`wireNumbersSafe`); the other three carry 21/30/48 significant mantissa
digits, over the 18-digit `wireDigitsSafe` bound. -/

#guard Seal.JsonUtil.wireNumbersSafe underflowLine.trimAscii.toString = false
#guard Seal.JsonUtil.wireDigitsSafe tooBigPosLine.trimAscii.toString = false
#guard Seal.JsonUtil.wireDigitsSafe tooBigNegLine.trimAscii.toString = false
#guard Seal.JsonUtil.wireDigitsSafe veryBigNegLine.trimAscii.toString = false

#guard isRefuse (classifyLine underflowLine)
#guard isRefuse (classifyLine tooBigPosLine)
#guard isRefuse (classifyLine tooBigNegLine)
#guard isRefuse (classifyLine veryBigNegLine)

/-- The four `rust=Act lean=Refuse` divergence lines. -/
def failClosedLines : List String :=
  [underflowLine, tooBigPosLine, tooBigNegLine, veryBigNegLine]

/-- **Every recorded `rust=Act lean=Refuse` divergence is fail-closed.** The
    four guard hypotheses are the exact `Bool` facts pinned by the `#guard`s
    above (build-time evaluation of the production guards on the exact wire
    lines); given them, each line is blocked under every verdict list — never
    forwarded, never passed through. The Rust serde view reading these lines
    as acts is a harness observation with no production decision path:
    `outcome` depends only on `classifyLine`. -/
theorem act_refuse_divergences_fail_closed
    (h1 : Seal.JsonUtil.wireNumbersSafe underflowLine.trimAscii.toString = false)
    (h2 : Seal.JsonUtil.wireDigitsSafe tooBigPosLine.trimAscii.toString = false)
    (h3 : Seal.JsonUtil.wireDigitsSafe tooBigNegLine.trimAscii.toString = false)
    (h4 : Seal.JsonUtil.wireDigitsSafe veryBigNegLine.trimAscii.toString = false) :
    ∀ line ∈ failClosedLines, FailClosed line := by
  intro line hmem
  simp only [failClosedLines, List.mem_cons, List.not_mem_nil, or_false] at hmem
  rcases hmem with h | h | h | h <;> subst h
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe _ h1)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_digits _ h2)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_digits _ h3)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_digits _ h4)

/-! ## Per-line pins, consequential class

Each of the fourteen lines classifies `.act` on tool `external.json_corpus`:
the kernel judges an event and, under an all-allow verdict list, the raw bytes
forward (`stepRoute_act_forward_iff`). For the nine lone-surrogate lines the
JUDGED arguments are pinned exactly: every unpaired surrogate escape in the
wire bytes appears as U+FFFD in the judged `CanonicalAction`, while the
forwarded bytes still carry the original `\uD800`-family escapes —
`docs/V31-DOWNSTREAM-PARSER-AGREEMENT.md` records four real downstream parsers
extracting the raw surrogates and a fifth rejecting the frame outright. The
judged-event/executed-event decoupling is therefore witnessed, not
hypothesized. -/

#guard isActOn "external.json_corpus" (classifyLine negIntHugeExpLine)
#guard isActOn "external.json_corpus" (classifyLine posDoubleHugeExpLine)
#guard isActOn "external.json_corpus" (classifyLine realNegOverflowLine)
#guard isActOn "external.json_corpus" (classifyLine realPosOverflowLine)
#guard isActOn "external.json_corpus" (classifyLine nested500Line)

#guard actArgs? (classifyLine surrogate2ndMissingLine)   == some "[\"\uFFFD\"]"
#guard actArgs? (classifyLine surrogate2ndInvalidLine)   == some "[\"\uFFFD\u1234\"]"
#guard actArgs? (classifyLine surrogateEscapeValidLine)  == some "[\"\uFFFD\\n\"]"
#guard actArgs? (classifyLine surrogatePairLine)         == some "[\"\uFFFDa\"]"
#guard actArgs? (classifyLine surrogatesEscapeValidLine) == some "[\"\uFFFD\uFFFD\\n\"]"
#guard actArgs? (classifyLine lonelySurrogateLine)       == some "[\"\uFFFD\"]"
#guard actArgs? (classifyLine invalidSurrogateLine)      == some "[\"\uFFFDabc\"]"
#guard actArgs? (classifyLine invertedSurrogatesLine)    == some "[\"\uFFFD\uFFFD\"]"
#guard actArgs? (classifyLine loneSecondSurrogateLine)   == some "[\"\uFFFD\"]"

/-! ## Finding: the binary64 agreement guard exists at this pin but is unwired

The pinned `mcp-seal` kernel already ships
`Seal.JsonUtil.wireNumbersAgreementSafe` — the raw-wire scan that asks whether
a mainstream binary64 JSON reader would choose the same decimal value the
exact `Lean.Json` reader sees. It REFUSES all four huge-exponent vectors, but
`Host.classifyLine` does not call it at this revision, so those four lines
still classify `.act`. Wiring it in is a code change outside this lane's
scope; the two pins below make the gap executable: the guard says unsafe, the
classifier still acts. -/

#guard Seal.JsonUtil.wireNumbersAgreementSafe
    negIntHugeExpLine.trimAscii.toString = false
#guard isActOn "external.json_corpus" (classifyLine negIntHugeExpLine)

/-! ## Axiom footprints -/

#print axioms act_refuse_divergences_fail_closed
#print axioms refuse_fail_closed
#print axioms failClosed_never_forwards
#print axioms failClosed_never_passes_through
#print axioms outcome_factors

end Host.A2Classify
