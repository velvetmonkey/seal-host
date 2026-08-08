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

Of the eighteen recorded divergences, ALL EIGHTEEN are fail-closed at this
revision and none remain consequential. History: at `8933c2b` the split was
4/14 — the four number-guard refusals fail-closed, everything else
consequential. On 2026-07-30 the class-(b) binary64 round-trip agreement
guard (`Seal.JsonUtil.wireNumbersAgreementSafe`, rows 5–8), the class-(a)
unpaired-surrogate-escape guard
(`Host.SurrogateEscapes.wireSurrogatesSafe`, rows 10–18) and the class-(c)
nesting-depth guard (`Host.NestingDepth.wireDepthSafe`, row 9) were wired
into `Host.classifyLine`, moving those fourteen rows to fail-closed. The
inert class is EMPTY: every recorded case is an act/non-act split, never a
representational difference.

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

-- The fourteen lines recorded `rust=NotAct lean=Act` at `8933c2b`. Rows 5-8
-- (huge exponents) are refused since the class-(b) agreement guard landed;
-- rows 9-18 are refused since the class-(a)/(c) guards landed.
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

/-! ## Per-line pins, class-(b) huge-exponent lines (rows 5-8)

Each of the four huge-exponent lines is refused by the binary64 round-trip
agreement guard: serde rejects the same bytes (`number out of range`), so a
mainstream binary64 reader cannot agree with the exact Lean reading, and the
guard fails closed before `Json.parse` runs. -/

#guard Seal.JsonUtil.wireNumbersAgreementSafe
    negIntHugeExpLine.trimAscii.toString = false
#guard Seal.JsonUtil.wireNumbersAgreementSafe
    posDoubleHugeExpLine.trimAscii.toString = false
#guard Seal.JsonUtil.wireNumbersAgreementSafe
    realNegOverflowLine.trimAscii.toString = false
#guard Seal.JsonUtil.wireNumbersAgreementSafe
    realPosOverflowLine.trimAscii.toString = false

#guard isRefuse (classifyLine negIntHugeExpLine)
#guard isRefuse (classifyLine posDoubleHugeExpLine)
#guard isRefuse (classifyLine realNegOverflowLine)
#guard isRefuse (classifyLine realPosOverflowLine)

/-- The four class-(b) huge-exponent lines (rows 5-8). -/
def agreementLines : List String :=
  [negIntHugeExpLine, posDoubleHugeExpLine, realNegOverflowLine,
   realPosOverflowLine]

/-- **Every class-(b) huge-exponent divergence line is fail-closed.** The four
    guard hypotheses are the exact `Bool` facts pinned by the `#guard`s above
    (build-time evaluation of the production guard on the exact wire lines);
    given them, each line is blocked under every verdict list — never
    forwarded, never passed through. Before 2026-07-30 these four lines were
    the residual consequential class; the class-(b) agreement guard moved
    them here. -/
theorem agreement_divergences_fail_closed
    (h5 : Seal.JsonUtil.wireNumbersAgreementSafe
      negIntHugeExpLine.trimAscii.toString = false)
    (h6 : Seal.JsonUtil.wireNumbersAgreementSafe
      posDoubleHugeExpLine.trimAscii.toString = false)
    (h7 : Seal.JsonUtil.wireNumbersAgreementSafe
      realNegOverflowLine.trimAscii.toString = false)
    (h8 : Seal.JsonUtil.wireNumbersAgreementSafe
      realPosOverflowLine.trimAscii.toString = false) :
    ∀ line ∈ agreementLines, FailClosed line := by
  intro line hmem
  simp only [agreementLines, List.mem_cons, List.not_mem_nil, or_false] at hmem
  rcases hmem with h | h | h | h <;> subst h
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_agreement _ h5)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_agreement _ h6)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_agreement _ h7)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_agreement _ h8)

#guard Host.SurrogateEscapes.wireSurrogatesSafe
    surrogate2ndMissingLine.trimAscii.toString = false
#guard Host.SurrogateEscapes.wireSurrogatesSafe
    surrogate2ndInvalidLine.trimAscii.toString = false
#guard Host.SurrogateEscapes.wireSurrogatesSafe
    surrogateEscapeValidLine.trimAscii.toString = false
#guard Host.SurrogateEscapes.wireSurrogatesSafe
    surrogatePairLine.trimAscii.toString = false
#guard Host.SurrogateEscapes.wireSurrogatesSafe
    surrogatesEscapeValidLine.trimAscii.toString = false
#guard Host.SurrogateEscapes.wireSurrogatesSafe
    lonelySurrogateLine.trimAscii.toString = false
#guard Host.SurrogateEscapes.wireSurrogatesSafe
    invalidSurrogateLine.trimAscii.toString = false
#guard Host.SurrogateEscapes.wireSurrogatesSafe
    invertedSurrogatesLine.trimAscii.toString = false
#guard Host.SurrogateEscapes.wireSurrogatesSafe
    loneSecondSurrogateLine.trimAscii.toString = false
#guard Host.NestingDepth.wireDepthSafe nested500Line.trimAscii.toString = false

#guard isRefuse (classifyLine surrogate2ndMissingLine)
#guard isRefuse (classifyLine surrogate2ndInvalidLine)
#guard isRefuse (classifyLine surrogateEscapeValidLine)
#guard isRefuse (classifyLine surrogatePairLine)
#guard isRefuse (classifyLine surrogatesEscapeValidLine)
#guard isRefuse (classifyLine lonelySurrogateLine)
#guard isRefuse (classifyLine invalidSurrogateLine)
#guard isRefuse (classifyLine invertedSurrogatesLine)
#guard isRefuse (classifyLine loneSecondSurrogateLine)
#guard isRefuse (classifyLine nested500Line)

/-- The nine class-(a) lines and the class-(c) line. -/
def surrogateDepthLines : List String :=
  [surrogate2ndMissingLine, surrogate2ndInvalidLine, surrogateEscapeValidLine,
   surrogatePairLine, surrogatesEscapeValidLine, lonelySurrogateLine,
   invalidSurrogateLine, invertedSurrogatesLine, loneSecondSurrogateLine,
   nested500Line]

/-- **Every class-(a) and class-(c) divergence line is fail-closed.** The ten
    guard hypotheses are the exact `Bool` facts pinned by the `#guard`s above
    (build-time evaluation of the production guards on the exact wire lines);
    given them, each line is blocked under every verdict list — never
    forwarded, never passed through. Before 2026-07-30 these ten lines were
    the witnessed bulk of the consequential class; the class-(a)/(c) guards
    moved them here. -/
theorem surrogate_depth_divergences_fail_closed
    (h10 : Host.SurrogateEscapes.wireSurrogatesSafe
      surrogate2ndMissingLine.trimAscii.toString = false)
    (h11 : Host.SurrogateEscapes.wireSurrogatesSafe
      surrogate2ndInvalidLine.trimAscii.toString = false)
    (h12 : Host.SurrogateEscapes.wireSurrogatesSafe
      surrogateEscapeValidLine.trimAscii.toString = false)
    (h13 : Host.SurrogateEscapes.wireSurrogatesSafe
      surrogatePairLine.trimAscii.toString = false)
    (h14 : Host.SurrogateEscapes.wireSurrogatesSafe
      surrogatesEscapeValidLine.trimAscii.toString = false)
    (h15 : Host.SurrogateEscapes.wireSurrogatesSafe
      lonelySurrogateLine.trimAscii.toString = false)
    (h16 : Host.SurrogateEscapes.wireSurrogatesSafe
      invalidSurrogateLine.trimAscii.toString = false)
    (h17 : Host.SurrogateEscapes.wireSurrogatesSafe
      invertedSurrogatesLine.trimAscii.toString = false)
    (h18 : Host.SurrogateEscapes.wireSurrogatesSafe
      loneSecondSurrogateLine.trimAscii.toString = false)
    (h9 : Host.NestingDepth.wireDepthSafe
      nested500Line.trimAscii.toString = false) :
    ∀ line ∈ surrogateDepthLines, FailClosed line := by
  intro line hmem
  simp only [surrogateDepthLines, List.mem_cons, List.not_mem_nil, or_false]
    at hmem
  rcases hmem with h | h | h | h | h | h | h | h | h | h <;> subst h
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_surrogates _ h10)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_surrogates _ h11)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_surrogates _ h12)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_surrogates _ h13)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_surrogates _ h14)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_surrogates _ h15)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_surrogates _ h16)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_surrogates _ h17)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_surrogates _ h18)
  · exact refuse_fail_closed (classifyLine_refuse_of_unsafe_depth _ h9)

/-! ## Axiom footprints

Each footprint is ASSERTED, not merely printed: `#guard_msgs` fails the build
unless `#print axioms` emits exactly the expected set named in the doc
comment. The expected sets are explicit literals — the three standard
classical axioms for the simp-driven theorems, none for the definitional
ones. If any declaration silently gains `sorryAx` or an unexpected axiom,
elaboration fails and the error names the declaration and the actual set. -/

/-- info: 'Host.A2Classify.act_refuse_divergences_fail_closed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms act_refuse_divergences_fail_closed

/-- info: 'Host.A2Classify.agreement_divergences_fail_closed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms agreement_divergences_fail_closed

/-- info: 'Host.A2Classify.surrogate_depth_divergences_fail_closed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms surrogate_depth_divergences_fail_closed

/-- info: 'Host.A2Classify.refuse_fail_closed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms refuse_fail_closed

/-- info: 'Host.A2Classify.failClosed_never_forwards' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms failClosed_never_forwards

/-- info: 'Host.A2Classify.failClosed_never_passes_through' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms failClosed_never_passes_through

/-- info: 'Host.A2Classify.outcome_factors' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms outcome_factors

end Host.A2Classify
