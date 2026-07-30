<!-- SPDX-License-Identifier: Apache-2.0 -->
# A2 divergence classification

Date: 2026-07-30. Revision classified: `8933c2b` (main). Kernel pin:
`mcp-seal-dev` `bd03bf7b`. Lane branch: `proof/a2-divergence-classification`.

`CLAIMS.md` assumption **A2** says two nominally strict parsers may disagree,
so the non-bypass theorem can hold of the host's parsed event while the child
executes a different one. Eighteen concrete Rust(serde)/Lean disagreements are
recorded and reproducible via `rust/tests/external_json_corpus.rs`
(JSONTestSuite `i_*` class). This document classifies all eighteen against the
mediation property, with the criterion stated formally first. The machine
side lives in `Test/A2DivergenceClassification.lean`.

All eighteen were re-reproduced at `8933c2b` before classification
(`cargo test --test external_json_corpus -- --nocapture`:
`total=318 y_=95 n_=188 i_=35 i_divergences=18`). None has been closed since
they were recorded.

## The criterion

The deployed routing decision factors through the Lean classifier:
`Ffi.stepImpl` routes by exactly `stepRoute (classifyLine line) verdicts`
(`Host/Step.lean:40`, wiring `rust/src/main.rs:1339`). Define

```
outcome line verdicts := stepRoute (classifyLine line) verdicts
```

(`Test/A2DivergenceClassification.lean`, `Host.A2Classify.outcome`). The Rust
serde view appears nowhere in `outcome`: serde enters production only at the
V2.3 effect projection, which fails closed on parse error
(`rust/src/envelope_v23.rs:200`), and at receipt fields that hash raw bytes
parser-independently (`rust/src/decision_receipt.rs:79`).

A recorded disagreement on wire line `ℓ` between the Lean view and another
parser is:

- **inert** — `outcome` is unchanged under both readings AND every conformant
  child parser that accepts the forwarded bytes extracts the same
  `(tool, arguments)` the kernel judged. Purely representational.
- **fail-closed** — `classifyLine ℓ = .refuse`. Then `outcome ℓ v = .block`
  for every verdict list `v`: never forwarded, never passed through
  (`refuse_fail_closed`, `failClosed_never_forwards`,
  `failClosed_never_passes_through` — Lean theorems). The disagreement can
  only move the outcome toward refusal; nothing reaches the child, so no
  judged/executed pair exists to decouple.
- **consequential** — `classifyLine ℓ = .act a` while another parser rejects
  the same bytes or reads a different event from them. Under an all-allow
  verdict list the outcome is `.forward` (`stepRoute_act_forward_iff`,
  `Host/Step.lean:75`), so the outcome moves toward acceptance relative to
  the stricter reading, and the child's execution of the raw forwarded bytes
  is bound to `a` only by A2 itself.

## Result

**14 fail-closed, 4 consequential, 0 inert** (as of the class-(a)/(c) guard
wiring on `feat/wire-surrogates-agreement`, 2026-07-30 — see the addendum
below the table). At the originally classified revision `8933c2b` the split
was **4 fail-closed, 14 consequential, 0 inert**; the table below records
that revision.

The inert class is empty because every recorded case is an act/non-act split
— the harness records a divergence exactly when
`(rust == Act) != (lean == Act)` (`rust/tests/external_json_corpus.rs:300`) —
never a representational difference.

## The table

Every input is the fixed envelope
(`rust/tests/external_json_corpus.rs:24-26`) around the byte-exact vector:
`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"external.json_corpus","arguments":` VECTOR `}}`.
serde column: `serde_json 1.0.151` on the exact envelope (probe run
2026-07-30). Lean column: the compiled production classifier at `8933c2b`
(`Test/DownstreamParserOracle.lean` binary + the `#guard` pins). Production
decision: refuse ⇒ blocked, SEAM error, nothing to child
(`rust/src/main.rs:1352`); act ⇒ mediated, raw bytes forward iff every gating
kernel allows.

| # | Vector | serde parse (Rust view) | Lean parse (judged event) | Class | Divergence source |
|---|---|---|---|---|---|
| 1 | `i_number_real_underflow` `[123e-10000000]` | **accepts, rewrites**: `[0.0]` (Act) | `.refuse` — 8-digit exponent run > 6 (`wireNumbersSafe`) | **fail-closed** | `Seal/JsonUtil.lean:95`, bound `:48`; `Host/Canonical.lean:51` |
| 2 | `i_number_too_big_pos_int` `[100000000000000000000]` | **accepts, rewrites**: `[1e+20]` (Act) | `.refuse` — 21 significant digits > 18 (`wireDigitsSafe`) | **fail-closed** | `Seal/JsonUtil.lean:537`, bound `:503`; `Host/Canonical.lean:72` |
| 3 | `i_number_too_big_neg_int` `[-123123123123123123123123123123]` | **accepts, rewrites**: `[-1.2312312312312312e+29]` (Act) | `.refuse` — 30 digits (`wireDigitsSafe`) | **fail-closed** | same as 2 |
| 4 | `i_number_very_big_negative_int` (48-digit) | **accepts, rewrites**: `[-2.3746237467327687e+47]` (Act) | `.refuse` — 48 digits (`wireDigitsSafe`) | **fail-closed** | same as 2 |
| 5 | `i_number_neg_int_huge_exp` `[-1e+9999]` | rejects: `number out of range` (NotAct) | `.act`, args = exact integer −10^9999 (expanded) | **consequential** | `Lean.JsonNumber` exact vs binary64; agreement guard exists but unwired (below) |
| 6 | `i_number_pos_double_huge_exp` `[1.5e+9999]` | rejects: `number out of range` (NotAct) | `.act`, exact expanded integer | **consequential** | same as 5 |
| 7 | `i_number_real_neg_overflow` `[-123123e100000]` | rejects: `number out of range` (NotAct) | `.act`, exact expanded integer (serializing it crashed the oracle; see Unverified) | **consequential** | same as 5 |
| 8 | `i_number_real_pos_overflow` `[123123e100000]` | rejects: `number out of range` (NotAct) | `.act`, exact expanded integer (same oracle crash) | **consequential** | same as 5 |
| 9 | `i_structure_500_nested_arrays` (500×`[` 500×`]`) | rejects: `recursion limit exceeded` (depth 128) (NotAct) | `.act`, args = 500-deep array | **consequential** | serde default depth limit vs Lean partial-recursive parser (toolchain `Lean/Data/Json/Parser.lean:75`) |
| 10 | `i_string_1st_surrogate_but_2nd_missing` `["\uDADA"]` | rejects: `unexpected end of hex escape` (NotAct) | `.act`, args = `["�"]` | **consequential** | toolchain `Lean/Data/Json/Parser.lean:60-70` (U+FFFD substitution) |
| 11 | `i_string_1st_valid_surrogate_2nd_invalid` `["\uD888\u1234"]` | rejects: `lone leading surrogate` (NotAct) | `.act`, args = `["�ሴ"]` | **consequential** | same as 10 |
| 12 | `i_string_incomplete_surrogate_and_escape_valid` `["\uD800\n"]` | rejects: `unexpected end of hex escape` (NotAct) | `.act`, args = `["�\n"]` | **consequential** | same as 10 |
| 13 | `i_string_incomplete_surrogate_pair` `["\uDd1ea"]` | rejects: `lone leading surrogate` (NotAct) | `.act`, args = `["�a"]` | **consequential** | same as 10 |
| 14 | `i_string_incomplete_surrogates_escape_valid` `["\uD800\uD800\n"]` | rejects: `lone leading surrogate` (NotAct) | `.act`, args = `["��\n"]` | **consequential** | same as 10 |
| 15 | `i_string_invalid_lonely_surrogate` `["\ud800"]` | rejects: `unexpected end of hex escape` (NotAct) | `.act`, args = `["�"]` | **consequential** | same as 10 |
| 16 | `i_string_invalid_surrogate` `["\ud800abc"]` | rejects: `unexpected end of hex escape` (NotAct) | `.act`, args = `["�abc"]` | **consequential** | same as 10 |
| 17 | `i_string_inverted_surrogates_U+1D11E` `["\uDd1e\uD834"]` | rejects: `lone leading surrogate` (NotAct) | `.act`, args = `["��"]` | **consequential** | same as 10 |
| 18 | `i_string_lone_second_surrogate` `["\uDFAA"]` | rejects: `lone leading surrogate` (NotAct) | `.act`, args = `["�"]` | **consequential** | same as 10 |

Rows 1-4 have a sharp reading: serde is the UNSAFE reader there (it silently
rewrites the numeric value under binary64), and the Lean guards refuse
precisely because a mainstream binary64 reader would disagree with the exact
reader. The refusal is the guard doing its designed job.

## Addendum, 2026-07-30: classes (a) and (c) closed

`feat/wire-surrogates-agreement` wires two new pre-parse raw-wire guards into
`Host.classifyLine`, in the `wireKeysSafe` style (total scans on the raw
bytes, before `Json.parse`):

* **`Host.SurrogateEscapes.wireSurrogatesSafe`** — class (a). Refuses a line
  carrying an unpaired UTF-16 surrogate escape inside a string literal. Rows
  10-18 now classify `.refuse`: fail-closed
  (`surrogate_depth_divergences_fail_closed`,
  `Test/A2DivergenceClassification.lean`). Exclusion is proven, not sampled:
  `unsafe_implies_surrogateEscape` (kernel theorem) shows a refused line
  literally contains the six raw characters `\uXXXX` with `XXXX` hex-reading
  into `D800`-`DFFF`; transparency lemmas show valid surrogate pairs,
  non-surrogate `\u` escapes and simple escapes are verdict-neutral.
* **`Host.NestingDepth.wireDepthSafe`** — class (c). Refuses container
  nesting beyond depth 128 (the serde_json default recursion limit, the
  shallowest recorded downstream bound; brackets inside strings do not
  count). Row 9 now classifies `.refuse`: fail-closed.

Rows 9-18 in the table above therefore read **fail-closed** at this branch;
the serde/Lean *parser* views still differ (the harness still counts rows
1-4 and 9-18 as recorded divergences), but the Lean side of each is now
`.refuse`, so the divergence can only move the outcome toward refusal.

## What is proven

`Test/A2DivergenceClassification.lean`, built at `8933c2b`
(`leanbuild build Test.A2DivergenceClassification`, exit 0):

- `refuse_fail_closed`, `failClosed_never_forwards`,
  `failClosed_never_passes_through`, `outcome_factors` — the criterion's
  fail-closed direction, kernel theorems.
- `act_refuse_divergences_fail_closed` — all four `rust=Act lean=Refuse`
  lines (byte-exact literals) are blocked under EVERY verdict list, from four
  guard-bool hypotheses.
- Axiom footprint of all of the above: `[propext, Classical.choice,
  Quot.sound]`. No `sorry`, no `native_decide`.
- The four guard-bool hypotheses, plus per-line classification and judged-
  argument values for all eighteen lines, are pinned as build-gated `#guard`s
  (elaboration-time evaluation of the production classifier; a change flips
  the build red). Concrete-string kernel theorems are not attainable on this
  toolchain without `native_decide` — `String` functions do not kernel-reduce
  (same limitation documented in `Seal/NumberGuardTheorems.lean`).

## The consequential set, in full

Rows 5-18. For every one of the fourteen: the host can judge and (policy
permitting) approve an event parsed from bytes that a strict conformant
reader rejects outright, and the raw bytes — not the judged event — are what
the child receives. For the nine surrogate rows the decoupling is WITNESSED,
not hypothetical: the judged `CanonicalAction` contains U+FFFD where the wire
contains unpaired surrogate escapes, and
`docs/V31-DOWNSTREAM-PARSER-AGREEMENT.md` records four real downstream
servers extracting the raw surrogates and a fifth rejecting the forwarded
frame — nine false receipts among nine forwarded vectors.

## Residual A2 (quotable)

> **A2 residual (2026-07-30, after the class-(a)/(c) guard wiring on
> `feat/wire-surrogates-agreement`).** Of the 18 recorded Rust/Lean parser
> disagreements, fourteen are proven fail-closed (refused and blocked under
> every verdict list; `act_refuse_divergences_fail_closed` and
> `surrogate_depth_divergences_fail_closed`,
> `Test/A2DivergenceClassification.lean`) and the inert class is empty: the
> four binary64 silent-rewrite lines, the nine unpaired-surrogate-escape
> lines (class (a), refused pre-parse by
> `Host.SurrogateEscapes.wireSurrogatesSafe`), and the over-deep nesting
> line (class (c), refused pre-parse by
> `Host.NestingDepth.wireDepthSafe`, bound 128). What remains assumed is
> exactly the four-line consequential class (b): wire lines carrying an
> unquoted number outside binary64 round-trip agreement, which
> `Host.classifyLine` judges as acts (the exact expanded integer) while a
> binary64 reader rejects the same bytes. A2 therefore reduces to: every
> deployed downstream server's parser either rejects, or agrees with
> `Lean.Json.parse` on the judged `(tool, arguments)`, for every forwarded
> class-(b) line. The pinned kernel already ships the closing guard
> (`Seal.JsonUtil.wireNumbersAgreementSafe`, refuses all four class-(b)
> vectors — pinned executable in `Test/A2DivergenceClassification.lean`),
> but `Host.classifyLine` does not call it at this revision; a sibling
> branch wires it.

## Findings (report only — no code changed here)

1. **The binary64 agreement guard is unwired.** `wireNumbersAgreementSafe`
   exists at the pinned kernel (`Seal/JsonUtil.lean:402`) and refuses all
   four huge-exponent vectors, but `classifyLine` (`Host/Canonical.lean:43`)
   never calls it. Wiring it would move rows 5-8 to fail-closed. (The b83
   kernel line used in the V3.1 experiment wired it; the checked-in pin
   `bd03bf7b` does not.)
2. **No raw-wire guard for unpaired surrogate escapes** (rows 10-18) or
   **nesting depth** (row 9). Both are scan-detectable pre-parse, in the
   exact style of `wireKeysSafe`/`wireNumbersSafe`. Until guarded (or the
   per-server agreement obligation is discharged), these rows are the live
   content of A2. *(Closed 2026-07-30 by the addendum above:
   `Host.SurrogateEscapes.wireSurrogatesSafe` and
   `Host.NestingDepth.wireDepthSafe` are wired at
   `feat/wire-surrogates-agreement`.)*
3. **Oracle serializer exception on rows 7-8** (`e100000`): the compiled
   classifier judged `.act`, then printing the expanded arguments raised an
   uncaught Lean exception in the oracle binary. Cause not diagnosed here;
   the production audit path serializes `argsJson` for full-argument guard
   targets (`Seal/Classify.lean:55`), so a mediated act on such a line may
   stress that path. Reported, unverified.

## Reproduce

```sh
# the 18 divergences (native FFI classifier)
cargo test --test external_json_corpus -- --nocapture
# the classification module (theorems + 24 #guard pins)
/home/monkey/bin/leanbuild build Test.A2DivergenceClassification
```
