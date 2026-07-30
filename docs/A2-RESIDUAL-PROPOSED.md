<!-- SPDX-License-Identifier: Apache-2.0 -->
# A2 residual — proposed replacement for the CLAIMS.md row

Date: 2026-07-30. Written at `main` = `db0efb0`; divergence classification
landed at `b5f6ad8` (merged `ce1ff1e`), classified revision `8933c2b`. All
classifier-relevant surfaces (`Host/Canonical.lean`, `Host/Step.lean`,
`rust/src/main.rs`, `rust/tests/external_json_corpus.rs`, `lake-manifest.json`,
kernel pin `bd03bf7b`) are byte-identical between `8933c2b` and `db0efb0`, so
the classification is valid at HEAD. This document proposes wording only; it
changes no claim until Ben rules and `CLAIMS.md` is edited in a separate
commit.

## Current text (CLAIMS.md:53, verbatim)

> **A2 (numeric/parse fidelity)** minimised by construction (canonical strict
> subset), not eliminated. Per-server equivalence obligation remains.

Two defects in the current text, beyond vagueness:

1. **"Minimised by construction (canonical strict subset)" is falsified by
   the classification.** In all fourteen consequential rows the Lean view is
   the MORE LENIENT reader: `Host.classifyLine` judges `.act` on bytes that
   strict serde rejects outright (lone surrogate escapes, huge exponents,
   500-deep nesting). The "canonical strict subset" construction minimises
   nothing on those lines; it is the four fail-closed rows where strictness
   does its job, and those are now proven, not "minimised".
2. **"Per-server equivalence obligation remains" reads as an open risk. For
   the surrogate class it is a witnessed defect**:
   `docs/V31-DOWNSTREAM-PARSER-AGREEMENT.md` records four of five real
   downstream servers extracting the raw surrogates the judged event does not
   contain — nine false receipts in nine forwarded vectors.

## Proposed replacement (the row)

> **A2 (parser-divergence fidelity) PARTIALLY DISCHARGED; residual named,
>   witnessed, and pinned** (classification `Test/A2DivergenceClassification.lean`
>   + `docs/A2-DIVERGENCE-CLASSIFICATION.md` at `8933c2b`, valid at current
>   main; kernel pin `bd03bf7b`). Of the 18 recorded Rust/Lean parser
>   divergences (`rust/tests/external_json_corpus.rs`, JSONTestSuite `i_*`):
>   the INERT class is empty (every recorded case is an act/non-act split);
>   the four lines a binary64 reader silently rewrites are PROVEN FAIL-CLOSED
>   — `classifyLine = .refuse`, hence blocked under EVERY verdict list, never
>   forwarded, never passed through (`act_refuse_divergences_fail_closed`;
>   axioms `propext, Classical.choice, Quot.sound`; no `sorry`, no
>   `native_decide`; concrete-line facts are build-gated `#guard`s because
>   `String` does not kernel-reduce on this toolchain). What REMAINS ASSUMED
>   is exactly the fourteen consequential lines, in three byte classes:
>   (a) nine unpaired-UTF-16-surrogate escapes — judged with U+FFFD, raw
>   bytes forwarded verbatim; decoupling WITNESSED, not hypothetical: four of
>   five real downstream servers extract the raw surrogates the judged event
>   does not contain and a fifth rejects the frame
>   (`docs/V31-DOWNSTREAM-PARSER-AGREEMENT.md`, nine false receipts in nine
>   forwards); (b) four numbers outside binary64 round-trip agreement —
>   judged as exact expanded integers a binary64 reader rejects; (c) one
>   nesting vector beyond serde's 128 depth limit. The residual claim, stated
>   to be falsifiable: **every wire line on which `Host.classifyLine` judges
>   `.act` while any strict conformant parser rejects the same bytes or
>   extracts different `(tool, arguments)` lies in class (a), (b), or (c),
>   and the recorded divergence count is exactly 18** — a forwarded line
>   outside (a)-(c) on which a real parser disagrees, or a corpus run moving
>   off `i_divergences=18` without a classifier change, refutes it and means
>   A2 is worse than classified. For class (a) per-server agreement is
>   already FALSE of 4/5 tested servers; treat any policy that forwards
>   class-(a) bytes as unsound today. CONDITIONAL — NOT merged to main:
>   `feat/wire-numeric-agreement` (`c1a7332`) wires the already-pinned
>   `Seal.JsonUtil.wireNumbersAgreementSafe` (kernel `Seal/JsonUtil.lean:402`)
>   into `classifyLine`, closing class (b); the stacked
>   `feat/wire-surrogates-agreement` (HEAD `3e8b464`; surrogate/depth feature
>   commit `7367dc1`, numeric guard restacked as `ac5145e`) adds pre-parse
>   guards for (a) and (c). The guardstack lane reports the stack built green
>   and corpus-measured all-18 fail-closed at in-stack commit `26d71bf`
>   (`i_divergences` 18→5, every remaining one refusal-direction, one NEW:
>   `[123.456e-789]`, serde accepts / agreement guard refuses — the numeric
>   guard's declared availability cost); the branch HEAD was recut after
>   that build and the build at HEAD is unverified. Nothing in this row may
>   be read as if the stack had landed. RETIREMENT: A2
>   cannot be retired by anything available to us — it quantifies over the
>   parsers of arbitrary present and future downstream servers, which the
>   host does not control (same shape as A7's ruled impossibility:
>   application-layer code cannot bind a counterparty's parser). The
>   achievable end state, if both guards land green, is a per-corpus
>   discharge — 18/18 fail-closed over the recorded set, with the residual
>   reduced to "no undiscovered divergence class exists", monitored forever
>   by the corpus count. Pinned in executable form by
>   `rust/tests/external_json_corpus.rs` (`i_divergences=18`) and the 24
>   `#guard` pins of `Test/A2DivergenceClassification.lean`; reclassifying
>   any line requires flipping those pins in the same commit.

## The three statuses, with evidence on disk

### DISCHARGED

- **The inert class is empty — nothing representational is being waved
  through.** Every recorded divergence is an act/non-act split by
  construction of the harness predicate
  (`rust/tests/external_json_corpus.rs:300`:
  `(rust == Act) != (lean == Act)`). Stated in both the doc
  (`docs/A2-DIVERGENCE-CLASSIFICATION.md`, "Result") and the module header.
- **The classification criterion itself.** The deployed route factors through
  the Lean classifier alone: `outcome line verdicts =
  stepRoute (classifyLine line) verdicts` (`outcome_factors`, definitional
  `rfl`). The serde view has no production decision path — it enters only at
  the V2.3 effect projection, which fails closed on parse error
  (`rust/src/envelope_v23.rs:200`), and at parser-independent raw-byte
  receipt hashes (`rust/src/decision_receipt.rs:79`). This retires the worry
  that the RUST parser's leniency could steer routing.

### FAIL-CLOSED (proven)

Rows 1-4 (`[123e-10000000]`, `[100000000000000000000]`,
`[-123123123123123123123123123123]`, 48-digit negative): serde accepts and
SILENTLY REWRITES the value under binary64; Lean refuses (`wireNumbersSafe`
exponent bound / `wireDigitsSafe` 18-digit bound).
`act_refuse_divergences_fail_closed` (`Test/A2DivergenceClassification.lean:191`)
proves all four blocked under every verdict list from four guard-bool
hypotheses, each pinned as a build-gated `#guard` on the byte-exact wire
line. Axiom footprint `[propext, Classical.choice, Quot.sound]`; no `sorry`,
no `native_decide`. Honesty caveat carried into the row: the concrete
per-line facts are elaboration-time `#guard`s, not kernel theorems —
concrete `String` evaluation does not kernel-reduce on this toolchain (same
limitation documented in `Seal/NumberGuardTheorems.lean`).

### STILL ASSUMED

Rows 5-18, the consequential class, three byte classes:

| Class | Rows | Judged event | Strict reader | Witness status |
|---|---|---|---|---|
| (a) unpaired surrogate escapes | 10-18 | U+FFFD substituted (toolchain `Lean/Data/Json/Parser.lean:60-70`) | rejects | **witnessed**: 4/5 real servers extract raw surrogates, 1/5 rejects (`docs/V31-DOWNSTREAM-PARSER-AGREEMENT.md:57-65`) |
| (b) numbers outside binary64 agreement | 5-8 | exact expanded integer (`Lean.JsonNumber`) | rejects (`number out of range`) | hypothetical decoupling; rejection recorded |
| (c) nesting depth | 9 | 500-deep array | rejects (`recursion limit exceeded`, depth 128) | hypothetical; one V3.1 observer rejected it pre-experiment |

For every one of the fourteen: the host can judge and (policy permitting)
approve an event parsed from bytes a strict conformant reader rejects, and
the RAW BYTES — not the judged event — are what the child receives.

## What makes the residual falsifiable

The claim: every `lean=Act`/strict-reader-disagrees line lies in classes
(a)-(c), and the recorded count is exactly 18.

Refuting counterexamples, concretely:

1. **A wire line outside (a)-(c)** that `classifyLine` judges `.act` and on
   which any real parser extracts different `(tool, arguments)` or rejects —
   e.g. a duplicate-key, whitespace, or encoding divergence not in the
   corpus. This would show the classification (and both in-flight guards)
   incomplete: A2 worse than classified.
2. **`cargo test --test external_json_corpus` reporting `i_divergences ≠ 18`**
   at an unchanged classifier — the corpus itself found a new class.
3. For the per-server obligation: a deployed server accepting a forwarded
   class-(b) or class-(c) line and executing arguments differing from the
   judged event — this would upgrade those classes from hypothetical to
   witnessed, joining class (a).

Class (a) needs no future counterexample: it is ALREADY refuted per-server
(4/5 tested). The falsifiable content left is completeness of the class
list, which is exactly what an attacker would probe.

## The conditional parts

| Class | Closed by | Branch @ commit | Status |
|---|---|---|---|
| (b) numeric agreement | wiring `Seal.JsonUtil.wireNumbersAgreementSafe` (exists at pin `bd03bf7b`, `Seal/JsonUtil.lean:402`; refuses all four vectors — pinned `#guard`, main) into `classifyLine` | `feat/wire-numeric-agreement` @ `c1a7332`; restacked as `ac5145e` inside the surrogates branch | unmerged |
| (a) surrogates, (c) depth | new `Host/SurrogateEscapes.lean` + `Host/NestingDepth.lean` pre-parse guards | `feat/wire-surrogates-agreement` @ `3e8b464` (feature commit `7367dc1`; reclassification `537a23c`; test recut `3e8b464`) | unmerged |

Build status, reported by the guardstack lane (worktree `wt/surrogates`,
2026-07-30), NOT independently verified by this lane: the full seven-guard
stack compiled green (`leanbuild` exit 0) at in-stack commit `26d71bf`, and
the corpus harness measured both sides (same binary, swapped `.so`):
`y_` acceptance unchanged at 91/95 (identical vectors), `i_divergences`
18→5, all five remaining refusal-direction, one NEW
(`i_number_double_huge_neg_exp` `[123.456e-789]`: serde accepts, agreement
guard refuses — the numeric guard's declared availability cost). The branch
HEAD was recut after that build (`537a23c`, `3e8b464`); the build at HEAD is
unverified.

Until the stack merges green to main, the deployed classifier forwards all
fourteen consequential lines under an all-allow verdict list. No wording
that presumes the guards may enter the claim surface before then.

## What would retire A2

Nothing available to us retires it. A2 universally quantifies over the
parsers of every present and future downstream server; the host does not
control, observe, or bind them. This is the A7 shape: an application-layer
component cannot authenticate a counterparty's internals. The honest end
state is a NAMED REDUCTION, not retirement:

1. Both guards land green → 18/18 recorded divergences fail-closed
   (per-corpus discharge).
2. The residual reduces to: **no divergence class exists outside the guarded
   set** — unprovable in principle (it ranges over all conformant-ish
   parsers, a set with no formal boundary), monitored by the corpus count
   pin and extendable only by discovery, JSONTestSuite-style.
3. Per-server: the V3.1 observer harness can re-run against any newly
   deployed server; agreement for the guarded classes becomes vacuous
   (nothing in them is forwarded), and agreement outside them stays assumed.

A candidate stronger move — forward the judged event's canonical
serialization instead of the raw bytes — would collapse A2 to the child
parser's handling of canonical output only, but it is a semantics change to
the `compatible` profile (the profile's contract is raw-byte forwarding) and
belongs to the `canonical-l0` row, not to A2 wording.
