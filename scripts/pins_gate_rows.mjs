// SPDX-License-Identifier: Apache-2.0
//
// The ONE DOOR for PINS.md row policy.
//
// Every ledger row must appear exactly once here, either with one mechanical
// check or with a reason why its claim is judgment rather than a fact. The
// checker imports this table, `pins_gate.mjs --list` emits it, and the
// meta-test cross-references it against both PINS.md and ci.yml.

export const PIN_ROWS = Object.freeze([
  {
    id: "issued-time-unit",
    anchor: "`issuedAt` / `expiresAt` epoch and unit",
    check: "issued-time-unit",
    fact:
      "Unix-epoch milliseconds are read in the kernel and both fields are encoded with u64be",
  },
  {
    id: "effect-message",
    anchor: "`effectMessage`",
    check: "effect-message",
    fact:
      "EffectEnvelope field count, effect domain tag, effectMessage declaration, and injectivity theorem",
  },
  {
    id: "raw-duplicate-keys",
    anchor: "duplicate object keys on the raw wire",
    check: "raw-duplicate-keys",
    fact:
      "Seal.JsonUtil.wireKeysSafe is declared in the pinned kernel and reached by Host.classifyLine",
  },
  {
    id: "significant-digit-bound",
    anchor: "significant-digit bound",
    check: "significant-digit-bound",
    fact:
      "Seal.JsonUtil.wireDigitsSafe is declared in the pinned kernel and reached by Host.classifyLine",
  },
  {
    id: "pathological-exponent-guard",
    anchor: "pathological exponent guard",
    check: "pathological-exponent-guard",
    fact:
      "Seal.JsonUtil.wireNumbersSafe is declared in the pinned kernel and reached by Host.classifyLine",
  },
  {
    id: "ledger-generation-information-flow",
    anchor: "`ledgerGeneration` information-flow class",
    outOfScope:
      "HIGH/declassified information-flow classification is a review judgment, not a tree-derived scalar",
  },
  {
    id: "lean-classify-encoding",
    anchor: "Lean-side `seal_host_classify` integer encoding",
    check: "lean-classify-encoding",
    fact:
      "guard count and 0/1/2 values, the Lake target name, and default-target reachability",
  },
  {
    id: "rust-classify-routing",
    anchor: "Rust `route_of_classify` mapping",
    check: "rust-classify-routing",
    fact:
      "0/1/other mapping, classify_literal_only declaration, and Cargo CI reachability",
  },
  {
    id: "lean-panic-default",
    anchor: "Lean panic default on the classify seam",
    check: "lean-panic-default",
    fact:
      "panic guard call, guarded and unguarded real-binary probes, and Cargo CI reachability",
  },
  {
    id: "unicode-duplicate-keys",
    anchor: "canonical-equivalent duplicate keys",
    check: "unicode-duplicate-keys",
    fact:
      "NFD and wireKeysSafe declarations, live Host.classifyLine use, and UnicodeBasic revision coherence",
  },
  {
    id: "effect-message-twin",
    anchor: "`effect_message` Rust ↔ Lean byte twin",
    check: "effect-message-twin",
    fact:
      "frozen test, pinned kernel SHA, explicit Cargo target reachability, and whether the live test is ignored",
  },
  {
    id: "trim-forwarded-bytes",
    anchor: "trim vs forwarded bytes",
    outOfScope:
      "the conclusion that trimming is semantically inert and needs no pin is a protocol judgment",
  },
  {
    id: "rust-adapter-refinement",
    anchor: "`rust/` ↔ `sealAdapter` byte-level refinement",
    outOfScope:
      "TCB/refinement status is an assurance judgment rather than a mechanically derivable row value",
  },
  {
    id: "adapter-classify-passthrough",
    anchor: "classify-passthrough path in the adapter model",
    outOfScope:
      "model-fidelity and TCB completeness are assurance judgments rather than tree-derived facts",
  },
  {
    id: "nonce-consume-ordering",
    anchor: "nonce durable-consume vs decision ordering",
    check: "nonce-consume-ordering",
    fact:
      "the store layer keeps its two-phase shape (a3.rs reclaim-before-rebuild and reserve-before-survival orderings; replay_store.rs open-reservation SQL and synchronous=FULL), and the host ordering itself is witnessed by the G2 crash suite: the three host_path G2 tests exist, none is #[ignore]d, T1/T3 arm crash points that main.rs really implements via an aborting maybe_test_crash, and a CI cargo test step selects them unfiltered",
  },
]);

export const GATED_ROWS = Object.freeze(
  PIN_ROWS.filter((row) => Object.hasOwn(row, "check")),
);

export const OUT_OF_SCOPE_ROWS = Object.freeze(
  PIN_ROWS.filter((row) => Object.hasOwn(row, "outOfScope")),
);

export const GATED_SECTIONS = Object.freeze([
  {
    id: "specification-only-inventory",
    anchor: "## Specification-only",
    check: "specification-only-inventory",
    fact:
      "every backticked specification-only identifier remains absent from both tracked source trees",
  },
]);
