# Canonical byte contract (not RFC 8785/JCS)

In this repository, **canonical** names bytes defined by the pinned Seal
kernel. It does not mean RFC 8785 JSON Canonicalization Scheme (JCS),
ECMAScript `JSON.stringify`, or another external canonical-JSON standard
unless a passage explicitly says so.

For the `seal.effect/v2` signed tuple, the kernel has two JSON rendering
paths:

1. `arguments` uses `SealV2.serializeAstValue`. It preserves the parsed AST's
   object-member order, preserves array order and decimal digits, uses the
   kernel's one-representation string grammar, and escapes DEL and non-ASCII
   scalars (`\u` or UTF-16 surrogate-pair form).
2. Present `_meta`, `requestState`, and `inputResponses` use
   `Lean.Json.compress`. Objects use Lean `TreeMap`/Unicode-scalar key order,
   arrays retain order, numbers use Lean's arbitrary-precision
   `JsonNumber.toString`, and string escaping is Lean's JSON printer.

The active Rust encoder independently uses `serde_json`: argument derivation
retains parsed member order (`preserve_order`), while the three complete-value
seats go through `envelope_v23::canonical_json`, which recursively sorts keys
by Unicode scalar order. Before a present effect claim may reach
signature-preimage reconstruction or verification, the
host asks the pinned Lean kernel for all six derived effect fields and admits
the request only if the Rust and Lean bytes are identical in every field.
There is no normalization: a mismatch or an unclassifiable result is a typed,
fail-closed request rejection. Effect absence carries no canonical JSON seat;
the exact judged line remains separately framed in the signed tuple.

Known non-JCS behavior remains after that containment:

- `Lean.Json.compress` emits U+0008, U+0009, and U+000C as `\u0008`,
  `\u0009`, and `\u000c`; RFC 8785 requires `\b`, `\t`, and `\f`.
- Lean numbers are arbitrary-precision decimals with Lean-specific rendering,
  not ECMAScript's IEEE-754 binary64 shortest rendering required by RFC 8785.
- In the three complete-value seats, Lean and Rust order property names by
  Unicode scalar/code-point order. RFC 8785 requires UTF-16 code-unit order,
  which differs for a high-BMP key (U+E000–U+FFFF) paired with a
  supplementary key (U+10000 or above). `arguments` instead retains parsed
  member order on both sides.
- `SealV2.serializeAstValue` has the separate order and Unicode escaping rules
  stated above; those are also not JCS.

The agreement gate makes the two deployed implementations agree on every
admitted present effect. It does **not** make either implementation JCS
conformant.

Other signed JSON surfaces have separate byte contracts:

- trusted-config signatures cover the exact compact Python `json.dumps`
  payload bytes emitted by `test/tools/sign_config.py`, preserving parsed
  insertion order;
- `ApprovalRecord` v2 uses the explicit renderer in
  `rust/src/providers.rs` (UTF-8 byte-sorted keys, unsigned safe-range
  integers, and `\u00xx` for every C0 control);
- authorization-decision derived strings and hashes use the exact
  `serde_json`/stored-order rules stated in
  `AUTHORIZATION-DECISION-SCHEMA.md`.

None of those separate contracts is an RFC 8785 conformance claim.
