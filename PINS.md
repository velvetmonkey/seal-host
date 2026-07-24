# seal — Pin Ledger

**What this tracks.** Every place where a name is given to a byte sequence, a digest input, a
correspondence across a language boundary, or an integer encoding, and the question "is the exact
form pinned, or is it left to the caller?" has an answer worth writing down.

**Why it exists.** The dominant recurring defect family in this project is *a named hash input
without a pinned byte formula*: two conforming implementations compute different bytes for the same
logical content, and a legitimately signed artifact fails to verify, or two different contents
collide. The second family is *a correspondence nothing regression-guards*: the mapping is correct
today, and nothing would notice if it stopped being correct.

**Status vocabulary.**

| status | meaning |
|---|---|
| `PINNED` | a total function fixes exactly one byte string; no caller discretion remains |
| `PINNED-BY-TEST` | a test enforces it, but no formula is written down; a rewrite could drift |
| `FROZEN-EXPECTATION` | pinned against a stored artifact rather than against the live definition |
| `UNPINNED` | correct today, nothing prevents or detects drift |
| `SPEC-ONLY` | named in a design document, no counterpart in either codebase |
| `CHARACTERISED` | examined and deliberately requires no pin; reasoning recorded |
| `TCB` | explicitly outside what is enforced; disclosed as an assumption |

---

## Kernel sites (`mcp-seal-dev`)

| site | status | evidence | note |
|---|---|---|---|
| `issuedAt` / `expiresAt` epoch and unit | `PINNED` | commit `d017ac1`, `SealV2/EffectEnvelope.lean` | width and endianness (`u64be`) were already pinned; the MEANING of the integer was not, so two conforming verifiers could read the same bytes as seconds and as milliseconds and diverge silently with no error |
| `effectMessage` 18-field signed tuple | `PINNED` | `SealV2/EffectEnvelope.lean:339`, `effect_message_injective` | injectivity proven at the hashed-byte surface |
| duplicate object keys on the raw wire | `PINNED` | `Seal/JsonUtil.lean` `wireKeysSafe` | raw-text scan, fails closed; also refuses escaped keys rather than re-implementing escape decoding |
| significant-digit bound | `PINNED` | `Seal/JsonUtil.lean` `wireDigitsSafe` | |
| pathological exponent guard | `PINNED` | `Seal/JsonUtil.lean` `wireNumbersSafe` | |
| `ledgerGeneration` information-flow class | `PINNED` | commit `9a4c972`, `SealV2/NonceLedger.lean` | HIGH on the base NI path, declassified on the ledgered path; both stated as theorems with a decision-flip negative control |

## Host sites (`seal-host`)

| site | status | evidence | note |
|---|---|---|---|
| Lean-side `seal_host_classify` integer encoding | **`UNPINNED`** | `Ffi.lean:329-334` emits `0/1/2` | **the live gap.** The Rust half is exhaustively property-tested (`rust/tests/differential.rs` `classify_literal_only`, over every `u32`). The Lean half is not. Change `.refuse => 0` and every test still passes while refused lines forward unmediated. Fix queued: assert the three constructors map to exactly 0, 1, 2 |
| Rust `route_of_classify` mapping | `PINNED-BY-TEST` | `rust/tests/differential.rs` `classify_literal_only` | property test over all `u32`; fails closed on everything except literal 0 and 1 |
| Lean panic default on the classify seam | `PINNED` | `rust/tests/panic_probe.rs`, F1 fix | a compiled Lean panic returns the type default, and for `UInt32` that is `0 = passthrough`. Guarded by `lean_set_exit_on_panic`, with a probe driving the real binary AND an unguarded variant demonstrating the fail-open is genuine |
| canonical-equivalent duplicate keys | `PINNED` | commit `7f0739d`, `Host/UnicodeKeys.lean` | NFD identity; rejects a repeated canonical identity only, NOT non-ASCII keys generally. Justified by Swift `String ==` canonical equivalence plus the official MCP Swift SDK decoding into `[String: Value]` |
| `effect_message` Rust ↔ Lean byte twin | `FROZEN-EXPECTATION` | `rust/tests/envelope_v23_twin.rs` | layer 1 runs against a frozen expectation; layer 2 (live differential, no frozen middleman) was `#[ignore]`d pending kernel pin `9452f32`. **That commit is now an ancestor of the pinned `6c74b61`, so layer 2 is unblocked** |
| trim vs forwarded bytes | `CHARACTERISED` | `Host/Canonical.lean:43` vs `:77` | guards and parsing run on `line.trimAscii.toString`; `raw := line` is forwarded. Lean 4.28 `Char.isWhitespace` is exactly `0x09/0x0A/0x0D/0x20`, trimmed only from the ends, which is precisely RFC 8259 whitespace around a complete JSON value. Semantically inert. No pin required |
| `rust/` ↔ `sealAdapter` byte-level refinement | `TCB` | `CLAIMS.md`, `Host/SealAdapter.lean` "TRUST BOUNDARY (residual, stated loud)" | named future work. The model emits `serialize checked`; the host forwards `raw`. Disclosed, not enforced |
| classify-passthrough path in the adapter model | `TCB` | `Host/SealAdapter.lean` "Fidelity to `rust/src/main.rs` (P1-P6), stated honestly" | P1 named explicitly as unrepresented, along with P5, P6, P4, P7-P9 |
| nonce durable-consume vs decision ordering | `CHARACTERISED` | `rust/src/a3.rs:47,95-130`, `rust/src/replay_store.rs:70` | the nonce is durably burned before the decision lands, so a failure between them costs a caller their token. Fails CLOSED. The in-memory cache is rebuilt from the store on startup and is only ever a fast-path reject, so it cannot be more permissive than the durable record |

## Specification-only (named in the design spec, absent from both codebases)

Verified by repository-wide fixed-string search, zero matches each. These are **specification**
defects if they are defects at all. Do not add machinery to satisfy a document.

`judged_request_sha256` · `trust_context_ref` · `canonical_plane_encoding` ·
`m_code` / `n_code` / `m_pol` / `n_pol` · `deprecated_from` · `permitted_profiles` ·
`admission_key` · `kernel_tool_namespace`

---

## How to use this

When a review names a site, classify it against the code **before** recording it as a defect. Five
of six sites reported in one 2026-07-24 review were `SPEC-ONLY`, and two headline findings from the
host review were already disclosed in the source. A finding that is already written down is not a
finding.
