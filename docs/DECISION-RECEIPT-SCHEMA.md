<!-- SPDX-License-Identifier: Apache-2.0 -->

# Decision-Receipt Schema v1 (normative)

**Status: v1 CONVERGED (Day-2 complete, 2026-07-04).** The Day-1 freeze was
reviewed and passed; the two parked decisions were ruled: (1) neutral
discriminator `seal_receipt: "v1"` adopted; (2) **hard split** of
`kernel_identity` vs asserted provenance, with `v0-live` grandfathered.
Producers and verifiers in seal-check and seal-assurance-kit now emit/accept
this schema (§10 records what landed). Serialization/format consolidation
only: nothing here changes the wasm binary, its pin, any Lean proof, or any
decision logic.

This document is the single normative definition of the JSON **decision
receipt** produced and verified across the seal family. It exists because
three incompatible dialects drifted into production:

| Dialect | Producer | Verifier | Fate under v1 |
|---|---|---|---|
| Schema K (`seal_check_receipt`) | `seal-check/kernel.js buildReceipt` | `seal-assurance-kit src/verify.cjs` (augmented as "kit receipt") | **Retired.** Producers converge to v1. Verifiers reject K with a clear "legacy" error. |
| Schema L (`seal_live_receipt`) | `seal-live-demo/seal-gateway/decide.cjs` | `seal-check/receipt.js` | **Adopted as v1** (generalised; L receipts remain valid as `v0-live`). |
| Host audit line | `seal-host/Host/Audit.lean` | `seal-host/scripts/seal_log.mjs` | **Not a receipt.** Distinct artifact — see §8. |

## 1. Canonical shape (v1 = Schema L, generalised)

A v1 receipt is a single JSON object. Version discriminator:

```
"seal_receipt": "v1"
```

Verifiers MUST also accept the legacy discriminator `"seal_live_receipt":
"v0"` with identical field semantics (`v0-live`; the deployed live-demo
gateway keeps emitting it until its own audited bump). The Schema K
discriminator `"seal_check_receipt"` is NOT v1-compatible; verifiers MUST
reject it as legacy, naming this spec.

> **Decision (ruled at Day-1 review):** the neutral discriminator
> `seal_receipt: "v1"` is adopted; producers do not spread the
> `seal_live_receipt` key beyond the deployed gateway that already emits it.

### Field table

| Field | Type | Required | Semantics |
|---|---|---|---|
| `seal_receipt` | `"v1"` | yes (or legacy `seal_live_receipt:"v0"`) | schema version discriminator |
| `tool` | string | yes | mediated tool name (e.g. `"db.execute"`) |
| `arguments` | object | yes | the tool-call arguments, verbatim; key order is fixed at production time and is significant (§2) |
| `now` | integer ≥ 0 | optional (default 1000) | the caller-supplied **logical clock** the kernel decided with — carried so re-derivation replays the same clock; NOT wall time |
| `canonical_request` | string | optional | the exact canonical request line that was hashed; if present it MUST equal the line derived per §2 |
| `canonical_request_sha256` | 64-hex string | yes | SHA-256 of the canonical request line (§2) |
| `bypass` | boolean | yes | `true` = mediation was skipped (control run); §6 |
| `verdict` | `"ALLOW" \| "BLOCK" \| "ERROR"` | yes | §5 vocabulary |
| `reason` | string | yes | human-readable ground for the verdict |
| `deny_kernel` | string or null | yes when mediated | which gating kernel denied (null on ALLOW) |
| `certs` | array | yes when mediated | per-gate seals `{kernel, verdict, reason, certHash}` with `certHash` a **decimal string** (u64; §3) — top-level, not nested under `witness` |
| `emitted_bytes` | string | yes when mediated | verbatim canonical `seal_decide` output |
| `kernel_identity` | object | yes | `wasm_sha256` (64-hex, or **null iff `bypass`**), `self_verified` (boolean). HARD SPLIT: never carries toolchain/axioms in v1. See §4 |
| `asserted_provenance` | object | optional | asserted-not-verified proof hygiene (`lean_toolchain`, `axioms`, `verified_in_browser` — MUST NOT be `true`); the only v1 home for toolchain/axioms (§4) |
| `kernel_config` | object | yes when mediated | the exact trusted config the kernel was initialised with — re-derivation input |
| `granted_capabilities` | array of objects | yes when mediated | the presented grants. Two entry forms (§3): **un-hashed** `{tool, <policy-selected fields>...}` when the producer holds the grant pre-image, or **opaque** `{target: "<64 lowercase hex>"}` when it does not (e.g. seal-check's fire-your-own box accepts raw targets) |
| `policy_id` | string | optional | producer's policy label |
| `signature` | object | optional | integrity envelope (e.g. live-demo HMAC demo key); never a substitute for re-derivation |

Producer-local trailing blocks (live-demo's `execution`, `gateway`) are
permitted; verifiers MUST ignore unknown top-level fields.

## 2. `canonical_request_sha256` — exact pre-image

The canonical request line is:

```js
JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
                 params: { name: <tool>, arguments: <arguments> } })
```

with `<tool>` = the receipt's `tool` and `<arguments>` = the receipt's
`arguments` object serialised **in its stored key order** (JS objects
preserve insertion order for non-integer-like keys; integer-like argument
names are forbidden in v1 for this reason). The hash is SHA-256 over the
UTF-8 bytes of that line, lowercase hex.

This single function subsumes both prior dialects — the divergence was never
the shape, only what was fed in:

* Schema K's `input.request_line` was already exactly this line for the
  receipt's own `(tool, args)` (`seal-check/seal-config.js` `rpc()`).
* Schema L hardcoded `name: "db.execute"`; v1 generalises `name` to `tool`.
  For every existing L receipt the bytes are unchanged.

**Verifier obligation (closes drift (c)):** a verifier MUST derive this line
from the SAME `(tool, arguments)` it feeds the kernel for re-derivation —
never hash one stored string while re-deriving from a different field. If
the receipt carries `canonical_request`, the verifier MUST check it equals
the derived line before hashing.

Frozen test vectors (also enforced by `test/receipt-format.test.cjs` in
seal-check and `test/format-check.cjs` in seal-assurance-kit):

| # | tool | arguments | sha256 |
|---|---|---|---|
| V1 (real live-demo receipt, `evidence/receipts.jsonl` line 1) | `db.execute` | `{"operation":"insert","table":"staging_deploy_audit","payload":"{\"deploy_ref\":\"deploy-2026-06-30\"}"}` | `66330ea2242d45a5a6b32d85007464125608fec7e88430fa3c23d5c5303db756` |
| V4 (kit block fixture, `fixtures/receipt-block.json`) | `db.execute` | `{"database":"prod","sql":"drop table users"}` | `460d746ba064ab9398885158dddfd6d32f1722b0efe0d3b6085c8441e9127793` |

V4 is the proof of convergence: the kit's stored Schema-K
`canonical_request_sha256` is byte-identical to what the v1 function
produces.

## 3. Capability targets — one convention, policy-determined arity

Approval targets are computed by the JS mirror of Lean `Seal.stableHashParts`:

```
encoded := parts.map(p => `${charCount(p)}:${p}`).join("")
target := SHA-256(UTF-8(encoded)) as 64-character lowercase hex
```

`charCount` is the JavaScript/Lean string character count, not UTF-8 byte
length. For non-ASCII, the bytes hashed are still the UTF-8 bytes of the
netstring text.

**The convention (pinned):**

```
target = stableHashParts([ tool, ...parts ])
```

where `parts` are the policy's `target` spec entries resolved **in policy
order** — each `{literal: s}` contributes `s`, each `{arg: a}` contributes
the call's argument value `a`. The prior "arity mismatch" (2-part vs 3-part)
was two policies, not two conventions: arity is policy-determined and both
existing uses already follow this rule.

Frozen vectors:

| # | policy target spec | encoded parts | target hex |
|---|---|---|---|
| V2 | `[{literal:"store"}]` (seal-check `store.update`) | `12:store.update5:store` | `6bff1759cf3c00f781f0b15d428f4cf84e59f8b10be48dd4dd742175a3e6f984` |
| V2b | `[{literal:"pay"}]` (seal-check `payments.send`) | `13:payments.send3:pay` | `e35dd14f3e1d02fec3b03a781b7f8928bfd1ce7b7f93a23a7b61228c536bd73a` |
| V3 | `[{arg:"table"},{arg:"operation"}]` (live-demo `db.execute`) | `10:db.execute20:staging_deploy_audit6:insert` | `351f47a44bcf935c7242432e24bd11db1536d7c1da873f0ca953c8b80ae02433` |

A v1 receipt carries grants in `granted_capabilities`, in one of two entry
forms, and the verifier resolves them via the shared
`capabilityTargetsFromPolicy(kernel_config, grants)`:

* **Un-hashed** `{tool, <fields>...}` — the strong form; the producer held
  the grant pre-image. The verifier recomputes the target from the POLICY's
  target spec for that tool: `{literal}` parts come from the policy itself,
  `{arg}` parts from the entry's field of that name, in policy order.
* **Opaque** `{target: "<64 lowercase hex>"}` — the producer did not hold the
  pre-image (e.g. a raw target pasted into seal-check's fire-your-own box).
  The verifier uses the target verbatim and COUNTS it: verdict
  re-derivation still holds, but the grant binding cannot be independently
  checked for that entry. Receipts say what the producer actually knew —
  opaque entries are honest, not equivalent.

## 4. `kernel_identity` and asserted provenance

Required keys: `wasm_sha256` (SHA-256 hex of the exact wasm binary the
producer executed; **null iff `bypass`**) and `self_verified` (boolean —
whether the producer hashed the loaded bytes against its pin). The key name
is `self_verified` (Schema L); Schema K's `self_verified_in_browser` is
retired with K.

Toolchain/axiom provenance (`lean_toolchain`, `axioms`) is ASSERTED, not
verified by any receipt consumer. **HARD SPLIT (ruled at Day-1 review, per
the L0 mediation profile §6.2,
`seal-check/docs/SEAL-MEDIATION-PROFILE-L0.md`):** in v1 these keys are
FORBIDDEN inside `kernel_identity` — a v1 receipt carrying them there is
invalid (`validateReceipt` rejects it). Their only v1 home is the separate
`asserted_provenance` block, whose `verified_in_browser` MUST NOT be `true`.
Legacy `v0-live` receipts with the merged block are grandfathered: verifiers
accept them as v0-live and base nothing on those fields either way.

The wasm pin itself (`ebd17c14668176612c49f6e2940b23df82a2c1a7cdef6759f0d6276ae997e9d0`)
is untouched by this spec; the pending audited repin
(`docs/CONFORMANCE-BRIDGE.md`) is a separate step.

## 5. Verdict vocabulary

Receipts use exactly `ALLOW | BLOCK | ERROR`. Mapping from the kernel wire:

| kernel output | receipt verdict |
|---|---|
| `route: "forward"` | `ALLOW` |
| `route: "passthrough"` (not a mediated call) | `ALLOW` (reason says passthrough) |
| `route: "block"` (audit verdict `deny`) | `BLOCK` |
| `error` | `ERROR` |

The host audit line (§8) uses lowercase `allow`/`deny`; the normative map is
`allow → ALLOW`, `deny → BLOCK`. `DENY` never appears in a receipt.

## 6. Bypass receipts

`bypass: true` records that mediation was deliberately skipped (the seal-off
control). Requirements: `kernel_identity.wasm_sha256 = null`,
`self_verified = false`, no `kernel_config`/`emitted_bytes`/`certs`
obligations. A verifier MUST report a bypass receipt as **NOT MEDIATED** —
it is not "verified", and its `ALLOW` is not a kernel verdict. (The kit's
`seal verify` currently has no bypass branch; that is a Day-2 convergence
item.)

## 7. Verifier obligations (summary)

0. Validate the shape FIRST (`validateReceipt`): version discriminator,
   field table, hard split, stored-line-vs-derived-line equality. A
   malformed receipt never reaches the kernel.
1. `kernel_identity.wasm_sha256` equals the verifier's own hash of the
   binary it will re-run, and that binary matches the audited pin.
2. Derive the canonical line from the same `(tool, arguments)` used for
   re-derivation; check stored `canonical_request` (if present) equals it;
   hash and compare to `canonical_request_sha256`.
3. Resolve `granted_capabilities` per §3 (recompute un-hashed entries from
   the policy; count opaque entries); re-run the kernel with
   `kernel_config` and the receipt's `now`; require verdict equality and
   (when present) byte-identical `emitted_bytes`.
4. Handle `bypass` per §6: report NOT MEDIATED, never "verified".
5. Reject `seal_check_receipt` objects as legacy Schema K.

## 8. The host audit line is NOT a decision receipt

`seal-host/Host/Audit.lean` emits `{epoch, tool, verdict, certs}` (verdict
lowercase `allow`/`deny`) per decision; `seal-host/scripts/seal_log.mjs`
chains those lines with `SHA256(prevHead ‖ 0x1f ‖ payload)` (the in-Lean
demonstration instance uses FNV — documented in
`docs/VERIFIABLE-RECORD.md`). Different fields, different purpose (tamper
evidence over a trace, not per-call re-derivability), different hash
primitive. Nothing in this spec restructures it; the only bridge is the
verdict map in §5 and the shared `certs` entry shape (§1). Tools MUST NOT
present an audit line as a receipt or vice versa.

## 9. Shared implementation (the frozen seam)

One module implements §2, §3 and §5 for every JS producer/verifier:

* **Canonical source:** `seal-check/receipt-format.js` (pure ES module,
  browser + Node, zero dependencies).
* **Vendored byte-identical copy:** `seal-assurance-kit/kernel/receipt-format.js`
  — same discipline as the kit's existing vendored `kernel.js` /
  `seal-config.js`. Any change lands in seal-check first, then is re-copied.

Frozen exports (signatures are the Day-1 contract):

```js
RECEIPT_SCHEMA_VERSION            // "v1"
RECEIPT_VERSION_KEY               // "seal_receipt"
LEGACY_VERSION_KEYS               // ["seal_live_receipt", "seal_check_receipt"]
VERDICTS                          // ["ALLOW", "BLOCK", "ERROR"]
HOST_AUDIT_VERDICT_MAP            // { allow: "ALLOW", deny: "BLOCK" }
canonicalRequest(tool, args, id=1)      // -> string   (§2 line)
sha256Hex(bytes)                        // -> hex      (pure-JS, browser-safe)
canonicalRequestSha256(tool, args)      // -> hex      (§2)
stableHashParts(parts)                  // -> hex      (§3)
capabilityTarget(tool, parts)           // -> hex      (§3 convention)
capabilityTargetsFromPolicy(cfg, grants) // -> { approvals, opaque, errors } (§3 resolve)
assembleReceiptV1(fields)               // -> object   (§1 fixed key order, byte-stable)
validateReceipt(obj)                    // -> { ok, version, errors }
```

Both repos ship a vector test (`V1/V2/V2b/V3/V4` above) that fails if the
module and this spec ever disagree. The kit's vendored `kernel.js` is also a
byte-identical copy of seal-check's (pre-existing discipline, re-vendored
with each producer change).

## 10. Day-2 convergence — LANDED (2026-07-04)

1. **DONE** `seal-check/kernel.js buildReceipt` emits v1 via
   `receipt-format.js` (hard-split identity + `asserted_provenance`; grants
   carried as opaque `{target}` entries since seal-check accepts raw
   targets). `app.js` call sites + conformance CLAUSE_MAP updated;
   `SEAL-MEDIATION-PROFILE-L0.md` §4 carries a supersession note.
2. **DONE** `seal-check/receipt.js` validates first, derives the line from
   `(tool, arguments)` (hardcode gone), resolves grants via
   `capabilityTargetsFromPolicy`, replays `now`, checks `emitted_bytes`,
   and reports bypass receipts NOT MEDIATED.
3. **DONE** kit: `gen-receipt.cjs` emits v1 (fixtures regenerated as v1);
   `verify.cjs` accepts v1 + `v0-live`, rejects Schema K, has the bypass
   branch (exit non-zero, prints `NOT MEDIATED`), and derives the hashed
   line from the same call it re-runs, asserting stored-line equality
   first. `fixtures/receipt-bypass.json` exercises the branch in `npm test`.
4. **DONE** cross-tool test: `seal-check/test/fixtures/cross-receipt.json`
   (produced by the shipped seal-check producer, byte-pinned) passes BOTH
   `seal-check/receipt.js` (`test/cross-receipt.test.cjs`) and
   `seal-assurance-kit`'s `seal verify`
   (`fixtures/receipt-crosstool.json`, byte-identical copy, wired into
   `npm test`).
5. seal-live-demo stays as-is (`v0-live` accepted); its own bump to
   `seal_receipt: "v1"` is a separate, later step.
