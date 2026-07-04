<!-- SPDX-License-Identifier: Apache-2.0 -->

# Decision-Receipt Schema v1 (normative)

**Status: Day-1 FROZEN DRAFT — spec + shared-module seam only. Producers and
verifiers are NOT yet rewired; that convergence happens after this freeze is
reviewed.** Serialization/format consolidation only: nothing here changes the
wasm binary, its pin, any Lean proof, or any decision logic.

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

> **Review point 1:** the new neutral discriminator `seal_receipt: "v1"`
> (rather than making every producer emit `seal_live_receipt`) is a Day-1
> decision — veto here if the family should instead keep the L key verbatim.

### Field table

| Field | Type | Required | Semantics |
|---|---|---|---|
| `seal_receipt` | `"v1"` | yes (or legacy `seal_live_receipt:"v0"`) | schema version discriminator |
| `tool` | string | yes | mediated tool name (e.g. `"db.execute"`) |
| `arguments` | object | yes | the tool-call arguments, verbatim; key order is fixed at production time and is significant (§2) |
| `canonical_request` | string | optional | the exact canonical request line that was hashed; if present it MUST equal the line derived per §2 |
| `canonical_request_sha256` | 64-hex string | yes | SHA-256 of the canonical request line (§2) |
| `bypass` | boolean | yes | `true` = mediation was skipped (control run); §6 |
| `verdict` | `"ALLOW" \| "BLOCK" \| "ERROR"` | yes | §5 vocabulary |
| `reason` | string | yes | human-readable ground for the verdict |
| `deny_kernel` | string or null | yes when mediated | which gating kernel denied (null on ALLOW) |
| `certs` | array | yes when mediated | per-gate seals `{kernel, verdict, reason, certHash}` with `certHash` a **decimal string** (u64; §3) — top-level, not nested under `witness` |
| `emitted_bytes` | string | yes when mediated | verbatim canonical `seal_decide` output |
| `kernel_identity` | object | yes | `wasm_sha256` (64-hex, or **null iff `bypass`**), `self_verified` (boolean). See §4 |
| `kernel_config` | object | yes when mediated | the exact trusted config the kernel was initialised with — re-derivation input |
| `granted_capabilities` | array of objects | yes when mediated | the presented grants, un-hashed: each entry carries `tool` plus the policy-selected argument fields (§3) |
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

Approval targets are computed by the JS mirror of Lean
`Seal.Hash.stableHashParts`:

```
acc := 14695981039346656037
for each Unicode codepoint c of parts.join("|"):
    acc := (acc * 1099511628211 + c) mod 2^64
```

(u64 result; exceeds `Number.MAX_SAFE_INTEGER`, so it is a BigInt in JS and
MUST be serialised as a decimal **string** or an exact integer literal —
never through lossy `Number`.)

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

| # | policy target spec | parts fed | decimal target |
|---|---|---|---|
| V2 | `[{literal:"store"}]` (seal-check `store.update`) | `["store.update","store"]` | `11662918066780758608` |
| V2b | `[{literal:"pay"}]` (seal-check `payments.send`) | `["payments.send","pay"]` | `2693940768235235512` |
| V3 | `[{arg:"table"},{arg:"operation"}]` (live-demo `db.execute`) | `["db.execute","staging_deploy_audit","insert"]` | `11517196862591714860` |

A v1 receipt carries grants **un-hashed** in `granted_capabilities`
(entry = `{tool, <selected arg fields>...}`); the verifier recomputes each
target with the convention above before re-derivation.

## 4. `kernel_identity` and asserted provenance

Required keys: `wasm_sha256` (SHA-256 hex of the exact wasm binary the
producer executed; **null iff `bypass`**) and `self_verified` (boolean —
whether the producer hashed the loaded bytes against its pin). The key name
is `self_verified` (Schema L); Schema K's `self_verified_in_browser` is
retired with K.

Toolchain/axiom provenance (`lean_toolchain`, `axioms`) is ASSERTED, not
verified by any receipt consumer. v0-live receipts carry these inside
`kernel_identity`; that stays accepted. v1 producers SHOULD emit them in a
separate `asserted_provenance` block instead, per the L0 mediation profile
§6.2 (`seal-check/docs/SEAL-MEDIATION-PROFILE-L0.md`) — verifiers MUST base
nothing on these fields either way.

> **Review point 2:** v1 keeps L's merged block *accepted* but *discouraged*.
> If the family wants a hard split (§6.2 strictly), say so at review and the
> Day-2 producers will emit `asserted_provenance` only.

The wasm pin itself (`1cc765c7de2cead88eda2e8e5f5af5a5e070f35a767916e754b873733562c70a`)
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

1. `kernel_identity.wasm_sha256` equals the verifier's own hash of the
   binary it will re-run, and that binary matches the audited pin.
2. Derive the canonical line from the same `(tool, arguments)` used for
   re-derivation; check stored `canonical_request` (if present) equals it;
   hash and compare to `canonical_request_sha256`.
3. Recompute approval targets from `granted_capabilities` per §3; re-run the
   kernel with `kernel_config`; require verdict equality and (when present)
   byte-identical `emitted_bytes`.
4. Handle `bypass` per §6.
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
stableHashParts(parts)                  // -> BigInt   (§3)
capabilityTarget(tool, parts)           // -> BigInt   (§3 convention)
validateReceipt(obj)                    // -> { ok, version, errors }
```

Both repos ship a vector test (`V1/V2/V2b/V3/V4` above) that fails if the
module and this spec ever disagree.

## 10. Day-2 convergence plan (after this freeze is reviewed)

1. `seal-check/kernel.js buildReceipt` → emit v1 (fields of §1) via
   `receipt-format.js`.
2. `seal-check/receipt.js` → derive the line via `canonicalRequest(tool,
   arguments)` (drop the `db.execute` hardcode), validate via
   `validateReceipt`.
3. `seal-assurance-kit gen-receipt.cjs` → emit v1; `verify.cjs` → accept v1
   (+`v0-live`), add the bypass branch, and derive the hashed line from the
   same call it re-runs (§2 obligation), asserting equality with any stored
   line first.
4. Cross-tool test: one receipt produced by seal-check verifies under BOTH
   `seal-check/receipt.js` and `seal-assurance-kit verify.cjs`.
5. seal-live-demo stays as-is (`v0-live` accepted); its own bump to
   `seal_receipt: "v1"` is a separate, later step.
