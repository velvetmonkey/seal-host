<!-- SPDX-License-Identifier: Apache-2.0 -->

# Authorization-Decision Schema (normative: v2 current, v1 legacy)

**Status: v1 CONVERGED (Day-2 complete, 2026-07-04).** The Day-1 freeze was
reviewed and passed; the two parked decisions were ruled: (1) neutral
discriminator `record_type: "seal.authorization-decision"` plus
`record_version: 1` adopted; (2) **hard split** of
`kernel_identity` vs asserted provenance, with `v0-live` grandfathered.
Producers and verifiers in seal-check and seal-assurance-kit now emit/accept
this schema (§10 records what landed). Serialization/format consolidation
only: nothing here changes the wasm binary, its pin, any Lean proof, or any
decision logic.

This document is the single normative definition of the JSON **authorization
decision** produced and verified across the seal family. It exists because
three incompatible dialects drifted into production:

| Dialect | Producer | Verifier | Fate under v1 |
|---|---|---|---|
| Schema K (`seal_check_receipt`) | `seal-check/kernel.js buildReceipt` | `seal-assurance-kit src/verify.cjs` (augmented as "kit receipt") | **Retired.** Producers converge to v1. Verifiers reject K with a clear "legacy" error. |
| Schema L (`seal_live_receipt`) | `seal-live-demo/seal-gateway/decide.cjs` | `seal-check/receipt.js` | **Adopted as v1** (generalised; L receipts remain valid as `v0-live`). |
| Host audit line | `seal-host/Host/Audit.lean` | `seal-host/scripts/seal_log.mjs` | **Not a receipt.** Distinct artifact — see §8. |

## 1. Canonical shape (v1 = Schema L, generalised)

A v1 receipt is a single JSON object. Version discriminator:

```
"record_type": "seal.authorization-decision",
"record_version": 1
```

Verifiers MUST also accept the legacy discriminator `"seal_live_receipt":
"v0"` with identical field semantics (`v0-live`; the deployed live-demo
gateway keeps emitting it until its own audited bump). The Schema K
discriminator `"seal_check_receipt"` is NOT v1-compatible; verifiers MUST
reject it as legacy, naming this spec.

> **Decision (ruled at Day-1 review):** the discriminator
> `record_type: "seal.authorization-decision"` with `record_version: 1` is
> adopted; producers do not spread the
> `seal_live_receipt` key beyond the deployed gateway that already emits it.

### Field table

| Field | Type | Required | Semantics |
|---|---|---|---|
| `record_type` | `"seal.authorization-decision"` | yes | authorization-decision type discriminator |
| `record_version` | `1` | yes (or legacy `seal_live_receipt:"v0"`) | schema version discriminator |
| `tool` | string | yes | mediated tool name (e.g. `"db.execute"`) |
| `arguments` | object | yes | complete parsed tool-call arguments; incoming member order is retained by Rust `serde_json`'s `preserve_order` feature and is significant (§2) |
| `_meta` | JSON value | optional | complete parsed `params._meta` value; absence means the request omitted `_meta`, while `{}` and `null` remain present and distinct (§2) |
| `requestState` | JSON value | optional | complete opaque `params.requestState` value; structural absence differs from every present value, including `{}` and `null`; consumers MUST NOT project or interpret its interior (§2) |
| `inputResponses` | JSON value | optional | complete `params.inputResponses` value with every member retained; structural absence differs from every present value, including `{}` and `null` (§2) |
| `now` | integer ≥ 0 | optional (default 1000) | the caller-supplied **logical clock** the kernel decided with — carried so re-derivation replays the same clock; NOT wall time |
| `canonical_request` | string | optional | legacy field name for the exact deterministic Rust request projection that was hashed; if present it MUST equal the line derived per §2 |
| `canonical_request_sha256` | 64-hex string | yes | SHA-256 of that deterministic request projection (§2) |
| `bypass` | boolean | yes | `true` = mediation was skipped (control run); §6 |
| `verdict` | `"ALLOW" \| "BLOCK" \| "ERROR"` | yes | §5 vocabulary |
| `reason` | string | yes | human-readable ground for the verdict |
| `deny_kernel` | string or null | yes when mediated | which gating kernel denied (null on ALLOW) |
| `certs` | array | yes when mediated | per-gate seals `{kernel, verdict, reason, certHash}` with `certHash` a **decimal string** (u64; §3) — top-level, not nested under `witness` |
| `emitted_bytes` | string | yes when mediated | verbatim `seal_decide` output |
| `kernel_identity` | object | yes | `wasm_sha256` (64-hex, or **null iff `bypass`**), `self_verified` (boolean). HARD SPLIT: never carries toolchain/axioms in v1. See §4 |
| `asserted_provenance` | object | optional | asserted-not-verified proof hygiene (`lean_toolchain`, `axioms`, `verified_in_browser` — MUST NOT be `true`); the only v1 home for toolchain/axioms (§4) |
| `kernel_config` | object | yes when mediated | the exact trusted config the kernel was initialised with — re-derivation input |
| `granted_capabilities` | array of objects | yes when mediated | the presented grants. Two entry forms (§3): **un-hashed** `{tool, <policy-selected fields>...}` when the producer holds the grant pre-image, or **opaque** `{target: "<64 lowercase hex>"}` when it does not (e.g. seal-check's fire-your-own box accepts raw targets) |
| `policy_id` | string | optional | producer's policy label |
| `signature` | object | optional | integrity envelope (e.g. live-demo HMAC demo key); never a substitute for re-derivation |

Producer-local trailing blocks (live-demo's `execution`, `gateway`) are
permitted; verifiers MUST ignore unknown top-level fields.

## 2. `canonical_request_sha256` — exact pre-image

`canonical_request` is a retained schema field name, not a JCS conformance
claim. Its bytes are the Rust `serde_json` serialization of this projection:

```js
JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
                 params: { name: <tool>, arguments: <arguments>,
                           ...(<_meta present> ? { _meta: <_meta> } : {}),
                           ...(<requestState present>
                                 ? { requestState: <requestState> } : {}),
                           ...(<inputResponses present>
                                 ? { inputResponses: <inputResponses> } : {}) } })
```

with `<tool>` = the receipt's `tool` and `<arguments>` = the receipt's
`arguments` object serialized in its retained incoming member order by Rust
`serde_json` with `preserve_order`; arrays retain order. When the receipt
carries `_meta`, it is inserted after `arguments`; the producer first applies
`envelope_v23::canonical_json` (recursive Unicode-scalar key sorting), reparses
that text, then the whole projection is emitted through `serde_json`.
`requestState` and `inputResponses` retain their parsed incoming member order.
This is deliberately **not** described as
the envelope/kernel renderer: Lean's signed-effect rule differs on control
escaping and some numbers, and the host boundary rejects those signed inputs
rather than pretending the receipt serializer is identical. The exact split
and remaining RFC 8785 divergences are in
[`CANONICAL-BYTE-CONTRACT.md`](CANONICAL-BYTE-CONTRACT.md). When
`_meta` is absent, the historical
two-member `params` bytes are unchanged unless an MRTR value follows it.
Present `requestState` is inserted after `_meta` (or after `arguments` when
metadata is absent) as one opaque complete JSON value. Present
`inputResponses` follows `requestState` (or the last earlier present member)
as one complete JSON value with every nested member retained. No present JSON
value is an absence sentinel. The hash is SHA-256 over the UTF-8 bytes of that
line, lowercase hex.

This single function subsumes both prior dialects — the divergence was never
the shape, only what was fed in:

* Schema K's `input.request_line` was already exactly this line for the
  receipt's own `(tool, args)` (`seal-check/seal-config.js` `rpc()`).
* Schema L hardcoded `name: "db.execute"`; v1 generalises `name` to `tool`.
  For every existing L receipt the bytes are unchanged.

**Verifier obligation (closes drift (c)):** a verifier MUST derive this line
from the SAME `(tool, arguments, _meta presence/value, requestState
presence/value, inputResponses presence/value)` it feeds the kernel for
re-derivation — never hash one stored string while re-deriving from a
different field. It MUST treat `requestState` opaquely and retain the complete
`inputResponses` value. If the receipt carries `canonical_request`, the
verifier MUST check it equals the derived line before hashing.

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

The current private verified wasm pin (`2d9ef8e0b0b977bde9b9a95832493aee24771c727fb954bae693faa9bf730ba0`)
is not changed by this authorization-decision schema; the pending audited public repin
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
2. Derive the canonical line from the same
   `(tool, arguments, _meta presence/value, requestState presence/value,
   inputResponses presence/value)` used for re-derivation; check stored
   `canonical_request` (if present) equals it; hash and compare to
   `canonical_request_sha256`.
3. Resolve `granted_capabilities` per §3 (recompute un-hashed entries from
   the policy; count opaque entries); re-run the kernel with
   `kernel_config` and the receipt's `now`; require verdict equality and
   (when present) byte-identical `emitted_bytes`.
3a. Check the kernel-attested request commitment: the `request_sha256`
   inside `emitted_bytes`' audit must equal the receipt's top-level
   `request_sha256`. For unparseable-request receipts this is the ONLY
   binding of kernel material to the request, and it is kernel-backed,
   not host-asserted.
4. Handle `bypass` per §6: report NOT MEDIATED, never "verified".
5. Reject `seal_check_receipt` objects as legacy Schema K.

## 8. The host audit line is NOT an authorization decision

`seal-host/Host/Audit.lean` emits `{epoch, tool, verdict, request_sha256,
certs}` (verdict lowercase `allow`/`deny`; `request_sha256` the kernel's own
SHA-256 commitment to the exact line it judged, keys serialized in
lexicographic order) per decision; `seal-host/scripts/seal_log.mjs`
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
* **Derived compatibility implementation:** `seal-assurance-kit/kernel/receipt-format.js`
  follows the same receipt-format rule independently, with documented kit-only
  omissions such as `signed_config`; it is not a byte copy. From sibling
  checkouts, `git diff --no-index ../seal-check/receipt-format.js ../seal-assurance-kit/kernel/receipt-format.js >/dev/null; test $? -eq 1`
  confirms that deliberate divergence.

Frozen exports (signatures are the Day-1 contract):

```js
AUTHORIZATION_DECISION_RECORD_TYPE // "seal.authorization-decision"
AUTHORIZATION_DECISION_VERSION     // 1
RECORD_TYPE_KEY                    // "record_type"
RECORD_VERSION_KEY                 // "record_version"
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
module and this spec ever disagree. The kit's `kernel.js` is a separate host
integration of the shared kernel contract, not a byte copy of seal-check's.
From sibling checkouts,
`git diff --no-index ../seal-check/kernel.js ../seal-assurance-kit/kernel/kernel.js >/dev/null; test $? -eq 1`
shows the integration-specific branches.

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
   `seal-assurance-kit`'s `seal verify`. The kit fixture
   (`fixtures/receipt-crosstool.json`) independently represents the compatible
   receipt while omitting kit-unsupported `signed_config`; it is wired into
   `npm test`, not copied byte for byte. From sibling checkouts,
   `git diff --no-index ../seal-check/test/fixtures/cross-receipt.json ../seal-assurance-kit/fixtures/receipt-crosstool.json >/dev/null; test $? -eq 1`
   displays that deliberate difference.
5. seal-live-demo stays as-is (`v0-live` accepted); its own bump to
   `record_type: "seal.authorization-decision", record_version: 1` is a
   separate, later step. **Superseded by §11:** the
   demo's bump goes straight to v2.

## 11. Authorization-decision schema v2 (DRAFT — frozen on merge of this section)

**Status: DRAFT, 2026-07-08.** v2 extends v1 with an approval block, derived
effect hashes, and class-gated payment fields, so one authorization-decision schema serves
every surface (Lean model via the conformance bridge, Rust host, wasm,
browser, checker) and the payments/PO audit story. Nothing in v2 changes the
host audit line or chain record (§8) — those artifacts stay byte-identical;
the v2 authorization decision is emitted alongside them. Nothing here changes any
Lean proof, the wasm binary, its pin, or decision logic.

Version discriminator:

```
"record_type": "seal.authorization-decision",
"record_version": 2
```

**Acceptance ladder (ruled 2026-07-08):** verifiers accept `v2` (current),
`v1` (accepted-legacy — grandfathered exactly as `v0-live` was under v1; no
hard break), and `v0-live` (grandfathered). Schema K stays rejected.
Producers converge repo-by-repo; a producer emits exactly one version.

### 11.1 Field table (delta over §1)

Every v1 field carries forward with unchanged semantics. New fields:

| Field | Type | Required | Semantics |
|---|---|---|---|
| `approval` | object | yes when mediated and `verdict = "ALLOW"`; optional on BLOCK (present iff an approval was consulted) | the approval that authorized the effect — see 11.2 |
| `authorization` | `"approval"` \| `"explicit_policy_allow"` | required on new mediated ALLOW producers; absent on BLOCK | distinguishes a human-approved guarded ALLOW from policy-v2's explicit safe ALLOW. Legacy v2 ALLOW receipts without it are interpreted as `approval`. |
| `approval.approval_identity` | object | yes within `approval` | `{channel, key_id?}`; `channel` ∈ `"file" \| "interactive" \| "ed25519"`; `key_id` = SHA-256 fingerprint of the OPERATOR-CONFIGURED approval verifying key (`--approval-pubkey`), present **iff** `channel = "ed25519"`. A boot-scoped constant of the trust root — never derived from the request, never from the token (the token gates whether `approval` appears, not what this says). Names the APPROVER's key, never the caller — see the authority frontier below. Never asserts a session id the producer did not parse. |
| `approval.nonce` | string | yes iff `channel = "ed25519"`; absent otherwise unless the channel truly carried one | approval nonce (64 lowercase hex on the signed channel) |
| `approval.issued_at` | integer (epoch ms) | yes iff the channel carried it | mint time as presented; producers MUST NOT invent it |
| `approval.expiry` | integer (epoch ms) | yes iff derivable (`issued_at` + TTL) or carried | absolute expiry deadline |
| `approval.policy_hash` | 64-hex string | yes within `approval` | SHA-256 of the deterministic Rust `kernel_config` serialization — see 11.3 |
| `args_hash` | 64-hex string | yes when mediated and the request parsed (see the unparseable-request rule below) | SHA-256 of the deterministic Rust `arguments` serialization — see 11.3 |
| `request_sha256` | 64-hex string | yes on native-host receipts | SHA-256 of the terminator-stripped request body the kernel judged (pre-canonicalisation). This established field is not the ApprovalRecord v2 framed-subject digest. Present on every receipt and kernel-attested: the kernel emits the same hash inside its audit (`emitted_bytes`), and the producer cross-checks the two before persisting — a mismatch is a SEAM failure that fails closed. |
| `framed_subject_sha256` | 64-hex string | yes on native-host receipts | SHA-256 of the exact delimiter-bearing raw frame used by ApprovalRecord v2 subject admission. Deliberately named separately from `request_sha256`; for ordinary LF-framed requests these hash nearly the same bytes but MUST NOT be interchanged. |
| `framed_subject_length` | non-negative integer | yes on native-host receipts | Byte length of the exact delimiter-bearing raw frame hashed by `framed_subject_sha256` and matched by ApprovalRecord v2. |
| `request_parse_error` | string | yes iff the producer could not parse the wire line | names why the structured request material is absent |
| `action` | string | optional | the SealV2 `params.action` binding when the producer parsed one; absent under the `compatible` profile, which does not parse it |
| `host_identity` | object | optional; required for the native Rust host | `{native_executable_sha256, lean_ffi_sha256, equivalence:"not_proven"}`. Identifies the native artifacts that executed the decision. It does **not** prove them equivalent to `kernel_identity.wasm_sha256`; that remains the Lane C gap. |
| `principal` | string | yes iff the kernel authenticated a V2.1 signed envelope; ABSENT otherwise (fail-closed) | the id of the signed-config `principals` registry key whose Ed25519 envelope verified in the Lean parse path over the exact judged line. Copied ONLY from the authoritative Lean step output — kernel-attested, never request-derived (the one carve-out from the descriptive-only rule; see the authority frontier below) |
| `amount` | number or string | yes iff payment-class (11.4) | copied **verbatim** from the argument field the policy's payment binding names |
| `merchant` | string | yes iff payment-class | ditto |
| `currency` | string | yes iff payment-class | ditto |

**Honesty rule (normative):** a field whose value the producer does not hold
is ABSENT — never null-filled, never fabricated. `approval_identity` states
the channel that actually supplied the approval; `nonce`/`issued_at`/`expiry`
appear only when that channel actually carried or derived them.

**Unparseable-request rule (normative, native host):** the kernel is
deliberately the more tolerant parser — lines exist that Lean mediates and
serde cannot re-parse (the differential corpus pins `1e309`). The receipt
layer is DESCRIPTIVE and holds no veto over the kernel's verdict: on such a
line the producer emits the receipt with `request_sha256`,
`framed_subject_sha256`, `framed_subject_length`, and
`request_parse_error`, and OMITS `tool`, `arguments`, `args_hash`,
`canonical_request`, `canonical_request_sha256` (and any payment fields,
which are bound to arguments it does not hold) — the honesty rule applied to
the request itself. Verifiers re-derive what the receipt carries: on an
unparseable-request receipt that is the kernel material
(`certs`/`emitted_bytes`/`kernel_config`) against the raw line identity,
with no canonical-request re-derivation possible.

**The authority frontier (normative — who a receipt authenticates):**
`approval_identity` answers *"whose key authorized this action"* and NEVER
*"which agent made this call"*. Its value is a boot-scoped constant of the
approval trust root: the `channel` flag the operator started the host with,
and (`ed25519` only) the SHA-256 fingerprint of the configured approval
verifying key. The signed approval token gates whether the `approval` block
appears; it never chooses the identity value. The authentication claim is
CHANNEL-SCOPED: only `ed25519` verifies signatures; `file` and `interactive`
are DEV-ONLY and unauthenticated — their receipts name a channel kind and no
key, and a verifier must read them as carrying no identity authentication at
all.

There is no caller identity in the receipt, and that absence is proven
rather than pending: on a stdio mediation topology every request byte is
authored by the very agent being gated, so NO function of the mediated
bytes — or of anything else the host holds at dispatch time — can
authenticate the caller (`Host/ReceiptIdentity.lean`,
`stdio_no_caller_authentication`; the request-independence of the identity
that IS present is `receipt_identity_separated`, exercised against the real
binary by `rust/tests/receipt_identity.rs`). Producers MUST NOT mint a
`caller_id` / `program_origin` / agent-identity field from request material;
whatever value one caller can plant there, every other caller can plant
byte-identically (`forgeable_echo`) — such a field is an unauthenticated
echo wearing an identity's clothes, and verifiers MUST treat any occurrence
of one as descriptive request material, never as provenance.

**What would bind a caller (V2.1 — the G1 caller/principal axis):** a
topology change, not a receipt field: per-caller transport credentials
(peer-credentialed per-caller sockets, an authenticated gateway in front of
the host, or per-caller approval keys). Once the transport constrains who
can send what, an authenticator exists —
`credentialed_topology_authenticates` proves the seam suffices — and a
`caller` binding can then ride the same trusted plane the isolation
theorems already filter on (`Host/Provenance.lean`,
`replayNamespace_trusted_plane`). Until then the honest receipt binds the
approver and refuses to name the caller.

**The V2.1 `principal` field (Route 2, signed envelope) — the ONE carve-out
from the descriptive-only rule above.** An optional top-level `principal`
field (string) is the id of a key from the signed config's `principals`
registry whose Ed25519 envelope VERIFIED, in the Lean parse path
(`Host.verifyEnvelope`), over the exact judged line — it is exactly the
credentialed instantiation the previous paragraph describes, not a
request-derived field. Semantics:

- present **iff** the kernel authenticated a signed envelope; absence means
  "no authenticated principal" (fail-closed `none`), never an error;
- the value is copied by the assembler ONLY from the authoritative Lean
  step output (one producer; `Ffi.principalOutField` /
  `Ffi.receipt_principal_authenticated`), and its request-independence is
  the presence/value split (`Host.envelope_gates_presence_not_value`:
  request bytes gate only WHETHER the field appears, never WHICH id);
- the assembler-faithfulness half is the **R-PRINC** seam
  (`Ffi.PrincipalFaithful`) — an explicit hypothesis discharged by
  `rust/tests/principal_identity.rs` including the mutation drill;
- what stays trusted: Ed25519 unforgeability + extern faithfulness at the
  request-path call site, and the Rust-side nonce-freshness window.

Verifiers MUST treat `principal` as authenticated (kernel-attested) and
MUST continue to treat every OTHER identity-shaped occurrence
(`caller_id`, `program_origin`, `agent`, a `principal` string inside
`arguments`, …) as descriptive request material. The caller no-go on bare
stdio is untouched: `principal` exists only when a cryptographic envelope
restricted the send relation — "authenticated principal when the envelope
verifies," never "caller authentication on stdio."

### 11.2 Requiredness matrix

| Context | `approval` | `nonce` | `issued_at` | `expiry` | `policy_hash` | `args_hash` | `amount`/`merchant`/`currency` |
|---|---|---|---|---|---|---|---|
| ALLOW via ed25519 channel | required | required | required | required | required | iff parsed | iff payment-class |
| ALLOW via file channel | required | if carried | if carried | if derivable | required | iff parsed | iff payment-class |
| ALLOW via interactive channel | required | if carried | if carried | if derivable | required | iff parsed | iff payment-class |
| BLOCK (mediated) | optional | — | — | — | in `approval` if present | iff parsed | iff payment-class |
| bypass | absent | — | — | — | — | absent | absent |

`iff parsed` means required whenever the producer parsed the wire line, and
ABSENT otherwise — see the unparseable-request rule in 11.1. Verifiers MUST
NOT treat `args_hash` (or `tool`, `arguments`, `canonical_request`,
`canonical_request_sha256`) as unconditionally required on a mediated
receipt: a receipt carrying `request_parse_error` is well-formed, and
rejecting it would restore to the verifier the veto the producer was
deliberately stripped of.

### 11.3 Derived hashes (computable on every surface)

Both hashes use the §2 deterministic Rust/ECMAScript-style serialization
discipline over the parsed object, SHA-256 over the UTF-8 bytes, lowercase
hex. They are not RFC 8785/JCS hashes. They are derived fields: any verifier
recomputes them from the receipt's own `arguments` / `kernel_config` and
REJECTS on mismatch.

```
args_hash   := sha256Hex(UTF8(JSON.stringify(arguments)))
policy_hash := sha256Hex(UTF8(JSON.stringify(kernel_config)))
```

Frozen vectors (enforced by the format tests in seal-check and the kit):

| # | input | sha256 |
|---|---|---|
| V5 (args of §2 V4) | `{"database":"prod","sql":"drop table users"}` | `46657b69f15f78859ead6dd0d416cbfc9809922757ba90aa16a56b7d73afafc8` |
| V6 (args of §2 V1) | `{"operation":"insert","table":"staging_deploy_audit","payload":"{\"deploy_ref\":\"deploy-2026-06-30\"}"}` | `53ae7fa46f79dd2637b3d5af5a160834b755d0a00a66fec11cb313db8bca753c` |
| V7 (policy_hash of the 11.4 example config) | see 11.4 | `436c50ce0860d500c188e7e7c8133eed1e41e626b01174727159f3f664e84407` |

Rationale for `policy_hash`: the host's only policy identifier today is
`config.epoch`; `policy_hash` binds the receipt to the exact config bytes
without requiring new host knowledge, and `epoch` remains visible inside
`kernel_config` itself.

### 11.4 Payment-class tools (runtime config, never proof-bearing)

A tool is payment-class iff the **host runtime config** declares it so.
The declaration lives in the tool rule and never reaches the kernel or any
proof (ruled 2026-07-08):

```json
{"name": "payments.send", "mode": "guarded",
 "payment": {"class": "payment",
             "bind": {"amount": "amount", "merchant": "to", "currency": "currency"}},
 "target": [{"literal": "pay"}, {"arg": "to"}, {"arg": "amount"}]}
```

V7's exact input (stored key order): `{"epoch":1,"safety":{"approval":{"ttl_seconds":120},"tools":[{"name":"payments.send","mode":"guarded","payment":{"class":"payment","bind":{"amount":"amount","merchant":"to","currency":"currency"}},"target":[{"literal":"pay"},{"arg":"to"},{"arg":"amount"}]}]}}`

The producer copies each bound argument value verbatim into the top-level
payment field. Verifier obligation: for a payment-class receipt, each payment
field MUST byte-equal the bound argument (`receipt.amount ==
arguments[bind.amount]`, etc.); any mismatch is a REJECT — this is the
`gate:amount-merchant-mismatch` negative gate. Non-payment tools carry none
of the three fields; the live-demo `db.execute` gateway emits none.

### 11.5 Deterministic serialization and roundtrip stability

v2 key order (extends the §1/`V1_KEY_ORDER` pattern; producers emit exactly
this top-level order):

```
record_type, record_version, tool, action, arguments, _meta, requestState,
inputResponses, args_hash, now,
canonical_request, canonical_request_sha256, request_sha256, request_parse_error,
bypass, verdict, authorization, reason,
deny_kernel, amount, merchant, currency, approval, certs, emitted_bytes,
kernel_identity, host_identity, asserted_provenance, kernel_config, granted_capabilities,
policy_id, signature
```

Within `approval`: `approval_identity, nonce, issued_at, expiry,
policy_hash`; within `approval_identity`: `channel, key_id`.

**Roundtrip obligation (normative):** for any valid v2 receipt `r`,
`assembleReceiptV2(parse(serialize(r)))` is byte-identical to
`serialize(r)`. Every producing repo ships a vector test asserting this on
its fixtures.

### 11.6 Verifier obligations (delta over §7)

6. Recompute `args_hash` and `approval.policy_hash` from the receipt's own
   `arguments` / `kernel_config`; REJECT on mismatch.
7. Payment-class receipts: check the 11.4 byte-equalities; REJECT on
   mismatch. A receipt carrying payment fields for a tool the supplied
   config does not declare payment-class is REJECTED (fabrication).
8. `approval_identity` consistency: known `channel` value; `key_id` present
   iff `channel = "ed25519"`.
9. v1 receipts remain verifiable under §7 unchanged (accepted-legacy).

### 11.7 Surfaces and emitters

| Surface | v2 role |
|---|---|
| Rust host (seal-host) | NEW additive emitter assembling v2 from step output + config + approval channel; audit line + chain record unchanged (§8) |
| Lean model | via the conformance bridge: v2 assembled from the model oracle's step output through the shared JS assembly; any in-Lean serializer is a separate proposal, not part of this spec |
| wasm / browser (seal-check) | `buildReceipt` emits v2 via `assembleReceiptV2` |
| checker (seal-assurance-kit) | `seal verify` accepts v2 + v1 + v0-live; fixtures regenerate as v2 |
| live demo (seal-live-demo) | gateway emits v2 (kills the v0 drift); evidence + bundle regenerate via the real docker run |

Shared implementation stays the §9 frozen seam: `seal-check/receipt-format.js`
is the authoritative implementation; the kit and the live demo vendor
byte-identical copies. This authority statement is not a JCS claim.
