# V2.3 effect envelope — staged host contract

Status: **gated behind `--envelope-v23`**. The manifest-pinned Lean source
package defines and proves the `seal.effect/v2` message shape, and Rust
independently reconstructs and verifies the same bytes. The shipped runtime
artifact has not yet been repinned and integrated to return the V2.3
authenticated principal, so the independent kernel-principal cross-check
still refuses V2.3 mediated calls. The flag is for client integration and
frisking, not a pre-repin authorization path.

There is no V2.2 compatibility window inside V2.3 mode. A line containing
`seal_env` must satisfy the strict V2.3 wrapper and envelope shapes or it is
refused as ambiguous.

## Session issuance

Before starting the child-output relay, the host emits exactly one JSON-RPC
notification:

```json
{"jsonrpc":"2.0","method":"notifications/seal/session","params":{"schema":"seal.session/v1","envelope":"seal.effect/v2","session":"seal-session-v1:<64 lowercase hex>"}}
```

The 32 random bytes come from `/dev/urandom`; failure to obtain them refuses
startup. The value is stable for the life of this host process and is the
host equality comparand for `principal.session`. It is not the receipt-only
`seal-host-rs/stdio:<pid>:<start-ms>` string. The notification is acknowledged
by the single stdout owner before the child relay starts, so a child frame
cannot race ahead of session issuance.

At runtime this issued value must also agree with the trusted
approval/replay session plane used by the kernel's session-equality gate.

## Wire shape

The outer object is exactly `{seal_env, request}`. `request` is a mandatory,
non-empty, newline/CR/NUL-free string. Its exact UTF-8 bytes are the signed
and judged `line`; the envelope's advisory `effect` never replaces it.
Unknown members in the outer object, `seal_env`, `adapter`, `principal`, or a
present `effect` object fail closed.

```json
{
  "seal_env": {
    "key_id": "alice",
    "sig": "<128 hex>",
    "nonce": "<64 hex>",
    "issued_at": 1234,
    "expires_at": 5678,
    "adapter": {"type": "mcp", "version": "2025-06-18"},
    "principal": {"session": "seal-session-v1:<64 lowercase hex>"},
    "policy_version": "policy-1",
    "effect": {"resource": "db.execute", "action": "call", "args": "{\"q\":1}"}
  },
  "request": "{\"jsonrpc\":\"2.0\",...}"
}
```

The signed inputs, in signed order, are:

| Order | Input | Presence and checks |
| ---: | --- | --- |
| 1 | `authority` | Mandatory trusted input, exactly 32 raw bytes; not request data. |
| 2 | `seal_env.key_id` | Mandatory string; verification requires a matching registered principal key. |
| 3 | `seal_env.nonce` | Mandatory string decoding to exactly 32 bytes. |
| 4 | `seal_env.issued_at` | Mandatory unsigned 64-bit integer. |
| 5 | `seal_env.expires_at` | Mandatory unsigned 64-bit integer; zero fails verification. |
| 6 | `request` | Mandatory outer string; its exact UTF-8 bytes are signed as `line`. |
| 7 | `seal_env.adapter.type` | Mandatory string; checked against the deployed adapter. |
| 8 | `seal_env.adapter.version` | Mandatory string; checked against the deployed adapter. |
| 9 | `seal_env.principal.session` | Mandatory string; empty or unequal to the issued session fails verification. |
| 10 | `seal_env.policy_version` | Mandatory string; empty fails verification and the kernel gates equality to trusted policy state. |
| 11 | `seal_env.effect` | Optional. A missing key or `null` declares absence; any object declares presence and must contain string `resource`, `action`, and `args`, even when all three are empty. |

`sig` is also a mandatory `seal_env` member and must decode to 64 bytes, but
it is the Ed25519 signature over the tuple and is not itself signed. JSON
member order is not significant; the order above is the encoder's byte
order.

When `effect` is present under the MCP adapter, Rust derives
`(params.name, params.action, canonical params.arguments)` from the exact
judged line and requires equality. The all-empty object is therefore an
ordinary present claim, not an absence sentinel, and normally fails that
equality check.

### Migration note — Stage B2 v1-to-v2 reconciliation (2026-07-25)

The retired `seal.effect/v1` layout signed the effect as three unconditional
frames, followed by seats for `idempotency_key`, `policy_version`,
`delegation.on_behalf_of`, `delegation.parent_capability_ref`,
`revocation_subject`, `audience`, and `causality_token`, then a trailing
`expires_at`. An absent effect and a present all-empty effect therefore had
the same three-empty-frame encoding.

`seal.effect/v2` removes these six fields completely:
`idempotency_key`, `on_behalf_of`, `parent_capability_ref`,
`revocation_subject`, `audience`, and `causality_token`. The first five
candidate seats had no interpreter in this envelope; `revocation_subject`
was also on the wrong trust plane because revocation is authority state, not
a requester-controlled restriction. `policy_version` and `expires_at` were
rescued, moved into the current tuple, made mandatory, and gated.
The effect is now an option with a signed presence byte.

An old key cannot silently survive as an unsigned authorization input.
Inside `seal_env` it is rejected as unknown; a leftover sibling beside
`seal_env` and `request` is also rejected because the outer wrapper is exact.
An upstream record may retain such a key only outside the submitted wrapper;
the V2 encoder has no field from which to read or sign it, so it cannot
influence V2 envelope verification. Integrations must remove old keys from
the submitted wrapper rather than relying on them being ignored.

The tag changes from `seal.effect/v1\0` to `seal.effect/v2\0`, separating old
signatures from the stripped and reconciled layout.

## Exact signed bytes

The Ed25519 message is the exact twin of the manifest-pinned
`SealV2.Effect.effectMessage`:

```text
"seal.effect/v2\0"
|| authority[32]
|| frame(key_id)
|| nonce[32]
|| u64be(issued_at)
|| u64be(expires_at)
|| frame(request)
|| frame(adapter.type)
|| frame(adapter.version)
|| frame(principal.session)
|| frame(policy_version)
|| opt_effect(effect)
```

Here:

```text
frame(x) = u64be(byte_length(UTF-8(x))) || UTF-8(x)

opt_effect(missing or null) =
  00

opt_effect({"resource":"","action":"","args":""}) =
  01
  || 0000000000000000
  || 0000000000000000
  || 0000000000000000
```

Thus the complete option-block hex encodings are different:

```text
effect: null
00

effect: {"resource":"","action":"","args":""}
01000000000000000000000000000000000000000000000000
```

`u64be` is exactly eight bytes, big-endian. Lengths count UTF-8 bytes, not
Unicode scalar values. The tag includes its trailing NUL. `authority` and
decoded `nonce` are raw fixed-width bytes. The `0x00` or `0x01` effect
presence byte is inside the signed message; changing absence to presence is
a signature-relevant byte change.

Rust verifies the registered principal signature over this reconstructed
tuple after its host-owned adapter, session, mandatory-binding, and present
effect checks. It then requires the kernel step output to report the same
authenticated registry id before consulting the route; missing or unequal
identity is a mediation-seam failure.
