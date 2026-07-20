# V2.3 effect envelope — staged host contract

Status: **gated, host/Rust side only**. The implementation is available only
with `--envelope-v23`. The currently pinned Lean artifact does not contain the
V2.3 adapter or Fable's proof package, so the host deliberately refuses every
V2.3 mediated call at the independent-kernel-principal cross-check. Enabling
the flag is useful for client integration and frisking; it is not a way to
authorize V2.3 traffic before the separately reviewed repin.

No V2.2 compatibility window exists inside V2.3 mode. A line claiming to be an
envelope must satisfy the V2.3 shape or it is refused as ambiguous.

## Session issuance

Before starting the child-output relay, the host emits exactly one JSON-RPC
notification:

```json
{"jsonrpc":"2.0","method":"notifications/seal/session","params":{"schema":"seal.session/v1","envelope":"seal.effect/v1","session":"seal-session-v1:<64 lowercase hex>"}}
```

The 32 random bytes come from `/dev/urandom`; failure to obtain them refuses
startup. The value is stable for the life of this host process and is the
host equality comparand for `principal.session`. It is not the receipt-only
`seal-host-rs/stdio:<pid>:<start-ms>` string. The notification is acknowledged
by the single stdout owner before the child relay starts, so a child frame
cannot race ahead of session issuance.

At the future Lean integration, this issued value must be threaded into the
trusted approval/replay session plane used by Fable's session-equality gate.
This branch does not edit Lean or claim that integration is already proven.

## Wire shape

The outer object is exactly `{seal_env, request}`. `request` is the non-empty,
newline/CR/NUL-free string whose exact UTF-8 bytes remain the decision value.
Unknown `seal_env` members fail closed. Optional seats may be omitted and map
to their empty wire values.

```json
{
  "seal_env": {
    "key_id": "alice",
    "sig": "<128 hex>",
    "nonce": "<64 hex>",
    "issued_at": 1234,
    "adapter": {"type": "mcp", "version": "2025-06-18"},
    "principal": {"session": "seal-session-v1:<64 lowercase hex>"},
    "effect": {"resource": "db.execute", "action": "call", "args": "{\"q\":1}"},
    "idempotency_key": "client-chosen-key",
    "policy_version": "",
    "delegation": {"on_behalf_of": "", "parent_capability_ref": ""},
    "revocation_subject": "",
    "audience": "",
    "causality_token": "",
    "expires_at": 0
  },
  "request": "{\"jsonrpc\":\"2.0\",...}"
}
```

`effect` is optional. When present and non-empty under the MCP adapter, Rust
derives `(params.name, params.action, canonical params.arguments)` from the
exact judged line and requires equality. A mismatch fails before signature
verification can influence routing. The claim remains advisory: it never
replaces `request` as the line passed to the kernel.

`policy_version`, both delegation strings, `revocation_subject`, `audience`,
`causality_token`, and `expires_at` are signed seats. They are deliberately not
read by a host authorization gate; empty strings and `expires_at = 0` are
accepted. In particular, `policy_version` may differ from the active config
epoch without causing rejection.

## Exact signed bytes

The Ed25519 message is the exact twin of
`SealV2.Effect.effectMessage` on Fable's V2.3 proof branch:

```text
"seal.effect/v1\0"
|| authority[32]
|| frame(key_id)
|| nonce[32]
|| u64be(issued_at)
|| frame(line)
|| frame(adapter.type) || frame(adapter.version)
|| frame(principal.session)
|| frame(effect.resource) || frame(effect.action) || frame(effect.args)
|| frame(idempotency_key)
|| frame(policy_version)
|| frame(delegation.on_behalf_of) || frame(delegation.parent_capability_ref)
|| frame(revocation_subject)
|| frame(audience) || frame(causality_token)
|| u64be(expires_at)
```

where `frame(x) = u64be(byte_length(UTF-8(x))) || UTF-8(x)`. The authority is
the raw 32-byte config verification key, not request data. An absent effect is
three empty frames; absent string seats are empty frames. Fixed-width fields
remain raw as shown.

Rust verifies the registered principal signature over this reconstructed full
tuple only after adapter, session, and non-empty effect equality checks pass.
It then requires the kernel step output to report the identical authenticated
registry id before consulting the route. Missing or unequal identity is a
mediation seam failure.

The Rust golden-vector test is a byte-for-byte test against Fable's checked
vector. It is test evidence, not a substitute for Fable's Lean proofs or for
the future cross-repository repin review.
