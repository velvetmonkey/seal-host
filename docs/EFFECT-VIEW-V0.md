# `seal.effect-view/v0`

`effect_view` is a non-authoritative, authorization-decision-only projection emitted by the
native host for each successfully parsed MCP JSON-RPC `tools/call`. It does
not participate in the kernel verdict, signature verification, request
routing, approval consumption, or freshness checks.

The object has this shape:

```json
{
  "schema": "seal.effect-view/v0",
  "source": "mcp-jsonrpc/tools-call@1",
  "adapter": {"type": "mcp-jsonrpc/tools-call", "version": "1"},
  "principal": {"id": "authenticated-id", "session": "runtime-session"},
  "session": "runtime-session",
  "effect": {"resource": "tool.name", "action": "call", "arguments": {}},
  "raw_preimage_sha256": "existing-request_sha256",
  "policy_hash": "trusted-config-sha256",
  "idempotency_key": "runtime-session:existing-request_sha256",
  "policy_version": 1,
  "policy_version_enforced": false,
  "authoritative": false
}
```

`effect.resource` and `effect.arguments` are derived host-side from the exact
line already judged by Lean. Arguments remain by value; neither
`canonical_request`, `canonical_request_sha256`, nor `args_hash` replaces
them. `principal` is absent unless the kernel authenticated an id; when
present its `id` is copied from the authenticated principal already exposed
in the step output and its `session` is passive runtime context. The sibling
`session` field records that boot-scoped context on every view.
`policy_version` records the verified signed config's required `epoch` and is
advisory only. `policy_hash` reuses the authorization decision's existing canonical hash of
the trusted config; neither field is signed by the principal envelope.

If the authorization-decision-side parser cannot recover the MCP call, `effect_view` is
absent and `request_parse_error` plus the existing kernel-cross-checked
`request_sha256` remain. That absence cannot change or veto the verdict.

## Idempotency follow-up

This version records a content-addressed key but does not add a replay store.
A later enforcing consumer must scope keys by runtime session and apply these
semantics atomically: the same key with the same raw preimage is idempotent
success; the same key with a different raw preimage is a hard failure. Such a
store is deliberately outside this authorization-decision-only change.

## Freshness and record commitments

The runtime session and idempotency key are passive authorization-decision fields. They do
not enter either A3 instance or inspect, consume, extend, or otherwise alter
nonce/TTL state. The request-envelope nonce/TTL A3 window remains the sole
freshness authority for the V2.2 principal envelope.

The view is not part of `Host.auditLine`, `Host.Record.Log`, or the
tamper-evident Lean chain payload. It changes only the sidecar authorization
decision assembled in `rust/src/authorization_decision.rs`; the Lean-emitted record
shape and wasm are unchanged, so no wasm repin is required.
