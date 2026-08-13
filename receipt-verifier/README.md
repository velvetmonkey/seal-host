# Authorization-decision re-derivation body

`wasm/seal.wasm` is the exact public verifier body identified by
`kernel_identity.wasm_sha256` in native-host authorization decisions. Its SHA-256 is:

```text
28bb3ae71985357163e3b651791e2a70c462ea5d1313a59b4967d4c20ea77657
```

It replays the authorization-decision-carried policy to check decision bytes. The native
executor is identified separately by `host_identity`; this artifact does not
prove the native executor equivalent to the wasm body. That is the open Lane C
gap.

## Six independent outcomes

`verify.mjs` verifies a detached receipt bundle and always emits six outcome
lines. It deliberately does not reduce a failed request or approval signature
to a generic receipt failure: issuer authentication, request authentication,
approval authentication, replay, history, and execution remain separately
observable.

```text
ISSUER AUTHENTICATED
REQUEST SIGNATURE VERIFIED
APPROVAL SIGNATURE VERIFIED
DECISION REPRODUCED
HISTORY NOT INDEPENDENTLY VERIFIED
EXECUTION NOT ATTESTED
```

The decision line is available only for `seal.single-step-closed/v1`, after the
verifier checks the six closure declarations and performs one fresh
`seal_init` plus one `seal_decide` against the SHA-256-bound WASM above. A
`seal.single-step-closed-stateful/v1` bundle prints `TRACE REQUIRED`; an absent
or unknown profile is a named non-zero refusal. History remains independently
negative because standalone replay cannot establish whether an approval nonce
was already consumed. No profile attests execution.

Usage:

```text
node receipt-verifier/verify.mjs RECEIPT.json \
  --issuer-pubkey ISSUER_ED25519_HEX \
  --request-pubkey REQUESTER_ED25519_HEX \
  --approval-pubkey APPROVER_ED25519_HEX
```

The three public keys are trust inputs, not values accepted from the receipt.
The detached statement signatures use Ed25519 over
`"seal.<role>-statement/v1\0" || uint64_be(payload_length) || payload` and
base64url-without-padding signature encoding. This verifier-only bundle surface
does not change the native authorization-decision producer or its signed shape.
