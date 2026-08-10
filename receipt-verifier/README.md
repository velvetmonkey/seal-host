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
