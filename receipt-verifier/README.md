# Authorization-decision re-derivation body

`wasm/seal.wasm` is the exact public verifier body identified by
`kernel_identity.wasm_sha256` in native-host authorization decisions. Its SHA-256 is:

```text
0b5e792500592b56847f70b1e27e47aecdc65023c7c59fd79695102c465f26ec
```

It replays the authorization-decision-carried policy to check decision bytes. The native
executor is identified separately by `host_identity`; this artifact does not
prove the native executor equivalent to the wasm body. That is the open Lane C
gap.
