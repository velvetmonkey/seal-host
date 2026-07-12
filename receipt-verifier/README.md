# Receipt re-derivation body

`wasm/seal.wasm` is the exact public verifier body identified by
`kernel_identity.wasm_sha256` in native-host decision receipts. Its SHA-256 is:

```text
ebd17c14668176612c49f6e2940b23df82a2c1a7cdef6759f0d6276ae997e9d0
```

It replays the receipt-carried policy to check decision bytes. The native
executor is identified separately by `host_identity`; this artifact does not
prove the native executor equivalent to the wasm body. That is the open Lane C
gap.
