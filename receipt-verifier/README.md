# Receipt re-derivation body

`wasm/seal.wasm` is the exact public verifier body identified by
`kernel_identity.wasm_sha256` in native-host decision receipts. Its SHA-256 is:

```text
df42cbada2297741bfeab99f222b96ac02e43a4ce8695b24922b425b8d66b1e8
```

It replays the receipt-carried policy to check decision bytes. The native
executor is identified separately by `host_identity`; this artifact does not
prove the native executor equivalent to the wasm body. That is the open Lane C
gap.
