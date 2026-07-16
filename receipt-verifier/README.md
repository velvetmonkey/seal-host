# Receipt re-derivation body

`wasm/seal.wasm` is the exact public verifier body identified by
`kernel_identity.wasm_sha256` in native-host decision receipts. Its SHA-256 is:

```text
ff1bfd68d7be51b6a395f94dfc46b2fb27ed11dc5833af6a84675f42f9730546
```

It replays the receipt-carried policy to check decision bytes. The native
executor is identified separately by `host_identity`; this artifact does not
prove the native executor equivalent to the wasm body. That is the open Lane C
gap.
