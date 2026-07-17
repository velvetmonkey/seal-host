# Receipt re-derivation body

`wasm/seal.wasm` is the exact public verifier body identified by
`kernel_identity.wasm_sha256` in native-host decision receipts. Its SHA-256 is:

```text
2d9ef8e0b0b977bde9b9a95832493aee24771c727fb954bae693faa9bf730ba0
```

It replays the receipt-carried policy to check decision bytes. The native
executor is identified separately by `host_identity`; this artifact does not
prove the native executor equivalent to the wasm body. That is the open Lane C
gap.
