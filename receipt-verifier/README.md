# Receipt re-derivation body

`wasm/seal.wasm` is the exact public verifier body identified by
`kernel_identity.wasm_sha256` in native-host decision receipts. Its SHA-256 is:

```text
a37901811df4767fd08142243622b8372254e6ec5bd2d3aca18f0e61d0f109af
```

It replays the receipt-carried policy to check decision bytes. The native
executor is identified separately by `host_identity`; this artifact does not
prove the native executor equivalent to the wasm body. That is the open Lane C
gap.
