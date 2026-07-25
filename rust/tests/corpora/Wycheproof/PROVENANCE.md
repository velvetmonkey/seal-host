# Wycheproof Ed25519 corpus provenance

- Upstream: <https://github.com/C2SP/wycheproof>
- Commit: `b61843a9a5115bb758134b6a1f5d5e502d445342`
- Upstream file: `testvectors_v1/ed25519_test.json`
- Upstream Git blob: `17cfb05dae4a351777d9e08e46095d81659b10b4`
- Files vendored: only `ed25519_test.json`
- File size: 122,087 bytes
- SHA-256: `70471c053c711731f2195ef4875b60ea7f5d6793939d99058ac12da810cb8e00`

The test hashes the byte-for-byte vendored file before invoking the verifier,
so an edit or substitution fails loudly with both the expected and actual
digest. Only the Ed25519 verification vector file is vendored because this
lane exercises the production Ed25519 verifier and the corpus must remain
available without network access.
