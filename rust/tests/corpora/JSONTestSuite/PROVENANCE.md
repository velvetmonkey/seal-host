# JSONTestSuite corpus provenance

- Upstream: <https://github.com/nst/JSONTestSuite>
- Commit: `1ef36fa01286573e846ac449e8683f8833c5b26a`
- Upstream `test_parsing/` Git tree: `b936f9acdd24b9f5fefe68b90b9beab2c681137a`
- Files vendored: only the 318 vectors in `test_parsing/`
- Aggregate SHA-256: `c80de9c62f456f949d4479bb686eab521f2362deea15ef9f808d8b45dfd724d3`

The aggregate SHA-256 uses the `sha256-record-v1` format documented in
`rust/tests/external_json_corpus.rs`. The test verifies it before invoking
either parser, so a vector edit, rename, addition, or deletion fails loudly
with both the expected and actual digest.

Only `test_parsing/` is vendored because external-corpus evidence must remain
available without network access and an unfetchable corpus must fail rather
than skip. Omitting the upstream parser wrappers, result pages, and transform
suite keeps the checkout cost to the parsing vectors actually exercised.
