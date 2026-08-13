# Conformance

Seal's deployment claim is byte identity over a corpus, not a theorem about every possible input.

The acceptance bridge lives in `seal-host/scripts/conformance_bridge.mjs`. Its Stage 3 gate compares:

- interpreted Lean model;
- native `.so` entry point;
- rebuilt wasm artifact;
- deployed Rust host record-chain behavior;
- JavaScript target-commitment mirrors used by the checker and demos.

The target commitment is lowercase 64-hex SHA-256 over `encodeParts(parts)`, where each part is framed as `<charCount>:<part>` using Lean/String code-point count, then encoded as UTF-8 before hashing. This is intentionally separate from the legacy UInt64 `certHash` audit helper.

What conformance says: for the corpus, the bodies emit byte-identical target hashes, decisions, audit bytes, and record chain heads.

What it does not say: Rust, wasm, JavaScript, browsers, compilers, or operating systems are proven correct for every possible input.

Local checks for this repo:

```sh
lake build
lake exe axiom_check
lake exe sha256_selfcheck
scripts/build_ffi_so.sh
cd rust && cargo test
cd .. && node scripts/conformance_bridge.mjs --wasm
```

### G2 crash-test fresh-artifact control

The CI `rust-conformance:control_31` step runs the fresh-artifact proof for
exactly these three tests:

<!-- g2-fresh-artifact-tests:begin -->
- `g2_t1_crash_between_reserve_and_recorded_recovers_the_approval`
- `g2_t2_second_presentation_fails_while_reservation_open`
- `g2_t3_crash_after_recorded_keeps_burn_and_receipt`
<!-- g2-fresh-artifact-tests:end -->

No other G2 test is covered by this compile-proof control. Locally, the three
forced rebuilds and test runs measured `G2_GUARD_WALL_SECONDS=75.29`. When
`SEAL_CI_READ_TOKEN` is empty, the control is skipped because the private FFI
dependency cannot be built; that skip is explicitly allowlisted in
`.github/ci-control-skip-allowlist.json` and is visible as a skip rather than
being described as fresh-artifact coverage.

To run the host, build the Lean core and start `rust/target/debug/seal-host-rs` with a signed config and a child MCP server. See `docs/ARCHITECTURE.md` and `docs/CONFORMANCE.md` before deploying.
