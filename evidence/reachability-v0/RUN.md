<!-- SPDX-License-Identifier: Apache-2.0 -->

# RUN reach0-v0-20260727T000059Z

Worktree: `/home/monkey/wt/reach0`

Branch: `feat/reachability-report-v0`

No Lean build was started.

## Trust anchor

The evidence run used a freshly generated ephemeral Ed25519 seed. The seed was
mode `0600` while in use and was deleted after the artifacts were issued. It
was not committed.

Expected public key:

```text
54ed621adcd5d537ba367deabb3ffe083829f664a32815d13fc5ab6ac42d9085
```

This key authenticates the captured run only. No external identity
certification for its owner is claimed.

## Commands physically run

```text
export PATH=/home/monkey/.cargo/bin:$PATH
export SEAL_FFI_LIB_DIR=/home/monkey/wt/perimeter/.lake/build/lib
cargo test --lib reachability::tests::
cargo clippy --lib --bin seal-reachability-report -- -D warnings
cargo build --bin seal-reachability-report

rust/target/debug/seal-reachability-report issue \
  --config config/reachability-v0.deployment.json \
  --signing-key-file .reach0-evidence-seed.hex \
  --out evidence/reachability-v0/report.signed.json

rust/target/debug/seal-reachability-report verify \
  --report evidence/reachability-v0/report.signed.json \
  --expected-pubkey 54ed621adcd5d537ba367deabb3ffe083829f664a32815d13fc5ab6ac42d9085
```

Focused tests: 3 passed, 0 failed, 0 ignored.

Base verification: exit 0. Verbatim verifier output is in
`verification.output.txt`.

A copy whose signed payload was changed from `release service` to
`release altered` was rejected with exit 2. Verbatim rejection is in
`tamper-rejection.output.txt`.

## Base report

The signed artifact is `report.signed.json`; its verbatim human rendering is
`report.output.txt`.

- 10 enumerated records;
- 2 BROKERED;
- 1 UNBROKERED;
- 7 UNKNOWN;
- denominator explicitly unsound; and
- coverage not computed.

## Negative control

`reachability-v0-negative-control.json` adds the declared direct handle
`negative-control.direct-echo-handle`, backed by the executable `/bin/echo`.
The resulting signed artifact is
`negative-control.signed.json`, with verbatim rendering in
`negative-control.output.txt`.

The report changed from 10 to 11 records and from 1 to 2 UNBROKERED records.
The new line is:

```text
  - negative-control.direct-echo-handle [tool_handles]: a direct subprocess tool handle invoking /bin/echo — the negative-control runtime configuration exposes this innocuous handle without crossing the seal-host transport
```

This demonstrates that a declared path outside the broker is not silently
discarded. `/bin/echo reach0-negative-control-reachable` was physically
executed and its output is in `negative-control-reachable.output.txt`. It does
not demonstrate automatic discovery of an undeclared path; that is an explicit
v0 limitation.

## Failed attempts

- `docs/NORTH-STAR-V3.md` was absent from both the fresh `main` worktree and
  `/home/monkey/src/seal-host`; §V3.2 was read from
  `/home/monkey/src/seal/docs/NORTH-STAR-V3.md`.
- `cargo fmt --all -- --check` exposed unrelated pre-existing rustfmt drift in
  `rust/tests/differential.rs` and `rust/tests/common/mod.rs`. Only the new
  source files were formatted, preserving the unrelated files.
- The first evidence seed fixture was malformed (29 bytes, not 32) and the
  signing tool rejected it.
- The first output redirection targeted `rust/evidence` instead of the
  repository-level `evidence` directory and failed before issuing an artifact;
  the empty directories were removed.
