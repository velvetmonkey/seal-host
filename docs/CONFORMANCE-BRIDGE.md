<!-- SPDX-License-Identifier: Apache-2.0 -->
# The spec→binary conformance bridge

The theorems bind the **Lean model**: L0 four-gate non-bypass
(`Host.step_forward_non_bypass`) and L1 verifiable record
(`Host.Record.tamper_evident`, `log_reflects_l0_decisions`). The shipped
artifact is that model **compiled** — Lean → C → native `libsealffi.so`, linked
by the deployed `seal-host-rs`. Nothing in a proof binds a theorem to a running
binary. This harness is that binding, **as far as it honestly goes**.

## What this is — and is NOT

- It **is** differential evidence, on a finite corpus C, that native codegen
  preserved the proven decisions and the audit bytes.
- It is **NOT** a theorem, and **NOT** a universal "the binary equals the
  model." We do not verify the Lean compiler or its C codegen (or emscripten
  for the WASM shape); that compile is trusted (T3 in the TCB ledger). The
  bridge converts that bare trust into *tested on the security-relevant corpus*.
- The corpus is no longer only the 15 named cases below: the **three-way
  property differential** (`rust/tests/three_way.rs`, see its own section)
  re-runs native ≡ wasm ≡ model byte-agreement every CI cycle over a seeded,
  generated adversarial corpus (25,000 fuzz cases + curated families in CI;
  soak counts on demand). The evidence is bigger; its KIND is unchanged —
  finite cases, not a universal claim.

The corpus-only line is load-bearing. Do not restate the result as "the deployed
binary is proven correct."

## The claim (evidence, over corpus C)

For every input in C:

1. **Decision agreement** — the route the compiled artifact takes
   (`forward` / `block` / `passthrough`) equals the route the **real Lean
   functions** take.
2. **Record agreement** — the artifact's emitted audit certificate is
   **byte-identical** to the model's, so the SHA-256 record chain
   (`scripts/seal_log.mjs`, the machine-checked structure `rollingHead` with
   `H = SHA-256`) over the artifact's log has the **same head** as over the
   model's log. In native mode, the deployed Rust host also emits that
   production receipt head directly, and the bridge checks it against an
   independent re-derivation.

Chain agreement reduces to payload agreement, which reduces to (1) + audit
serialization — so the whole thing rests on byte-identical audit emission,
which the harness checks directly.

## The three oracles

| Oracle | What it is | Backend |
|---|---|---|
| **MODEL** | the REAL Lean `stepImpl` (`scripts/model_oracle.lean`, via `lake env lean`) | Lean **interpreter** — never a reimplementation |
| **NATIVE** | `kernel_oracle` calling `seal_host_step` | the compiled **`libsealffi.so`** the deployed host links |
| **DEPLOYED** | the actual `seal-host-rs` binary over stdio | the shipped artifact, end-to-end |
| **WASM** | the emscripten module (`seal_init`/`seal_decide`) headless in Node | the compiled **`seal.wasm`** — the in-browser seal-check shape (`--wasm` mode) |

The MODEL side being the **interpreter** is the point: interpreter vs native
codegen is exactly the gap a codegen bug would open. The oracle evaluates the
same Lean source the theorems govern, through Lean's own evaluator, so a
divergence is a codegen defect, not a spec question.

R6 boundary: the interpreter cannot execute the `@[extern]` Ed25519
config-signature leaf. The MODEL oracle therefore initialises from the
harness-trusted payload through a non-exported model-only helper. Native,
WASM, and deployed oracles still initialise from the signed envelope and
verify the real signature. Config-signature behavior is covered by dedicated
startup/config tests, not by the interpreted MODEL leg of this bridge.

## Corpus C (finite, named — not exhaustive)

- 11 destructive-delete **disguises** (drop / delete / truncate × casing /
  leading-trailing whitespace / tab) — all must `block`.
- 3 **passthrough** lines (initialize / tools/list / notification).
- 1 **approved forward** (the canonical destructive call with a fresh live
  approval) — exercises the `forward` route and the allow path.

Both routes and both record outcomes (deny audit, allow audit) are covered.

## Run it

```sh
node scripts/conformance_bridge.mjs          # native .so + deployed seal-host-rs
node scripts/conformance_bridge.mjs --wasm    # emscripten seal.wasm (browser shape)
# exit non-zero on any divergence
```

Green transcripts: `docs/conformance-ci-transcript.txt` (native),
`docs/conformance-wasm-ci-transcript.txt` (wasm). Each asserts, in order:
harness liveness (below), 15/15 byte agreement + route agreement, and
artifact/model chain-head equality (native mode additionally checks the
deployed-`seal-host-rs` emitted receipt head against the model chain head). All
three artifacts — native `.so`, `seal.wasm`, and the deployed binary — produce
the **same** SHA-256 record head as the Lean model over corpus C.

## Red-team / objections (adversarially reviewed)

- **"Is the harness vacuous — would it pass even if nothing matched?"** No. A
  liveness gate runs first and fails the harness unless (a) the corpus actually
  exercises all three routes and (b) the record chain is order-sensitive (a
  reordered log yields a different head). A comparator that couldn't
  discriminate would trip these before any PASS.
- **"Interpreter == native proves nothing; they're the same source."** That is
  precisely the claim's scope: *given the source is the proven source*, the
  bridge shows the two BACKENDS (bytecode interpreter vs C codegen) agree on C.
  It catches a codegen/ABI-marshalling bug — the realistic model↔binary gap —
  not a spec bug (the proofs cover that).
- **"Wall-clock nondeterminism could hide a divergence."** The corpus's audit
  payloads are clock-independent (no timestamp in `auditLine`; the temporal
  cert reason is trace-length, the safety reason is a target hash), and `now`
  is fixed in the model step inputs. The deployed binary uses its own wall
  clock yet produces a byte-identical record — demonstrated, not assumed.
- **"64-bit FNV again?"** No. The target commitment and record chain use
  SHA-256. The Rust host emits the SHA-256 receipt head as
  `seal_record:"v1"`. The FNV `auditHashParts` value inside `auditLine` is a
  per-cert content hash, not the target or chain commitment.
- **"Which recent proof gaps does this bridge name?"** It names the model
  theorems landed for single-request NI
  (`Host.NonInterference.observe_noninterference`), replay isolation
  (`Host.ReplayIsolation.replay_isolation_trace`), and deployed-adapter O1/O2
  plus non-vacuity (`Host.Channel.deployed_O1`, `deployed_O2`,
  `deployed_nonvacuous`). The bridge tests binary correspondence on C; it does
  not turn those model theorems into a universal binary proof.

## TCB (named, not proven)

- The Lean compiler + native code generation (`libsealffi.so`) **and the
  emscripten codegen (`seal.wasm`)** — both trusted compiles; the bridge tests
  each on corpus C rather than trusting it blind.
- The FFI marshalling (`lean.rs`) and the wasm C glue (`wasm-spike/seal_wrapper.c`,
  `scripts/ffi_shim.c`); the FFI seam is already TCB in `RUST_BRIDGE.md`.
- `node:crypto` SHA-256 and the harness itself.
- **Corpus finiteness** — evidence covers the cases tried only: corpus C here,
  plus the generated corpus of the three-way property differential (large and
  re-drawn from a printed seed every run, but still finite). The bridge and
  the three-way harness narrow the T3 trusted-compile assumption to the
  security-relevant corpus; they do not discharge it universally.

## Scope

- **Native (done):** the Rust host / native `libsealffi.so` — the
  `seal-live-demo` / receipt binary. `node scripts/conformance_bridge.mjs`.
- **WASM (done at HEAD):** the emscripten `seal.wasm` — the in-browser
  seal-check shape. `node scripts/conformance_bridge.mjs --wasm`. See below.

## WASM shape (`seal.wasm`) — done at HEAD

The public artifact a reviewer runs in the browser is the emscripten `seal.wasm`,
not the native `.so`. The `--wasm` oracle drives that module headless in Node
(`seal_init`/`seal_decide`, thin C aliases over the SAME Lean `seal_host_init`/
`seal_host_step`) against the identical corpus C and the real-Lean MODEL oracle
above. It asserts the same two things — 15/15 byte-identical decision + audit,
and SHA-256 record chain-head equality WASM vs model. The wasm's record head on C
is byte-identical to the native `.so`'s and the deployed binary's.

**Provenance (the version-skew hazard, closed).** Earlier this doc flagged that
driving the *pinned* in-tree `seal.wasm` would report version skew as a codegen
bug. That hazard is closed by **rebuilding `seal.wasm` from the current Lean HEAD**
before the differential, and driving the fresh artifact:

- Source: `mcp-seal-dev` `1d35669` + seal-host
  `feat/principal-envelope-authority-binding` @ `11e9e8d` (the single-source
  policy codec + the V2.2 authority-bound principal envelope: domain tag
  `seal/v2.2/principal-envelope\0`, config authority, and length-prefixed key
  id, plus the existing Kernel PB)
- `seal.wasm` sha256: `c9f32b00543c2dd3b1493b3d89ded98abd4d50b8f2dd4e17c2d5256813388eda`
- emscripten `6.0.0` (vendored `wasm-spike/emsdk`), Lean `v4.28.0`
- Supersedes `3d70637f60f31c7c71dd6f65f3f2740d28db3b7620578b146a2ab4b1dec9ce01`
  (the V2.1 principal-envelope build; the hash changes because V2.2 changes
  the signed-message domain and layout), which superseded
  `0d3536e5624bccf2c81a94c247d8c8e7a15db4f9850d56b1d6ba59ed4b6ad130`
  (checked in at `cdb9447` claiming source `1d35669`, but a clean rebuild of
  `1d35669` yields `3d70637f` not `0d3536e5`; `3d70637f` is the authoritative
  rebuild-from-source pin, clean-runner CI reproducibility judged of record),
  which superseded `fab75d9def6f7741ca91db809f15233e4cb715f1f0139033f2e9f009461bd878`
  (the codec-refactor build; parsers carried unchanged, principal section the
  sole delta), which superseded
  `a37901811df4767fd08142243622b8372254e6ec5bd2d3aca18f0e61d0f109af`
  (the 7-kernel DX-surface build; decision semantics carried forward
  unchanged, parser equivalence PROVEN at the codec refactor), which superseded
  `ff1bfd68d7be51b6a395f94dfc46b2fb27ed11dc5833af6a84675f42f9730546`
  (the pathological-number fail-closed build, whose guard and decision
  semantics are carried forward unchanged), which superseded
  `d3067bc07e74977dedf6bb96d79a710c4b61143f6e8db151655bc88ece8b9d66`
  (correct on corpus C, but diverged from the native `.so` on a pathological
  numeric literal), which in turn superseded the fleet pin
  `df42cbada2297741bfeab99f222b96ac02e43a4ce8695b24922b425b8d66b1e8`.

For this neutral worktree rebuild, empty ignored object directories exposed two
workstation assumptions in the checked-in build scripts: canonical-checkout
absolute paths and a first closure scan whose empty glob needed shell nullglob.
Those settings were adjusted only for the build and restored before the repin
commit. The local hash identifies the artifact tested below; finite
differential agreement is evidence, not a universal compile-equivalence proof.
Clean-runner CI remains the reproducibility judge of record.

The verified artifact + full provenance + reproduce recipe are staged at
`wasm-spike/verified/{seal.wasm,seal.js,PROVENANCE.txt}`; the rebuild step that
was missing from the vendored pipeline (project ir → `build-core/*.o`, including
the new `Host/Step`) is `wasm-spike/build_core.sh`.

**Public deployment note.** For the conformance claim to cover the *deployed
public* checker, `seal-check` must repin its `wasm/seal.wasm` to this verified
build (sha256 `c9f32b00…`). That repin is a separate, audited step gated to the
public flip — it is **not** performed here; this repo stays the private source of
truth and the public mirror is untouched.
