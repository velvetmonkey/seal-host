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
   model's log.

Chain agreement reduces to payload agreement, which reduces to (1) + audit
serialization — so the whole thing rests on byte-identical audit emission,
which the harness checks directly.

## The three oracles

| Oracle | What it is | Backend |
|---|---|---|
| **MODEL** | the REAL Lean `stepImpl` (`scripts/model_oracle.lean`, via `lake env lean`) | Lean **interpreter** — never a reimplementation |
| **NATIVE** | `kernel_oracle` calling `seal_host_step` | the compiled **`libsealffi.so`** the deployed host links |
| **DEPLOYED** | the actual `seal-host-rs` binary over stdio | the shipped artifact, end-to-end |

The MODEL side being the **interpreter** is the point: interpreter vs native
codegen is exactly the gap a codegen bug would open. The oracle evaluates the
same Lean source the theorems govern, through Lean's own evaluator, so a
divergence is a codegen defect, not a spec question.

## Corpus C (finite, named — not exhaustive)

- 11 destructive-delete **disguises** (drop / delete / truncate × casing /
  leading-trailing whitespace / tab) — all must `block`.
- 3 **passthrough** lines (initialize / tools/list / notification).
- 1 **approved forward** (the canonical destructive call with a fresh live
  approval) — exercises the `forward` route and the allow path.

Both routes and both record outcomes (deny audit, allow audit) are covered.

## Run it

```sh
node scripts/conformance_bridge.mjs        # exit non-zero on any divergence
```

Green transcript: `docs/conformance-ci-transcript.txt`. It asserts, in order:
harness liveness (below), 15/15 byte agreement + route agreement, native/model
chain-head equality, and deployed-binary/model chain-head equality.

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
- **"64-bit FNV again?"** No. The record chain here uses SHA-256 (the L1
  deploy decision, exit a). The FNV `stableHashParts` inside `auditLine` is a
  per-cert content hash, not the chain commitment.

## TCB (named, not proven)

- The Lean compiler + native code generation (`libsealffi.so`); emscripten for
  the WASM shape (out of scope here — stretch).
- The FFI marshalling (`lean.rs`), already TCB in `RUST_BRIDGE.md`.
- `node:crypto` SHA-256 and the harness itself.
- **Corpus finiteness** — evidence covers C only. The bridge narrows the T3
  trusted-compile assumption to the security-relevant corpus; it does not
  discharge it universally.

## Scope

- **Must-ship (done):** the Rust host / native `libsealffi.so` — the
  `seal-live-demo` / receipt binary.
- **Stretch:** the WASM (`seal-check/wasm/seal.wasm`, emscripten) — same corpus
  through the browser-deployment shape. Same method; a WASM oracle in place of
  `kernel_oracle`.
