# WASM browser demo spike — resume state (2026-06-16)

## STATUS: WORKING ✅ — init-trap fixed; seal_decide runs end-to-end in node AND browser.
- All 7 kernels decide correctly; determinism tested (100 runs node / 50 browser, identical certs).
- Strict link: ZERO undefined symbols (no DCE-hides-undefined trickery).
- Conformance: WASM == native (libsealffi.so) == fixture, 25/25 steps identical (incl. cert hashes).

## Goal
Port verified Lean seal kernel to WebAssembly. seal_host_step deciding allow/block
entirely in-browser, no backend. ARIA "prove it in the browser" demo.

## ROOT CAUSE of the `RuntimeError: unreachable` trap (now fixed)
Two stacked bugs, the second masked by the first:

1. **Signature mismatch (the trap).** `scripts/ffi_shim.c` declared+called the Lean
   module initializer as `initialize_seal_x2dhost_Ffi(uint8_t, lean_object* w)` (2-arg,
   old Lean convention), but the v4.28.0-generated definition is `(uint8_t builtin)`
   (1-arg; returns the IO result directly, takes no world). On native x86-64 the extra
   arg sits in an ignored register (harmless — that's why libsealffi.so passed 10/10).
   On wasm, wasm-ld redirects the signature-mismatched call to a trap stub that executes
   `unreachable` → the exact symptom (traps inside seal_ffi_initialize, after runtime
   init, no Lean panic text). FIX: call with the real 1-arg signature (public
   seal_ffi_initialize keeps its (builtin, w) shape; w ignored, for caller ABI compat).

2. **Incomplete init closure (masked by #1).** The trap stub short-circuited
   `initialize_seal_x2dhost_Ffi` before its body ran, so the "stdlib subset chased to
   ZERO" was a fiction. Once #1 was fixed, `initialize_Init` (the umbrella) called
   ~80 submodule initializers absent from the subset → `Aborted(missing function:
   initialize_Init_*)`. FIX: `build_closure.sh` compiles the FULL transitive
   module-initializer closure from lean4-src/stage0/stdlib, stubbing only the two
   external proof-library umbrella initializers (Mathlib and Batteries) whose inits
   set up no runtime-read data. Plus: drop native-only Host_Main/Host/Host_Composition .o (pulled
   Std.Time); define 4 compiler-shared specializations (List.elem etc.) referenced by
   Kernels_Temporal + Consensus_Checker, by compiling their defining .c in isolation
   (build-spec/*.o, DCE keeps only the needed symbol).

## BUILD (reproduce from a clean tree)
    ./provision_toolchain.sh              # 0. verified emsdk + Lean source trees
    source ./emsdk/emsdk_env.sh
    ./build_runtime_wasm.sh               # 1. Lean runtime -> build-wasm-rt/libleanrt.a
    ./build_core.sh                       # 2. current host + mcp-seal Lean-C -> wasm objects
    ./build_base.sh                       # 3. runtime package/stdlib/specialization objects
    ./build_closure.sh                    # 4. module-init closure -> build-stdlib-closure/*.o + stubs
    ./build_wasm.sh                       # 5. recompile wrapper+shim, link -> build-core/seal.{js,wasm}
    ./build_wasm.sh strict                #    (optional) prove ZERO undefined symbols
    ./build_native_conformance.sh         # 6. native comparator (needs ../.lake/build/lib/libsealffi.so)
    node test_kernels.mjs                 # 7 kernels + determinism (100 runs)
    node conformance.mjs                  # wasm == native == fixture (needs build-core/conformance_native)

No ignored object directory is assumed to survive from an earlier build.
`build_core.sh` and `build_base.sh` recreate every project/package/base object;
`build_closure.sh` derives the remaining initializer closure. Native conformance
CLI is built with the checked-in `build_native_conformance.sh`, including the
required Lean and host-library runtime search paths.

`build_closure.sh` also normalizes the two obsolete erased-world declarations
in stage-0 `Init.System.IO.c` (`lean_io_create_tempfile` and
`lean_io_create_tempdir`) to the current runtime ABI. It checks the expected
generated-source shape before patching and fails if that shape changes; this
keeps strict linking free of function-signature warnings. Because browser
mediation does not provide Lean's native libuv filesystem runtime,
`seal_wrapper.c` supplies ABI-correct wasm-only trap implementations. An
unexpected future call therefore stops the gate instead of creating an
untracked filesystem dependency.

## Exports (build-core/seal.js, MODULARIZE, EXPORT_NAME=SealModule)
- `seal_init(envelopeJson, pubkey) -> summaryJson` — load signed trusted-config; call once.
- `seal_decide(stepInputJson) -> {route, response?, audit?}` — one mediation step.
  step input: `{line, now, approvals:[{target,issuedAt?}], votes, grants, forecasts}`.
  Config envelope is Ed25519-signed over the exact compact payload bytes; the
  matching public key is supplied as the `seal_init`/`--pubkey` trust root.

## Key files
- scripts/ffi_shim.c          — the 1-arg init fix (shared with native build).
- seal_wrapper.c              — boots runtime; exports seal_init + seal_decide.
- build_closure.sh            — iterative module-init closure builder (batched emnm).
- build_wasm.sh [strict]      — recompile glue + link.
- seal_scenarios.mjs          — shared config + 7-kernel scenarios (mirrors test_host.py).
- test_kernels.mjs            — 7-kernel + determinism harness.
- conformance.mjs / conformance_native.c — wasm vs native vs fixture gate.
- conformance_fixture.json    — captured native verdicts (source of truth).
