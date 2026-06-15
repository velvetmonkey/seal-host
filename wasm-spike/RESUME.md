# WASM browser demo spike — resume state (2026-06-15 ~23:45)

## Goal
Port verified Lean seal kernel to WebAssembly. seal_host_step deciding allow/block
entirely in-browser, no backend. ARIA "prove it in the browser" demo.

## DONE — full symbol closure + runnable wasm (the hard 90%)
- emsdk active at ./emsdk (source ./emsdk/emsdk_env.sh). lean4 v4.28.0 at ./lean4-src.
- GMP dodged (non-GMP bignum fallback, no -D LEAN_USE_GMP).
- Generated headers in ./gen: include/lean/{config,version}.h, githash.h, uv.h (stub).
- Lean RUNTIME -> wasm: 25/25 .cpp incl io.cpp -> build-wasm-rt/libleanrt.a.
  - io.cpp compiles against gen/uv.h (57 UV_E* error consts + 8 fn decls; the
    temp-file fns dead-strip, never reached by decide path).
  - interrupt.cpp patched: uncaught_exception() -> uncaught_exceptions().
- All 23 generated seal-host C modules (Ffi + Host/* + Kernels/*) -> build-core/*.o.
- Dep packages compiled: mcp-seal (22 obj, build-seal/), consensus-lean +
  temporal-logic-lean (14 obj, build-pkg/).
- Lean stdlib subset (29 obj, build-stdlib/): Init umbrella + Prelude + Json +
  Parsec + String/List/Int/Format/Repr/Meta etc. Whole closure chased to ZERO.
- C wrapper seal_wrapper.c: boots runtime + exposes seal_decide(json)->json.
  Reuses scripts/ffi_shim.c (seal_ffi_initialize / seal_lean_*).
- LINKS CLEAN at -O2, ZERO undefined symbols. build-core/seal.wasm (~834KB) +
  seal.js (MODULARIZE, EXPORT_NAME=SealModule, exports _seal_decide).
- Module LOADS under node, seal_decide executes, runtime_module init OK.

## BLOCKER — traps in the module-init chain (the last 10%)
- node run_demo2.mjs: breadcrumbs show lean_initialize_runtime_module() returns
  fine, then `RuntimeError: unreachable` INSIDE seal_ffi_initialize(...) — i.e.
  somewhere in the initialize_* module-init chain. NO Lean panic text (not a
  lean_internal_panic; a raw wasm `unreachable`).
- Ruled out: stack overflow (8MB stack no change); builtin flag (0 and 1 both trap).
- Likely: one module initializer executes an unreachable arm, OR a non-GMP-path
  Nat/Int literal build, OR a decide/native_decide-baked constant in a Theorems
  module mismatching under cross-compile.

## DEBUG PATH (Wednesday)
The clean -O2 link only works because DCE strips unreachable refs (lean_initialize,
l_Lean_Parser_Tactic_*, repr helpers from Init_Meta.o + Ffi.o main). ANY diagnostic
build (-g2 / ASSERTIONS / -O1) weakens DCE and re-exposes those as unlinkable.
To get a NAMED stack trace:
  1. Drop build-stdlib/Init_Meta.o (only added for l_Nat_reprFast, also in
     Init_Data_Repr.o) — kills the l_Lean_Parser_Tactic_* refs.
  2. Provide/stub lean_initialize (main-only) + the 1 repr helper from Kernels_Budget.
  3. Then link -O2 -g2 -s ASSERTIONS=1 -s ERROR_ON_UNDEFINED_SYMBOLS=0 -> named trap.
  4. The named initialize_<Module> in the trace IS the culprit; inspect its _init.
Alt: bisect — instrument generated Ffi.c initialize_seal_x2dhost_Ffi to printf
before each initialize_<import>, find which one traps.

## BUILD RECIPE (reproduce from a clean tree)
source ./emsdk/emsdk_env.sh
# 1. runtime -> libleanrt.a:  build_runtime_wasm.sh (+ io.cpp w/ gen/uv.h)
# 2. seal-host C:   emcc -O2 -I lean4-src/src/include -I gen/include -I gen -D LEAN_EMSCRIPTEN=1 -c .lake/build/ir/**/*.c
# 3. packages:      same flags over .lake/packages/{mcp-seal,consensus-lean,temporal-logic-lean}/.lake/build/ir/**/*.c
# 4. stdlib subset: same flags, modules under build-stdlib/
# 5. wrapper+shim:  emcc ... -c seal_wrapper.c scripts/ffi_shim.c
# 6. link:          emcc -O2 build-core/*.o build-seal/*.o build-stdlib/*.o build-pkg/*.o libleanrt.a \
#                     -o seal.js -s EXPORTED_FUNCTIONS='["_seal_decide","_malloc","_free"]' \
#                     -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' -s ALLOW_MEMORY_GROWTH=1 \
#                     -s MODULARIZE=1 -s EXPORT_NAME=SealModule -Wl,--allow-multiple-definition
# test: node run_demo2.mjs
