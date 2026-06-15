# WASM browser demo spike — resume state (2026-06-15 ~23:10)

## Goal
Port verified Lean seal kernel to WebAssembly. seal_host_step deciding allow/block
entirely in-browser, no backend. ARIA "prove it in the browser" demo.

## DONE (hard crux cracked)
- emsdk installed + active at ./emsdk (source ./emsdk/emsdk_env.sh).
- lean4 v4.28.0 source cloned at ./lean4-src (HEAD 7e01a1b, tag v4.28.0).
- GMP wall DODGED: build with non-GMP bignum fallback (no -D LEAN_USE_GMP).
- Generated headers hand-made in ./gen: include/lean/config.h, include/lean/version.h, githash.h.
- Lean RUNTIME compiles to wasm: 24/25 runtime .cpp -> build-wasm-rt/libleanrt.a (592KB).
  - 'io' excluded (needs libuv uv.h). 'interrupt' patched: uncaught_exception()->uncaught_exceptions().
- All 21 of OUR generated C (Ffi + Host/* + Kernels/*) compile to wasm -> build-core/*.o.
  - Compile flags (C):  -O2 -I lean4-src/src/include -I gen/include -I gen -D LEAN_EMSCRIPTEN=1
  - Runtime flags (C++): add -I lean4-src/src -std=c++20 -DLEAN_MULTI_THREAD=0 (NO -fno-exceptions)

## REMAINING (bounded stdlib wiring, will cascade)
Link of build-core/*.o + libleanrt.a leaves 7 undefined symbols:
  - lean_st_ref_get            -> in runtime/io.cpp (excluded). Stub uv.h to compile io.cpp, or extract.
  - l_List_appendTR___redArg   -> stage0/stdlib/Init/Data/List/Basic.c
  - l_List_isEmpty___redArg    -> stage0/stdlib/Init/Data/List/Basic.c
  - l_Lean_Json_parse/compress/mkObj/getObjVal_x3f/getStr_x3f/getNat_x3f
                               -> stage0/stdlib/Lean/Data/Json/{Parser,Printer,Stream,Basic}.c
NOTE: duplicate 'main' in Ffi.o + Host_Main.o. Use -Wl,--allow-multiple-definition (link is --no-entry).

## NEXT STEPS (Wednesday deep session)
1. Stub uv.h (or compile io.cpp minimal) -> get lean_st_ref_get.
2. Compile Json subset + Init/Data/List/Basic.c to wasm; chase transitive cascade to closure.
3. Link: emcc -O2 build-core/*.o <stdlib objs> libleanrt.a -o seal.js \
     -s EXPORTED_FUNCTIONS='["_seal_host_step"]' -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' \
     -s MODULARIZE=1 -Wl,--allow-multiple-definition
4. C wrapper: call lean_initialize_runtime_module + initialize_Ffi(...) once, expose decide(json)->json.
5. Tiny index.html + JS loader. Real verified verdict in the page.
