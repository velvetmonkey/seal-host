#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./emsdk/emsdk_env.sh >/dev/null 2>&1
SRC=lean4-src/src
OUT=build-wasm-rt
mkdir -p "$OUT"
FLAGS="-O2 -std=c++20 -I $SRC -I $SRC/include -I gen/include -I gen -D LEAN_EMSCRIPTEN=1 -DLEAN_MULTI_THREAD=0"
pass=0; fail=0
: > "$OUT/PASS.txt"; : > "$OUT/FAIL.txt"
for f in $SRC/runtime/*.cpp; do
  b=$(basename "$f" .cpp)
  compile_src="$f"
  if [ "$b" = "object" ]; then
    # Lean 4.28's String.data helper seeds a List Char with
    # lean_box_uint32(0). That is List.nil by accident on 64-bit native, but
    # a boxed UInt32 object on 32-bit wasm. Normalize only the guarded source
    # shape so the generated list has the real scalar List.nil terminator.
    needle='    obj_res  r = lean_box_uint32(0);'
    [ "$(grep -cF "$needle" "$f")" -eq 1 ] || {
      echo "RUNTIME_NORMALIZATION_FAILED unexpected string_to_list_core source" >&2
      exit 1
    }
    compile_src="$OUT/object.wasm.cpp"
    sed 's/    obj_res  r = lean_box_uint32(0);/    obj_res r = lean_box(0);/' \
      "$f" > "$compile_src"
    ! grep -qF "$needle" "$compile_src" || {
      echo "RUNTIME_NORMALIZATION_FAILED replacement did not apply" >&2
      exit 1
    }
  fi
  if emcc $FLAGS -c "$compile_src" -o "$OUT/$b.o" >"$OUT/$b.log" 2>&1; then
    echo "$b" >> "$OUT/PASS.txt"; pass=$((pass+1))
  else
    echo "$b" >> "$OUT/FAIL.txt"; fail=$((fail+1))
  fi
done
if [ "$fail" -ne 0 ]; then
  echo "RUNTIME_BUILD_FAILED pass=$pass fail=$fail" | tee "$OUT/SUMMARY.txt"
  exit 1
fi
emar rcs "$OUT/libleanrt.a" "$OUT"/*.o
echo "RUNTIME_BUILD_DONE pass=$pass fail=$fail" | tee "$OUT/SUMMARY.txt"
