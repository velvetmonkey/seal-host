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
  if emcc $FLAGS -c "$f" -o "$OUT/$b.o" >"$OUT/$b.log" 2>&1; then
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
