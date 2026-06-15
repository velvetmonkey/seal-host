#!/usr/bin/env bash
set -uo pipefail
cd /home/monkey/src/seal-host/wasm-spike
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
echo "RUNTIME_BUILD_DONE pass=$pass fail=$fail" | tee "$OUT/SUMMARY.txt"
