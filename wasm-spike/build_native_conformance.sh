#!/usr/bin/env bash
# Build the native side of the native/WASM/fixture conformance gate.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HOST_ROOT=$(cd "$ROOT/.." && pwd)
LEAN_PREFIX=$(lean --print-prefix)
OUT="$ROOT/build-core/conformance_native"

if [[ ! -f "$HOST_ROOT/.lake/build/lib/libsealffi.so" ]]; then
  echo "missing $HOST_ROOT/.lake/build/lib/libsealffi.so" >&2
  echo "build the native FFI library first: ../scripts/build_ffi_so.sh" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
cc -O2 -Wall -Wextra "$ROOT/conformance_native.c" \
  -L "$HOST_ROOT/.lake/build/lib" -lsealffi \
  -L "$LEAN_PREFIX/lib/lean" -lleanshared \
  -Wl,-rpath,"$HOST_ROOT/.lake/build/lib" \
  -Wl,-rpath,"$LEAN_PREFIX/lib/lean" \
  -o "$OUT"

echo "built $OUT"
