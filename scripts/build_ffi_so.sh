#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Link the self-contained seal-host FFI shared library.
#
# Strategy: every Lake package's compiled module objects go into a thin
# archive; the linker pulls exactly the objects the Ffi initializer chain
# references. Lean runtime + Init/Std/Lean symbols stay undefined and
# resolve against libleanshared.so at load (PIC + dynamic TLS — the static
# libleanrt.a cannot enter a shared object).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/.lake/build/lib/libsealffi.so"
TMP="$ROOT/.lake/build/ffi-archives"
LEAN_PREFIX="$(lean --print-prefix)"
CRYPTO_ROOT="$ROOT/.lake/packages/mcp-seal"
CRYPTO_OBJ="$CRYPTO_ROOT/c/build/libsealcrypto.o"
CRYPTO_TWEET_PIC="$TMP/tweetnacl_pic.o"
CRYPTO_ED25519_PIC="$TMP/seal_ed25519_pic.o"
mkdir -p "$TMP"

if [ ! -f "$CRYPTO_OBJ" ]; then
  (cd "$CRYPTO_ROOT" && bash c/build.sh)
fi

# The default `lake build Ffi` refreshes Lean artifacts (`.olean`, `.c`) but
# not always the exported native objects this linker consumes. Build the
# module object facet explicitly so edited Lean code cannot leave a stale
# `.c.o.export` in the shared library.
(cd "$ROOT" && lake build +Ffi:o)

# Project objects: the Ffi module + Host/Kernels modules. Test modules and
# Host/Main are excluded — they carry their own `main` symbols.
mapfile -t PROJ_OBJS < <(find "$ROOT/.lake/build/ir" -name '*.c.o.export' \
  ! -path '*/Test/*' ! -name 'Test.c.o.export' ! -path '*/Host/Main.c.o.export' | sort)
[ "${#PROJ_OBJS[@]}" -gt 0 ] || { echo "no project objects; run lake build Ffi first" >&2; exit 1; }

ARCHIVES=()
for pkgdir in "$ROOT"/.lake/packages/*/; do
  pkg="$(basename "$pkgdir")"
  irdir="$pkgdir/.lake/build/ir"
  [ -d "$irdir" ] || continue
  objs="$(find "$irdir" -name '*.c.o.export' | sort)"
  [ -n "$objs" ] || continue
  archive="$TMP/lib_${pkg}.a"
  if [ ! -f "$archive" ] || [ "$(find "$irdir" -name '*.c.o.export' -newer "$archive" | head -1)" ]; then
    rm -f "$archive"
    # Thin archive built by chunked quick-append (q), then indexed (s) once
    # at the end — replace-mode chunking silently truncated earlier.
    printf '%s\0' $objs | xargs -0 ar qT "$archive"
    ar sT "$archive"
  fi
  ARCHIVES+=("$archive")
done

cc -O2 -fPIC -I "$LEAN_PREFIX/include" -c "$ROOT/scripts/ffi_shim.c" -o "$TMP/ffi_shim.o"
CRYPTO_CFLAGS="-O2 -fPIC -fwrapv -fno-strict-aliasing"
cc $CRYPTO_CFLAGS -c "$CRYPTO_ROOT/c/tweetnacl.c" -o "$CRYPTO_TWEET_PIC"
cc $CRYPTO_CFLAGS -I "$LEAN_PREFIX/include" -I "$CRYPTO_ROOT/c" \
  -c "$CRYPTO_ROOT/c/seal_ed25519.c" -o "$CRYPTO_ED25519_PIC"

cc -shared -o "$OUT" \
  "$TMP/ffi_shim.o" \
  "$CRYPTO_TWEET_PIC" \
  "$CRYPTO_ED25519_PIC" \
  "${PROJ_OBJS[@]}" \
  -Wl,--start-group "${ARCHIVES[@]}" -Wl,--end-group \
  -L "$LEAN_PREFIX/lib/lean" -lleanshared -lLake_shared \
  -Wl,-rpath,"$LEAN_PREFIX/lib/lean"

echo "built $OUT"
nm -D "$OUT" | grep -E ' T seal_host_(init|step|classify)$' || {
  echo "FATAL: exports missing" >&2; exit 1; }
