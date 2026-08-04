#!/usr/bin/env bash
# Build seal.wasm / seal.js from the pre-built object trees.
# Recompiles only the C wrapper + FFI shim (the hand-written glue); all Lean-
# generated objects are reused from build-{core,seal,pkg,stdlib}/ and libleanrt.a.
#
# Usage: ./build_wasm.sh [strict]
#   strict -> link with -sERROR_ON_UNDEFINED_SYMBOLS=1 (proves full symbol closure)
set -euo pipefail
# Deterministic link: the object list comes from shell globs, glob order is
# LC_COLLATE-dependent, and object order assigns wasm function indices — an
# en_US.UTF-8 host and a C-locale clean runner produced different (equally
# valid) bytes from identical objects. Pin the C locale so every environment
# links the clean runner's bytes.
export LC_ALL=C
cd "$(dirname "$0")"
source ./emsdk/emsdk_env.sh >/dev/null 2>&1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CFLAGS="-O2 -I lean4-src/src/include -I gen/include -I gen -D LEAN_EMSCRIPTEN=1"
MCP_TYPE="$(jq -r '.packages[] | select(.name | contains("mcp-seal")) | .type' "$ROOT/lake-manifest.json")"
if [ "$MCP_TYPE" = "path" ]; then
  MCP_DIR="$(jq -r '.packages[] | select(.name | contains("mcp-seal")) | .dir' "$ROOT/lake-manifest.json")"
  SEAL_ROOT="$(realpath "$ROOT/$MCP_DIR")"
else
  SEAL_ROOT="$ROOT/.lake/packages/mcp-seal"
fi

echo "[build_wasm] recompiling wrapper + shim"
emcc $CFLAGS -c seal_wrapper.c          -o build-core/seal_wrapper.o || exit 1
emcc $CFLAGS -c "$ROOT/scripts/ffi_shim.c" -o build-core/ffi_shim.o  || exit 1
emcc $CFLAGS -I "$SEAL_ROOT/c" \
  -c "$SEAL_ROOT/c/tweetnacl.c" \
  -o build-core/tweetnacl.o || exit 1
emcc $CFLAGS -I "$SEAL_ROOT/c" \
  -c "$SEAL_ROOT/c/seal_ed25519.c" \
  -o build-core/seal_ed25519.o || exit 1

# Undefined-symbol policy: lax by default (DCE drops unreachable refs), strict on demand.
UNDEF="-sERROR_ON_UNDEFINED_SYMBOLS=0"
[ "${1:-}" = "strict" ] && UNDEF="-sERROR_ON_UNDEFINED_SYMBOLS=1"

# Init_Meta.o is required at runtime (initialize_Init calls initialize_Init_Meta);
# its data ref l_Lean_Parser_Tactic_optConfig now resolves from the closure's
# Init_Tactics.o, so it links cleanly.
STDLIB_O=$(ls build-stdlib/*.o)
# build-stdlib-closure/*.o = transitive module-initializer closure (build_closure.sh);
# build-core/stubs.o = no-op inits for external proof libs (mathlib/aesop/batteries).
CLOSURE_O=$(ls build-stdlib-closure/*.o 2>/dev/null)
# build-spec/*.o: external modules compiled in isolation purely to DEFINE the
# compiler-shared specializations (List.elem/Option.beq/List.repr'/Format.joinSep)
# that Kernels_Temporal + Consensus_Checker reference; DCE keeps only those.
SPEC_O=$(ls build-spec/*.o 2>/dev/null)

# The artifact is linked UNPUBLISHED (build-core/pending/) and only moved to
# its real path after the link-set audit below positively passes. Any prior
# artifact is removed first, so a failed gate leaves nothing at the published
# path that could be mistaken for a vetted build. The link must come before
# the audit: emscripten builds the sysroot archives (libc.a, libc++, ...)
# lazily at first link, and the audit resolves libc references against those
# same archives — pre-link in a cold tree every libc call is unresolved.
PENDING=build-core/pending
rm -rf "$PENDING" build-core/seal.js build-core/seal.wasm
mkdir -p "$PENDING"

echo "[build_wasm] linking seal.js / seal.wasm ($UNDEF) into $PENDING (unpublished)"
emcc -O2 \
  build-core/*.o build-seal/*.o build-pkg/*.o $STDLIB_O $CLOSURE_O $SPEC_O \
  build-wasm-rt/libleanrt.a \
  -o "$PENDING/seal.js" \
  -s EXPORTED_FUNCTIONS='["_seal_init","_seal_decide","_seal_mcp_version_gate","_malloc","_free"]' \
  -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s MODULARIZE=1 -s EXPORT_NAME=SealModule \
  $UNDEF \
  -Wl,--allow-multiple-definition \
  || { echo "[build_wasm] LINK FAILED"; rm -rf "$PENDING"; exit 1; }

# --- Link-set audit gate, fail-closed --------------------------------------
# The stub warrant is proven per-link, never assumed per-name: the audit must
# POSITIVELY pass over exactly the objects linked above. A nonzero exit
# (offenders, unparseable object, unmodelled relocation, missing tool) refuses
# to publish — and so does exit 0 without the printed PASS verdict, so a
# silent or truncated audit can never read as success.
AUDIT_LOG=build-core/link_set_audit.log
rm -f "$AUDIT_LOG"
echo "[build_wasm] link-set audit (gate: no PASS verdict, no artifact)"
set +e
./audit_link_set.sh > "$AUDIT_LOG" 2>&1
audit_rc=$?
set -e
if [ "$audit_rc" -ne 0 ]; then
  tail -n 40 "$AUDIT_LOG" >&2
  echo "[build_wasm] LINK-SET AUDIT FAILED rc=$audit_rc; refusing to emit" >&2
  rm -rf "$PENDING"
  exit 1
fi
if ! grep -q '^\[link-set-audit\] PASS fail-closed initializer-state rule$' "$AUDIT_LOG"; then
  tail -n 40 "$AUDIT_LOG" >&2
  echo "[build_wasm] audit exited 0 but printed no PASS verdict; refusing to emit" >&2
  rm -rf "$PENDING"
  exit 1
fi
echo "[build_wasm] link-set audit PASS ($AUDIT_LOG); publishing artifact"
mv "$PENDING/seal.js" "$PENDING/seal.wasm" build-core/
rmdir "$PENDING"

echo "[build_wasm] done: $(ls -la build-core/seal.wasm | awk '{print $5}') bytes"
