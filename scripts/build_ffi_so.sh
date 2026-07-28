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
# Build command resolution: explicit LEANBUILD wins, then a `leanbuild`
# wrapper on PATH (the dev box installs one that serializes builds and caps
# memory — box protections, not build semantics), else bare `lake` (CI
# runners are ephemeral and single-build, so the wrapper adds nothing there).
# The wrapper forwards its arguments to lake, so both spellings take the
# same argument list.
if [ -z "${LEANBUILD:-}" ]; then
  if command -v leanbuild >/dev/null 2>&1; then
    LEANBUILD=leanbuild
  else
    LEANBUILD=lake
  fi
fi
LEAN_PREFIX="$(lean --print-prefix)"
MCP_TYPE="$(jq -r '.packages[] | select(.name | contains("mcp-seal")) | .type' "$ROOT/lake-manifest.json")"
if [ "$MCP_TYPE" = "path" ]; then
  MCP_DIR="$(jq -r '.packages[] | select(.name | contains("mcp-seal")) | .dir' "$ROOT/lake-manifest.json")"
  CRYPTO_ROOT="$(realpath "$ROOT/$MCP_DIR")"
else
  CRYPTO_ROOT="$ROOT/.lake/packages/mcp-seal"
fi
CRYPTO_OBJ="$CRYPTO_ROOT/c/build/libsealcrypto.o"
CRYPTO_TWEET_PIC="$TMP/tweetnacl_pic.o"
CRYPTO_ED25519_PIC="$TMP/seal_ed25519_pic.o"
mkdir -p "$TMP"

if [ ! -f "$CRYPTO_OBJ" ]; then
  (cd "$CRYPTO_ROOT" && bash c/build.sh)
fi

# Build only the runtime import closure. Dependency module object facets are
# named explicitly because `+Ffi:o` otherwise materializes their C/olean inputs
# but can leave old `.c.o.export` files from a previous dependency revision.
LAKE_FLAGS=()
if [ -n "${SEAL_LAKE_PACKAGES:-}" ]; then
  LAKE_FLAGS+=("--packages=$SEAL_LAKE_PACKAGES")
fi
if [ "${SEAL_LAKE_OLD:-0}" = "1" ]; then
  # Compatibility-probe escape hatch for a memory-constrained developer box.
  # This is never the release build: --old deliberately ignores transitive
  # invalidation. A promoted immutable dependency must receive a clean build
  # on the release runner before its artifact hashes are published.
  LAKE_FLAGS+=(--old)
fi
MCP_MODULES=(
  SealCore SealCore.Automaton SealCore.Event SealCore.Safety SealCore.Sha256
  Seal.Block Seal.Channel Seal.Classify Seal.Hash Seal.JsonUtil Seal.Policy
  Seal.PolicyBundle
  SealV2.Canonical SealV2.Crypto SealV2.Decide SealV2.Escape SealV2.Parser
  SealV2.Serialization SealV2.Validation
)
PROJECT_MODULES=(
  Ffi
  Host/Action Host/Audit Host/Canonical Host/Config Host/Evidence Host/Kernel Host/Registry Host/Sha256 Host/Step
  Host/Principal Host/Provenance
  # Added 2026-07-25. `Host/UnicodeKeys.lean` landed on 2026-07-25 and was not
  # added here, so every relink of the `.so` failed with `undefined symbol:
  # lp_seal_x2dhost_Host_UnicodeKeys_wireKeysSafe`. This list is MANUAL (see the
  # comment above): adding a Lean module under Host/ that Ffi's import closure
  # reaches REQUIRES adding it here, or the shared object cannot be rebuilt.
  Host/UnicodeKeys
  Kernels
  Kernels/Budget Kernels/BudgetCore Kernels/Calibration Kernels/Consensus
  Kernels/Convergence Kernels/Linear Kernels/LinearCore Kernels/PrincipalBudget
  Kernels/Safety Kernels/Temporal
)
MCP_TARGETS=()
for module in "${MCP_MODULES[@]}"; do
  MCP_TARGETS+=("@mcp-seal/+${module}:o")
done
PROJECT_TARGETS=()
for module in "${PROJECT_MODULES[@]}"; do
  PROJECT_TARGETS+=("+${module//\//.}:o")
done
# The seal-host exe link materializes the dependency packages' .c.o.export
# objects (its import closure reaches Kernels and through them every dep
# package's runtime modules). The per-module lists above cannot: they cover
# only project and pinned policy-core modules, and a fresh runner has NO
# dependency IR at all — exactly the state in which this script used to
# link a silently broken .so (dependency initializers unresolved,
# cc -shared tolerates it). If the Ffi surface ever imports a dep module
# outside the seal-host closure, the load-time resolution gate below names
# the missing symbol — extend this build line then. (`ffi_shared` cannot be
# the vehicle: its exe-shaped -shared link pulls the static libleanrt.a,
# which can never enter a shared object, and the target has never built.)
(cd "$ROOT" && "$LEANBUILD" "${LAKE_FLAGS[@]}" build "${PROJECT_TARGETS[@]}" "${MCP_TARGETS[@]}" seal-host)

# Project objects: the exact Ffi runtime closure, excluding theorem/off-path
# modules even if stale objects for them exist in the build directory.
PROJ_OBJS=()
for module in "${PROJECT_MODULES[@]}"; do
  object="$ROOT/.lake/build/ir/$module.c.o.export"
  [ -f "$object" ] || { echo "missing runtime object: $object" >&2; exit 1; }
  PROJ_OBJS+=("$object")
done

ARCHIVES=()
# Packages legitimately outside FfiMain's runtime import closure: no module
# of theirs is transitively imported, so no initializer is needed and the
# ffi_shared build leaves them with no objects. Anything else with no IR is
# a hard error — a silently skipped package is precisely how CI shipped a
# libsealffi.so with unresolved dependency initializers while this script
# printed "built" and exited 0.
# PROOF-ONLY dependencies. Each supplies mathematics that proof modules cite,
# not code any kernel runs, so the exe build never materializes their C objects
# and they contribute none BY DESIGN. Verified against PROJECT_MODULES above —
# the declared runtime closure — rather than assumed:
#
#   calibration-lean  Calibration.* is imported ONLY by Test/Axioms.lean.
#                     Kernels/Calibration.lean pulls just Seal.Hash and
#                     Host.Kernel. CondHoeffding.lean is 2 theorems, 0 defs.
#   crdt-lean         Crdt.* is imported ONLY by Host/AuthorityFrontierBridge.lean,
#                     Kernels/ConvergencePotential.lean and Test/Axioms.lean —
#                     none of which appear in PROJECT_MODULES. (Note the runtime
#                     kernel is Kernels/Convergence; ConvergencePotential is its
#                     proof.)
#
# For contrast, consensus-lean and temporal-logic-lean ARE runtime: the closure
# imports Consensus and Temporal directly, so they must contribute objects and a
# FATAL for either is a real defect, not a missing exemption.
#
# Before adding to this list: grep the package's root module across the
# PROJECT_MODULES files ONLY. Grepping all of Host/ will mislead you — most of
# Host/ is proofs the runtime never loads.
CLOSURE_EXEMPT=(Cli calibration-lean crdt-lean)

archive_package_ir() {
  local pkgdir="$1" force="${2:-0}"
  pkg="$(basename "$pkgdir")"
  irdir="$pkgdir/.lake/build/ir"
  objs=""
  if [ -d "$irdir" ]; then
    objs="$(find "$irdir" -name '*.c.o.export' | sort)"
  fi
  if [ -z "$objs" ]; then
    for exempt in "${CLOSURE_EXEMPT[@]}"; do
      [ "$pkg" = "$exempt" ] && return 0
    done
    echo "FATAL: dependency package '$pkg' contributed no compiled module objects" >&2
    echo "  expected: $irdir/**/*.c.o.export" >&2
    echo "  The seal-host exe build materializes the runtime closure. If this" >&2
    echo "  package is genuinely outside the Ffi import closure, add it to" >&2
    echo "  CLOSURE_EXEMPT above. Otherwise the link would silently drop its" >&2
    echo "  module initializers and produce a broken libsealffi.so." >&2
    exit 1
  fi
  archive="$TMP/lib_${pkg}.a"
  if [ "$force" = "1" ] || [ ! -f "$archive" ] || [ "$(find "$irdir" -name '*.c.o.export' -newer "$archive" | head -1)" ]; then
    rm -f "$archive"
    # Thin archive built by chunked quick-append (q), then indexed (s) once
    # at the end — replace-mode chunking silently truncated earlier.
    printf '%s\0' $objs | xargs -0 ar qT "$archive"
    ar sT "$archive"
  fi
  ARCHIVES+=("$archive")
}

for pkgdir in "$ROOT"/.lake/packages/*/; do
  if [ "$MCP_TYPE" = "path" ] && [ "$(basename "$pkgdir")" = "mcp-seal" ]; then
    continue
  fi
  if [ "$(basename "$pkgdir")" = "mcp-seal" ]; then
    # Git preserves checkout mtimes poorly enough that a newly pinned commit
    # can look older than this thin archive. Never link a stale policy core.
    archive_package_ir "$pkgdir" 1
  else
    archive_package_ir "$pkgdir"
  fi
done
if [ "$MCP_TYPE" = "path" ]; then
  archive_package_ir "$CRYPTO_ROOT" 1
fi

# UnicodeBasic ships a HAND-WRITTEN C library (`libunicodeclib.a`), not Lean-IR
# output, so `archive_package_ir` above cannot see it: that function collects
# `.c.o.export` objects, and these are compiled from real `.c` sources in the
# package's own build. `Host/UnicodeKeys` reaches it, so without this the link
# fails with `undefined symbol: unicode_case_lookup` / `unicode_prop_lookup`.
# Added 2026-07-25 alongside Host/UnicodeKeys in PROJECT_MODULES.
UNICODE_CLIB="$ROOT/.lake/packages/UnicodeBasic/.lake/build/lib/libunicodeclib.a"
if [ -f "$UNICODE_CLIB" ]; then
  ARCHIVES+=("$UNICODE_CLIB")
else
  echo "FATAL: UnicodeBasic native archive missing: $UNICODE_CLIB" >&2
  echo "  Host/UnicodeKeys needs it. Run 'lake build' first." >&2
  exit 1
fi

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

nm -D "$OUT" | grep -E ' T seal_host_(init|step|classify)$' || {
  echo "FATAL: exports missing" >&2; exit 1; }

# Load-time resolution proof. `ldd -r` performs full relocation processing
# against the DT_NEEDED set (libleanshared / libLake_shared / libc): the
# Lean runtime symbols that are LEGITIMATELY undefined at static link
# (PIC + dynamic TLS, resolved at load) resolve here, so this does not
# false-fail correct artifacts the way a blanket "no undefined symbols"
# nm check would. Anything still unresolved means a module object was
# dropped from the link — refuse to call that "built".
UNRESOLVED="$(ldd -r "$OUT" 2>&1 | grep -F 'undefined symbol' || true)"
if [ -n "$UNRESOLVED" ]; then
  echo "FATAL: $OUT has unresolved symbols after load-time resolution:" >&2
  echo "$UNRESOLVED" | head -20 >&2
  echo "  ($(printf '%s\n' "$UNRESOLVED" | wc -l) unresolved total)" >&2
  exit 1
fi
echo "built $OUT"
