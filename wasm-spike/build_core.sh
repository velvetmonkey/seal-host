#!/usr/bin/env bash
# Compile the seal-host PROJECT Lean-C (.lake/build/ir/*.c) -> build-core/*.o for
# the wasm decide path. This is the ir->build-core step that build_wasm.sh assumes
# already exists: build_wasm.sh only recompiles the C glue and relinks build-core/*.o.
# Run this FIRST to rebuild the project objects from the CURRENT Lean HEAD, so the
# emitted seal.wasm reflects HEAD sources (not a stale spike build).
#
# EXPLICIT ALLOW-LIST, not a glob: only the modules in Ffi's transitive import
# closure that belong in the wasm. Native-only modules (Host, Host/Main,
# Host/Composition — carry `main` / pull Std.Time) and off-path modules
# (Host/Record, Host/RecordReflection — not imported by Ffi) are deliberately
# NOT compiled, so they can never enter build_wasm.sh's `build-core/*.o` glob.
#
# Flags are byte-identical to build_wasm.sh:13 / build_closure.sh:19.
#
# Usage: ./build_core.sh
set -uo pipefail
cd "$(dirname "$0")"
source ./emsdk/emsdk_env.sh >/dev/null 2>&1 || { echo "[build_core] emsdk activate FAILED"; exit 1; }

ROOT=/home/monkey/src/seal-host
IR="$ROOT/.lake/build/ir"
CFLAGS="-O2 -I lean4-src/src/include -I gen/include -I gen -D LEAN_EMSCRIPTEN=1"

# Ffi-reachable project modules (ir-relative paths, no .c). Output name = path with
# '/' -> '_'. NEW at this HEAD: Host/Step (Ffi now routes through Host.stepRoute).
MODULES=(
  Ffi
  Host/Action Host/Audit Host/Canonical Host/Config Host/Evidence Host/Kernel Host/Registry Host/Step
  Kernels
  Kernels/Budget Kernels/BudgetCore Kernels/Calibration Kernels/Consensus
  Kernels/Convergence Kernels/Linear Kernels/LinearCore Kernels/Safety Kernels/Temporal
)

mkdir -p build-core
echo "[build_core] compiling ${#MODULES[@]} project modules from $IR"
for m in "${MODULES[@]}"; do
  src="$IR/$m.c"
  out="build-core/${m//\//_}.o"
  if [ ! -f "$src" ]; then
    echo "[build_core] MISSING ir source: $src (run 'lake build Ffi' first)"; exit 1
  fi
  emcc $CFLAGS -c "$src" -o "$out" || { echo "[build_core] COMPILE FAILED: $m"; exit 1; }
  echo "  ok  $m -> $out"
done
echo "[build_core] done: $(ls build-core/*.o | grep -vcE 'stubs|seal_wrapper|ffi_shim') project objects"
