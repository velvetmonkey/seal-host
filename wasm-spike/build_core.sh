#!/usr/bin/env bash
# Compile the seal-host PROJECT Lean-C (.lake/build/ir/*.c) -> build-core/*.o
# and the mcp-seal package Lean-C -> build-seal/*.o for the wasm decide path.
# This is the ir->object step that build_wasm.sh assumes already exists:
# build_wasm.sh only recompiles the C glue and relinks object trees.
# Run this FIRST to rebuild from the CURRENT Lean HEAD, so the emitted seal.wasm
# reflects HEAD sources (not a stale spike build).
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
set -euo pipefail
cd "$(dirname "$0")"
source ./emsdk/emsdk_env.sh >/dev/null 2>&1 || { echo "[build_core] emsdk activate FAILED"; exit 1; }

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IR="$ROOT/.lake/build/ir"
CFLAGS="-O2 -I lean4-src/src/include -I gen/include -I gen -D LEAN_EMSCRIPTEN=1"

# Ffi-reachable project modules (ir-relative paths, no .c). Output name = path
# with '/' -> '_'. Host/Step is present because Ffi routes through Host.stepRoute;
# Host/UnicodeKeys supplies the runtime NFD key-identity guard used by
# Host/Canonical. Host/SurrogateEscapes and Host/NestingDepth supply the A2
# pre-parse guards reached through Host/Canonical.
MODULES=(
  Ffi
  Host/Action Host/Audit Host/Canonical Host/Config Host/Evidence Host/JsonWire Host/Kernel Host/Registry Host/Sha256 Host/Step Host/UnicodeKeys
  Host/SurrogateEscapes Host/NestingDepth
  Host/Principal Host/Provenance
  Kernels
  Kernels/Budget Kernels/BudgetCore Kernels/Calibration Kernels/Consensus
  Kernels/Convergence Kernels/Linear Kernels/LinearCore Kernels/PrincipalBudget
  Kernels/Safety Kernels/Temporal
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

MCP_TYPE="$(jq -r '.packages[] | select(.name | contains("mcp-seal")) | .type' "$ROOT/lake-manifest.json")"
if [ "$MCP_TYPE" = "path" ]; then
  MCP_DIR="$(jq -r '.packages[] | select(.name | contains("mcp-seal")) | .dir' "$ROOT/lake-manifest.json")"
  SEAL_ROOT="$(realpath "$ROOT/$MCP_DIR")"
else
  SEAL_ROOT="$ROOT/.lake/packages/mcp-seal"
fi
SEAL_IR="$SEAL_ROOT/.lake/build/ir"
SEAL_MODULES=(
  SealCore SealCore/Automaton SealCore/Event SealCore/Safety SealCore/Sha256
  Seal/Block Seal/Channel Seal/Classify Seal/Hash Seal/JsonUtil
  Seal/EffectCommitment Seal/EncodingInjective
  Seal/PolicyWire Seal/Policy Seal/PolicyBundle
  SealV2/Canonical SealV2/Crypto SealV2/Decide SealV2/Escape SealV2/Parser
  SealV2/EffectEnvelope SealV2/McpVersionGate
  SealV2/Serialization SealV2/Validation
)

mkdir -p build-seal
rm -f build-seal/*.o build-seal/*.log
echo "[build_core] compiling ${#SEAL_MODULES[@]} mcp-seal modules from $SEAL_IR"
for m in "${SEAL_MODULES[@]}"; do
  src="$SEAL_IR/$m.c"
  out="build-seal/${m//\//_}.o"
  if [ ! -f "$src" ]; then
    echo "[build_core] MISSING mcp-seal ir source: $src (run 'lake build Ffi' first)"; exit 1
  fi
  emcc $CFLAGS -c "$src" -o "$out" || { echo "[build_core] MCP-SEAL COMPILE FAILED: $m"; exit 1; }
  echo "  ok  $m -> $out"
done
echo "[build_core] done: $(ls build-seal/*.o | wc -l) mcp-seal objects"
