#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Local Phase 0 evidence wrapper. Assumes the private Seal repos are siblings
# under the parent directory of this repo.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$(cd "$ROOT/.." && pwd)"
MCP_SEAL_DEV="$SRC/mcp-seal-dev"
SEAL_CHECK="$SRC/seal-check"
SEAL_ASSURANCE_KIT="$SRC/seal-assurance-kit"

current_step="startup"
completed_steps=()

on_error() {
  local code=$?
  echo
  echo "EVIDENCE: FAIL"
  echo "  failed step: $current_step"
  echo "  exit code: $code"
  if [ "${#completed_steps[@]}" -gt 0 ]; then
    echo "  completed:"
    printf '    - %s\n' "${completed_steps[@]}"
  fi
  exit "$code"
}
trap on_error ERR

require_dir() {
  local path="$1"
  [ -d "$path" ] || { echo "missing required sibling repo: $path" >&2; exit 2; }
}

run_step() {
  local name="$1"
  local dir="$2"
  shift 2
  current_step="$name"
  echo
  echo "==> $name"
  (cd "$dir" && "$@")
  completed_steps+=("$name")
}

require_dir "$MCP_SEAL_DEV"
require_dir "$SEAL_CHECK"
require_dir "$SEAL_ASSURANCE_KIT"

echo "Seal Phase 0 evidence chain"
echo "  seal-host:          $ROOT"
echo "  mcp-seal-dev:       $MCP_SEAL_DEV"
echo "  seal-check:         $SEAL_CHECK"
echo "  seal-assurance-kit: $SEAL_ASSURANCE_KIT"

run_step "mcp-seal-dev: build Ed25519 C leaf" "$MCP_SEAL_DEV" bash c/build.sh
run_step "mcp-seal-dev: lake build" "$MCP_SEAL_DEV" lake build
run_step "mcp-seal-dev: axiom_check" "$MCP_SEAL_DEV" lake exe axiom_check
for exe in \
  v2_m1_axiom_check \
  v2_m2_axiom_check \
  v2_m3_parser_axiom_check \
  v2_m3_axiom_check \
  v2_m4_axiom_check \
  v2_m6_axiom_check
do
  run_step "mcp-seal-dev: $exe" "$MCP_SEAL_DEV" lake exe "$exe"
done

if [ ! -d "$ROOT/.lake/packages/mcp-seal" ]; then
  run_step "seal-host: lake update" "$ROOT" lake update
fi
run_step "seal-host: build vendored Ed25519 C leaf" "$ROOT/.lake/packages/mcp-seal" bash c/build.sh
run_step "seal-host: lake build" "$ROOT" lake build
run_step "seal-host: axiom_check" "$ROOT" lake exe axiom_check
run_step "seal-host: lake build Ffi native export" "$ROOT" lake build +Ffi:c.o.export
run_step "seal-host: build FFI shared object" "$ROOT" scripts/build_ffi_so.sh
run_step "seal-host: cargo fmt --check" "$ROOT/rust" cargo fmt --check
run_step "seal-host: cargo clippy" "$ROOT/rust" cargo clippy --all-targets -- -D warnings
run_step "seal-host: cargo test" "$ROOT/rust" cargo test
run_step "seal-host: cargo build --release --bins" "$ROOT/rust" cargo build --release --bins
run_step "seal-host: conformance bridge --wasm" "$ROOT" node scripts/conformance_bridge.mjs --wasm

run_step "seal-check: receipt-format vectors" "$SEAL_CHECK" node test/receipt-format.test.cjs
run_step "seal-check: receipt harness" "$SEAL_CHECK" node test/receipt-harness.cjs
run_step "seal-check: cross-receipt vectors" "$SEAL_CHECK" node test/cross-receipt.test.cjs

run_step "seal-assurance-kit: npm test" "$SEAL_ASSURANCE_KIT" npm test

echo
echo "EVIDENCE: PASS"
printf '  - %s\n' "${completed_steps[@]}"
