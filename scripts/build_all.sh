#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# One-shot build for seal-host: Lean core + FFI shared object + Rust host.
# Runs the four steps from DEPLOY.md §1 in order, from the repo root.
#
#   lake build             -> Lean core + FFI + compiled byte-lock witness
#   lake exe axiom_check   -> confirm the axiom footprint (optional but cheap)
#   scripts/build_ffi_so.sh-> the FFI shared object the Rust host loads
#   cargo build            -> the Rust host binary
#
# Result binary: rust/target/debug/seal-host-rs
set -euo pipefail

# Keep the one-shot release-shaped build on the same locale policy as the
# individual release helpers it invokes.
export LC_ALL=C

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
if [[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR=.
fi
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# A shared developer host may provide `leanbuild` to serialize and bound Lean
# builds.  Honour an explicit LEANBUILD command first, then that wrapper when
# available; CI and fresh machines without it retain the ordinary Lake path.
if [ -z "${LEANBUILD:-}" ]; then
  if command -v leanbuild >/dev/null 2>&1; then
    LEANBUILD=leanbuild
  else
    LEANBUILD=lake
  fi
fi

# `axiom_check` is a default Lake target and links this unmanaged native
# object through `moreLinkArgs`.  On a fresh checkout `lake build +Ffi` may
# therefore reach that link before the later FFI stage has had a chance to
# create it.  Fetch packages first, then build the native prerequisite.
if [ -d vendor/mcp-seal ]; then
  MCP_SEAL_ROOT=vendor/mcp-seal
else
  MCP_SEAL_ROOT=.lake/packages/mcp-seal
fi

if [ ! -f "$MCP_SEAL_ROOT/c/build/libsealcrypto.o" ]; then
  "$LEANBUILD" update
  bash "$MCP_SEAL_ROOT/c/build.sh"
fi

echo "==> lake build +Ffi three_artifact_byte_lock (runtime import closure + byte-lock witness)"
"$LEANBUILD" build +Ffi three_artifact_byte_lock

echo "==> lake exe axiom_check"
"$LEANBUILD" exe axiom_check

echo "==> scripts/build_ffi_so.sh"
LEANBUILD="$LEANBUILD" scripts/build_ffi_so.sh

echo "==> cargo build (rust host)"
(
  cd rust
  cargo build
)

echo "==> done: rust/target/debug/seal-host-rs"
