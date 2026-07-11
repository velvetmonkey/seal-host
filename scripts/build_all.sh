#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# One-shot build for seal-host: Lean core + FFI shared object + Rust host.
# Runs the four steps from DEPLOY.md §1 in order, from the repo root.
#
#   lake build             -> Lean core + FFI
#   lake exe axiom_check   -> confirm the axiom footprint (optional but cheap)
#   scripts/build_ffi_so.sh-> the FFI shared object the Rust host loads
#   cargo build            -> the Rust host binary
#
# Result binary: rust/target/debug/seal-host-rs
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> lake build"
lake build

echo "==> lake exe axiom_check"
lake exe axiom_check

echo "==> scripts/build_ffi_so.sh"
scripts/build_ffi_so.sh

echo "==> cargo build (rust host)"
cd rust && cargo build && cd ..

echo "==> done: rust/target/debug/seal-host-rs"
