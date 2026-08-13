#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the Rust release binaries with checkout-independent embedded paths.
set -euo pipefail

# Cargo is the final release compiler; keep its environment aligned with the
# deterministic filesystem and linker-input policy used by the native build.
export LC_ALL=C

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
if [[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR=.
fi
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PIN="$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' "$ROOT/rust/rust-toolchain.toml")"
test -n "$PIN" || { echo "cannot read exact Rust toolchain pin" >&2; exit 1; }

ACTUAL="$(cd "$ROOT/rust" && rustc --version | awk '{print $2}')"
test "$ACTUAL" = "$PIN" || {
  echo "rustc version mismatch: rust-toolchain.toml pins $PIN, active rustc is $ACTUAL" >&2
  exit 1
}

CARGO_HOME_REAL=${CARGO_HOME:-${HOME:?HOME is required}/.cargo}
RUSTUP_HOME_REAL=${RUSTUP_HOME:-${HOME:?HOME is required}/.rustup}
REMAP_FLAGS="--remap-path-prefix=$ROOT=/src/seal-host --remap-path-prefix=$CARGO_HOME_REAL=/opt/cargo --remap-path-prefix=$RUSTUP_HOME_REAL=/opt/rustup"
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }$REMAP_FLAGS"
export SEAL_REPRODUCIBLE_RELEASE=1

cd "$ROOT/rust"
exec cargo build --locked --release --bins
