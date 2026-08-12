#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# C compiler shim for Lean's generated C.  GCC otherwise records the checkout
# and Lean installation paths in the object files that become libsealffi.so.
set -euo pipefail

ROOT=${SEAL_REPRO_ROOT:?SEAL_REPRO_ROOT must name the seal-host checkout}
LEAN_PREFIX=${SEAL_REPRO_LEAN_PREFIX:?SEAL_REPRO_LEAN_PREFIX must name the Lean installation}

# Lake calls LEAN_CC directly, bypassing `leanc`. Re-enter `leanc` with the
# override removed so it restores the toolchain's sysroot/runtime flags before
# delegating to the bundled compiler.
exec env -u LEAN_CC "$LEAN_PREFIX/bin/leanc" \
  "-ffile-prefix-map=$ROOT=/src/seal-host" \
  "-fdebug-prefix-map=$ROOT=/src/seal-host" \
  "-fmacro-prefix-map=$ROOT=/src/seal-host" \
  "-ffile-prefix-map=$LEAN_PREFIX=/opt/lean" \
  "-fdebug-prefix-map=$LEAN_PREFIX=/opt/lean" \
  "-fmacro-prefix-map=$LEAN_PREFIX=/opt/lean" \
  "$@"
