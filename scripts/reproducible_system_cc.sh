#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Host C compiler shim for handwritten FFI/crypto C sources.
set -euo pipefail

ROOT=${SEAL_REPRO_ROOT:?SEAL_REPRO_ROOT must name the seal-host checkout}
LEAN_PREFIX=${SEAL_REPRO_LEAN_PREFIX:?SEAL_REPRO_LEAN_PREFIX must name the Lean installation}

exec /usr/bin/cc \
  "-ffile-prefix-map=$ROOT=/src/seal-host" \
  "-fdebug-prefix-map=$ROOT=/src/seal-host" \
  "-fmacro-prefix-map=$ROOT=/src/seal-host" \
  "-ffile-prefix-map=$LEAN_PREFIX=/opt/lean" \
  "-fdebug-prefix-map=$LEAN_PREFIX=/opt/lean" \
  "-fmacro-prefix-map=$LEAN_PREFIX=/opt/lean" \
  "$@"
