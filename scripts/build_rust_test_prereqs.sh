#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build Lean executables invoked by the generic Rust integration-test suite.
set -euo pipefail

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
if [[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR=.
fi
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -z "${LEANBUILD:-}" ]; then
  if command -v leanbuild >/dev/null 2>&1; then
    LEANBUILD=leanbuild
  else
    LEANBUILD=lake
  fi
fi

cd "$ROOT"
"$LEANBUILD" build three_artifact_byte_lock
