#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

STAGE=${1:?usage: runtime_dependency_gate.sh RELEASE_DIRECTORY}
BIN="$STAGE/bin/seal-host-rs"
test -x "$BIN"

if readelf -d "$BIN" "$STAGE"/lib/*.so | grep -E 'RPATH|RUNPATH' | grep -E '/home/|\.lake|mcp-seal|github\.com'; then
  echo "release has a private or build-workspace runtime path" >&2
  exit 1
fi
if LD_LIBRARY_PATH="$STAGE/lib" ldd "$BIN" | grep -E 'not found|/home/|\.lake|mcp-seal'; then
  echo "release has an unresolved or private runtime dependency" >&2
  exit 1
fi
set +e
SMOKE=$(LD_LIBRARY_PATH="$STAGE/lib" "$BIN" 2>&1)
STATUS=$?
set -e
if [ "$STATUS" -ne 2 ] || ! grep -q '^usage: seal-host-rs' <<<"$SMOKE"; then
  echo "packaged binary did not reach its argument parser" >&2
  echo "$SMOKE" >&2
  exit 1
fi
echo "PASS self-contained public runtime dependency gate"
