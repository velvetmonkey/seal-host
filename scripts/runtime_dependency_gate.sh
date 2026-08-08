#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

STAGE=${1:?usage: runtime_dependency_gate.sh RELEASE_DIRECTORY}
STAGE=$(realpath -e "$STAGE")
BIN="$STAGE/bin/seal-host-rs"
test -x "$BIN"

READELF_OUTPUT="$(readelf -d "$BIN" "$STAGE"/lib/*.so)"
while IFS= read -r line; do
  if [[ "$line" =~ (RPATH|RUNPATH) ]] &&
     [[ "$line" =~ /home/|\.lake|mcp-seal|github\.com ]]; then
    echo "release has a private or build-workspace runtime path" >&2
    exit 1
  fi
done <<< "$READELF_OUTPUT"
LDD_OUTPUT="$(LD_LIBRARY_PATH="$STAGE/lib" ldd "$BIN")"
while IFS= read -r line; do
  if [[ "$line" =~ not\ found ]]; then
    echo "release has an unresolved or private runtime dependency" >&2
    exit 1
  fi

  # ldd reports bundled libraries by their absolute staging path. That path
  # may legitimately live below a user's home directory (RUNNER_TEMP does on
  # GitHub-hosted runners), so classify the resolved dependency relative to
  # the stage root before applying the private-workspace heuristic.
  read -r -a fields <<< "$line"
  dependency=
  if [[ "${fields[1]:-}" == "=>" ]]; then
    dependency=${fields[2]:-}
  elif [[ "${fields[0]:-}" == /* ]]; then
    dependency=${fields[0]}
  fi
  [[ "$dependency" == /* ]] || continue

  resolved_dependency=$(realpath -e "$dependency" 2>/dev/null) || {
    echo "release has an unresolved or private runtime dependency" >&2
    exit 1
  }
  case "$resolved_dependency" in
    "$STAGE"/*) continue ;;
  esac
  if [[ "$dependency" =~ /home/|\.lake|mcp-seal ]] ||
     [[ "$resolved_dependency" =~ /home/|\.lake|mcp-seal ]]; then
    echo "release has an unresolved or private runtime dependency" >&2
    exit 1
  fi
done <<< "$LDD_OUTPUT"
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
