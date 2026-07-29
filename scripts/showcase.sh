#!/bin/bash
set -euo pipefail
SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
if [[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR=.
fi
cd "$SCRIPT_DIR/.."
exec python3 demo/see_the_loop.py 2>&1
