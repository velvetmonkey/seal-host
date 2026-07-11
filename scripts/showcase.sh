#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 demo/see_the_loop.py 2>&1
