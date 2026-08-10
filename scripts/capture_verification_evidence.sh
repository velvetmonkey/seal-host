#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Canonical evidence capture for the approval-ingress verification plan.
# Runs steps 1-4 mechanically and saves real output to SCRATCH.
# Exits non-zero if any critical observation fails.
#
# Usage (from seal-host/):
#   bash scripts/capture_verification_evidence.sh
#   SCRATCH=/path/to/out bash scripts/capture_verification_evidence.sh   # custom output dir

set -euo pipefail

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
if [[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR=.
fi
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/seal-host-evidence}"
mkdir -p "$SCRATCH"

# Native libs derived from the toolchain + this checkout, not hardcoded:
#   LEAN_LIB  = the Lean runtime shared libs (from `lean --print-prefix`)
#   LAKE_LIB  = libsealffi.so built into this repo's .lake (see scripts/build_ffi_so.sh)
LEAN_PREFIX="$(lean --print-prefix 2>/dev/null || true)"
LEAN_LIB="${LEAN_PREFIX:+$LEAN_PREFIX/lib/lean}"
LAKE_LIB="$ROOT/.lake/build/lib"
export LIBRARY_PATH="${LEAN_LIB}:${LAKE_LIB}"
export LD_LIBRARY_PATH="${LEAN_LIB}:${LAKE_LIB}:${LD_LIBRARY_PATH:-}"

echo "=== 1. branch + status ===" | tee "$SCRATCH/branch.log"
(
  cd "$ROOT" || exit
  echo "BRANCH:"
  git branch --show-current || exit
  echo "PORCELAIN:"
  P=$(git status --porcelain) || exit
  if [ -z "$P" ]; then
    echo "(clean committed tree - no modified/untracked files)"
  else
    echo "$P"
  fi
  echo "PORCELAIN_END"
) | tee -a "$SCRATCH/branch.log"

echo "=== 2. cargo test (providers decline) ===" | tee "$SCRATCH/cargo-test.log"
( cd "$ROOT/rust" || exit; \
  export LIBRARY_PATH="${LEAN_LIB}:${LAKE_LIB}"; \
  export LD_LIBRARY_PATH="${LEAN_LIB}:${LAKE_LIB}:${LD_LIBRARY_PATH:-}"; \
  cargo test ed25519_provider_accepts_signed_decline_and_allow --lib 2>&1 ) | tee -a "$SCRATCH/cargo-test.log"

echo "=== 3. quickstart x2 (documented entrypoint over synthetic, fresh state each) ==="
( cd "$ROOT" || exit; python3 demo/see_the_loop.py ) 2>&1 | tee "${SCRATCH}/quickstart-1.log"
( cd "$ROOT" || exit; QS_SQL1="drop table users" QS_SQL2="truncate table audit" python3 demo/see_the_loop.py ) 2>&1 | tee "${SCRATCH}/quickstart-2.log"

echo "=== 4. consumer (real Ed25519TokenProvider) ===" | tee "$SCRATCH/signer-consumer.log"
( cd "$ROOT" || exit; python3 test/integration/test_approval_consumer.py ) 2>&1 | tee "$SCRATCH/signer-consumer.log"

echo "=== Evidence captured to $SCRATCH ==="
ls -l "$SCRATCH"/{branch.log,cargo-test.log,quickstart-*.log,signer-consumer.log} 2>/dev/null || true

# Basic mechanical assertions (the harness + see_the_loop also assert internally)
grep -q "PORCELAIN_END" "$SCRATCH/branch.log" || { echo "FAIL: branch.log missing PORCELAIN_END"; exit 1; }
grep -q "ed25519_provider_accepts_signed_decline_and_allow ... ok" "$SCRATCH/cargo-test.log" || { echo "FAIL: decline provider test not ok"; exit 1; }
grep -q "SYNTHETIC side-effect observed" "$SCRATCH/quickstart-1.log" || { echo "FAIL: no SYNTHETIC side-effect in quickstart-1"; exit 1; }
grep -q "host-emitted refused" "$SCRATCH/quickstart-2.log" || { echo "FAIL: no host-emitted refused in quickstart-2"; exit 1; }
grep -q "approval refused (signed decline" "$SCRATCH/signer-consumer.log" || { echo "FAIL: signer-consumer.log missing explicit refused string from host"; exit 1; }
grep -q "approval required" "$SCRATCH/quickstart-1.log" || { echo "FAIL: quickstart-1.log missing 'approval required' + hex"; exit 1; }
grep -q "approval required" "$SCRATCH/quickstart-2.log" || { echo "FAIL: quickstart-2.log missing 'approval required' + hex"; exit 1; }

echo "ALL MECHANICAL OBSERVATIONS PASS"
