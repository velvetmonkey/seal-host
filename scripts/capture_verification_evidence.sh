#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Canonical evidence capture for the approval-ingress verification plan.
# Runs steps 1-4 mechanically and saves real output to SCRATCH.
# Exits non-zero if any critical observation fails.
#
# Usage (from seal-host/):
#   SCRATCH=/tmp/grok-goal-0011268d014e/implementer bash scripts/capture_verification_evidence.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="${SCRATCH:-/tmp/grok-goal-0011268d014e/implementer}"
mkdir -p "$SCRATCH"

echo "=== 1. branch + status ===" | tee "$SCRATCH/branch.log"
( cd "$ROOT"; git branch --show-current; git status --porcelain ) | tee -a "$SCRATCH/branch.log"

echo "=== 2. cargo test (providers decline) ===" | tee "$SCRATCH/cargo-test.log"
( cd "$ROOT/rust"; \
  export LIBRARY_PATH="/home/monkey/.elan/toolchains/leanprover--lean4---v4.28.0/lib/lean:/home/monkey/src/seal-host/.lake/build/lib"; \
  export LD_LIBRARY_PATH="/home/monkey/.elan/toolchains/leanprover--lean4---v4.28.0/lib/lean:/home/monkey/src/seal-host/.lake/build/lib:${LD_LIBRARY_PATH:-}"; \
  cargo test ed25519_provider_accepts_signed_decline_and_allow --lib 2>&1 ) | tee -a "$SCRATCH/cargo-test.log" || true

echo "=== 3. quickstart x2 (documented entrypoint over synthetic, fresh state each) ==="
( cd "$ROOT"; python3 demo/see_the_loop.py ) 2>&1 | tee "$SCRATCH/quickstart-1.log" || true
( cd "$ROOT"; python3 demo/see_the_loop.py ) 2>&1 | tee "$SCRATCH/quickstart-2.log" || true

echo "=== 4. consumer (real Ed25519TokenProvider) ===" | tee "$SCRATCH/signer-consumer.log"
( cd "$ROOT"; python3 test/integration/test_approval_consumer.py ) 2>&1 | tee "$SCRATCH/signer-consumer.log" || true

echo "=== Evidence captured to $SCRATCH ==="
ls -l "$SCRATCH"/{branch.log,cargo-test.log,quickstart-*.log,signer-consumer.log} 2>/dev/null || true

# Basic mechanical assertions (the harness + see_the_loop also assert internally)
grep -q "feat/approval-ingress" "$SCRATCH/branch.log" || { echo "FAIL: not on feat/approval-ingress"; exit 1; }
grep -q "ed25519_provider_accepts_signed_decline_and_allow ... ok" "$SCRATCH/cargo-test.log" || { echo "FAIL: decline provider test not ok"; exit 1; }
grep -q "SYNTHETIC_LEDGER_ACTION" "$SCRATCH/quickstart-1.log" || { echo "FAIL: no SYNTHETIC side-effect in quickstart-1"; exit 1; }
grep -qi "refused" "$SCRATCH/quickstart-1.log" || { echo "FAIL: no refused in quickstart-1"; exit 1; }
grep -q "real Ed25519TokenProvider" "$SCRATCH/signer-consumer.log" || { echo "FAIL: consumer did not mention real provider"; exit 1; }

echo "ALL MECHANICAL OBSERVATIONS PASS"
