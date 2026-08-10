#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
One-command "see the loop" quickstart (thin wrapper over the canonical harness).

  python3 demo/see_the_loop.py

Uses the single source of truth `run_signed_ed25519_loop` (ed25519 signed tokens,
synthetic child, real CLI approver, dynamic target extraction).

Runs approve then deny. For the second run a different SQL is used so the
two invocations produce distinct target hexes while still using the signed
ed25519 channel.

No duplicate subprocess logic here.
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test" / "integration"))

from approval_loop import run_signed_ed25519_loop  # noqa: E402


def main() -> int:
    print("=== seal developer-ingress one-command (REAL ed25519 signed + synthetic via harness) ===")

    # First run (approve)
    sql1 = os.environ.get("QS_SQL1", "drop table users")
    with tempfile.TemporaryDirectory(prefix="see-qs-1-") as td:
        o1 = run_signed_ed25519_loop(
            Path(td),
            allow=True,
            tool_name="db.execute",
            tool_args={"database": "prod", "sql": sql1},
        )
        if o1.get("block_text"):
            print("BLOCK:", o1["block_text"].strip())
        print(f"--- approve target={o1['target']} flowed={o1['flowed']} refused={o1['refused']}")
        assert o1["flowed"], "approve expectation failed: action did not flow"
        if o1.get("cli_out"):
            print("CLI:", o1["cli_out"].strip()[:300])
        if "SYNTHETIC_LEDGER_ACTION" in (o1.get("stdout", "") + o1.get("stderr", "")):
            print("  (SYNTHETIC side-effect observed — action flowed)")

    # Second run (deny) — different SQL so target differs
    sql2 = os.environ.get("QS_SQL2", "truncate table audit")
    with tempfile.TemporaryDirectory(prefix="see-qs-2-") as td:
        o2 = run_signed_ed25519_loop(
            Path(td),
            allow=False,
            tool_name="db.execute",
            tool_args={"database": "prod", "sql": sql2},
        )
        if o2.get("block_text"):
            print("BLOCK:", o2["block_text"].strip())
        print(f"--- deny   target={o2['target']} flowed={o2['flowed']} refused={o2['refused']}")
        assert o2["refused"], "deny expectation failed: action was not refused"
        if o2.get("cli_out"):
            print("CLI:", o2["cli_out"].strip()[:300])
        combined2 = o2.get("stdout", "") + "\n" + o2.get("stderr", "")
        if "approval refused (signed decline" in combined2:
            print("  (host-emitted refused — not timed out)")

    print("\n=== PASS ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
