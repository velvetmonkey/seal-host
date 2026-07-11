#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
External consumer test (outside approver modules) — two explicit steps, zero fallbacks.

Step A (provider): run the unit test that exercises the real Ed25519TokenProvider
with signed allow + decline lines. Print full output. Fail if not ok.

Step B (host short-circuit): call the canonical run_signed_ed25519_loop(allow=False)
with matching tool args, assert the explicit "approval refused (signed decline" string
is present in combined stdout+stderr, print the full transcript.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "integration"))
from approval_loop import run_signed_ed25519_loop  # noqa: E402


def main() -> int:
    ROOT = Path(__file__).resolve().parents[2]

    print("=== Step A: real Ed25519TokenProvider unit test ===")
    res = subprocess.run(
        ["cargo", "test", "ed25519_provider_accepts_signed_decline_and_allow", "--lib"],
        cwd=ROOT / "rust",
        capture_output=True,
        text=True,
        timeout=120,
    )
    print(res.stdout)
    print(res.stderr)
    if res.returncode != 0 or "FAILED" in res.stdout or "FAILED" in res.stderr:
        print("Step A FAILED")
        return 1
    print("Step A OK (real provider accepted signed allow + decline)")

    print("\n=== Step B: host short-circuit with signed decline ===")
    with tempfile.TemporaryDirectory(prefix="consumer-stepb-") as td:
        obs = run_signed_ed25519_loop(
            Path(td),
            allow=False,
            tool_name="db.execute",
            tool_args={"database": "prod", "sql": "drop table users"},
        )
        combined = (obs.get("stdout") or "") + "\n" + (obs.get("stderr") or "")
        block = obs.get("block_text") or ""
        print("FULL TRANSCRIPT (stdout + stderr):")
        if block:
            print("INITIAL_BLOCK:", block.strip())
        print(combined)
        if "approval refused (signed decline" not in combined:
            print("Step B FAILED: refused string not found in host output")
            return 1
        print("Step B OK (host emitted explicit refused for signed decline)")

    print("\nconsumer: SUCCESS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
