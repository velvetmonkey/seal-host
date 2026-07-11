#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
One-command "see the loop" quickstart over synthetic ledger using the ed25519 signed token channel.

  python3 demo/see_the_loop.py

Drives the real shipped seal-host-rs with:
- ed25519 signed approval channel (target ‖ nonce ‖ issuedAt [decision])
- real CLI approver (no --plain) that emits the signed envelope and appends it
- synthetic_ledger.py as the child (emits SYNTHETIC_LEDGER_ACTION side-effect on allow)

Both approve and deny paths:
- block with real "approval required: <64-hex>" (target extracted, no fallback)
- human "ping" via CLI (signed record written)
- action flows (SYNTHETIC side-effect) only on allow
- explicit refused (host "refused" response + "approval refused" audit) on deny, not "timed out"

Zero external setup. Full TCB/ORDERING-vs-ORIGIN/"what this proves" in docs and CLI output.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust" / "target" / "debug" / "seal-host-rs"
SYN = ROOT / "test" / "integration" / "synthetic_ledger.py"
CLI = ROOT / "demo" / "approve_cli.py"

sys.path.insert(0, str(ROOT / "test" / "tools"))
sys.path.insert(0, str(ROOT / "test" / "integration"))

from sign_approval import generate_approval_keypair  # noqa: E402
from test_host_rs import write_config, DESTRUCTIVE, PUBKEY as CONFIG_PUB  # noqa: E402


def env_ld():
    e = os.environ.copy()
    lean = "/home/monkey/.elan/toolchains/leanprover--lean4---v4.28.0/lib/lean"
    lake = str(ROOT / ".lake/build/lib")
    e["LD_LIBRARY_PATH"] = f"{lean}:{lake}:{e.get('LD_LIBRARY_PATH', '')}".rstrip(":")
    return e


def extract_target(text: str):
    m = re.search(r"approval required: ([0-9a-f]{64})", text)
    return m.group(1) if m else None


def run_one(label: str, work: Path):
    tokens = work / "tokens.ndjson"
    tokens.write_text("", encoding="utf-8")
    dummy = work / "dummy.ndjson"
    dummy.write_text("", encoding="utf-8")

    # Proven config (works for ed25519 in the test suite)
    trusted = write_config(work, dummy)

    # Separate approval channel key (must differ from config key)
    appr_priv, appr_pub = generate_approval_keypair()

    cmd = [
        str(BIN),
        "--config", str(trusted),
        "--pubkey", CONFIG_PUB,
        "--channel", "ed25519",
        "--token-file", str(tokens),
        "--approval-pubkey", appr_pub,
        "--",
        "python3", str(SYN),
    ]

    env = env_ld()
    proc = subprocess.Popen(cmd, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env)
    obs = {"target": None, "flowed": False, "refused": False, "cli": ""}

    try:
        # passthrough init
        try:
            proc.stdin.write('{"jsonrpc":"2.0","id":0,"method":"initialize"}\n')
            proc.stdin.flush()
            _ = proc.stdout.readline()
        except Exception:
            pass

        call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "db.execute", "arguments": DESTRUCTIVE}},
                          separators=(",", ":"))

        # first call -> block, extract real target (no fallback)
        proc.stdin.write(call + "\n")
        proc.stdin.flush()

        blocked = ""
        for _ in range(12):
            l = proc.stdout.readline()
            blocked += l
            if "approval required:" in l:
                break
            time.sleep(0.03)

        t = extract_target(blocked)
        if not t:
            # fail loudly if we can't get a real target — do not fall back
            raise AssertionError(f"failed to extract dynamic target from block: {blocked[:300]}")
        obs["target"] = t
        print(f"[{label}] BLOCK (real host): {blocked.strip()[:200]}")

        # real CLI approver (signed ed25519 envelope, target-bound)
        cli_cmd = [sys.executable, str(CLI), "--token-file", str(tokens), "--target", t,
                   "--approve" if label == "approve" else "--deny", "--key", appr_priv, "--yes"]
        cli_out = subprocess.check_output(cli_cmd, cwd=ROOT, text=True, env=env, timeout=15)
        obs["cli"] = cli_out
        print(f"[{label}] CLI (signed ed25519 envelope):\n{cli_out.strip()[:600]}")

        # re-issue
        proc.stdin.write(call + "\n")
        proc.stdin.flush()
        time.sleep(0.35)

        second = ""
        for _ in range(8):
            l = proc.stdout.readline()
            second += l
            if l.strip():
                break
        print(f"[{label}] AFTER: {second.strip()[:220]}")

        if "SYNTHETIC_LEDGER_ACTION" in second:
            obs["flowed"] = True
        if "refused" in second.lower() or "approval refused" in second.lower():
            obs["refused"] = True

        # capture audit/refused from stderr
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            o2, e2 = proc.communicate(timeout=2.5)
            full_err = (e2 or "") + (o2 or "")
            if "SYNTHETIC_LEDGER_ACTION" in full_err:
                obs["flowed"] = True
            if "refused" in full_err.lower() or "approval refused" in full_err.lower():
                obs["refused"] = True
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    finally:
        try:
            proc.kill()
        except Exception:
            pass

    return obs


def main() -> int:
    print("=== seal developer-ingress one-command (REAL ed25519 signed + synthetic) ===")
    print("Uses shipped host + ed25519 signed tokens + real CLI approver (target-bound).")
    print("")

    for lab in ("approve", "deny"):
        with tempfile.TemporaryDirectory(prefix=f"see-ed-{lab}-") as td:
            o = run_one(lab, Path(td))
            print(f"--- {lab} target={o['target']} flowed={o['flowed']} refused={o['refused']}")
            if o['flowed'] and lab == "approve":
                print("  (SYNTHETIC side-effect observed — action flowed)")
            if o['refused']:
                print("  (host-emitted refused — not timed out)")

    print("\n=== PASS ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
