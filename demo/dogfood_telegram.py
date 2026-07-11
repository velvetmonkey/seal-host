#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Dogfood demo 2 — Telegram approval, a REAL human tapping a REAL phone.

One command:
  TELEGRAM_BOT_TOKEN=... SEAL_TG_ALLOWED=<your numeric from.id> \
      python3 demo/dogfood_telegram.py

Setup (once, ~2 min): make a bot with @BotFather -> token; send it /start
from your account; get your numeric id (e.g. via @userinfobot).

What happens, all real:
  1. Real seal-host-rs spawns; guarded call -> BLOCKED with 64-hex target.
  2. The real Telegram bridge (demo/approve_telegram.py) starts with a fresh
     ed25519 key. Paste the printed target into your bot chat; it answers
     with Approve/Deny buttons (HMAC-bound intent; the BRIDGE key signs).
  3. Tap. The signed token lands in the token file; the identical call is
     re-issued: Approve -> flows; Deny -> explicit refusal, fail-closed.

No token/id -> honest exit 2 with instructions. Nothing is mocked.
Exit 0 = approved+flowed; 3 = denied (fail-closed, also correct); 1 = broken.
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
sys.path.insert(0, str(ROOT / "test" / "integration"))
sys.path.insert(0, str(ROOT / "test" / "tools"))

from approval_loop import env_with_ld  # noqa: E402
from sign_approval import generate_approval_keypair  # noqa: E402


def main() -> int:
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    allowed = os.environ.get("SEAL_TG_ALLOWED", "")
    if not tg_token or not allowed:
        print("NOT RUN: this demo needs a real Telegram bot — nothing is mocked.")
        print("  1. @BotFather -> create bot -> copy the token")
        print("  2. send your bot /start; get your numeric id (@userinfobot)")
        print("  3. TELEGRAM_BOT_TOKEN=<token> SEAL_TG_ALLOWED=<id> "
              "python3 demo/dogfood_telegram.py")
        return 2

    BIN = ROOT / "rust" / "target" / "debug" / "seal-host-rs"
    if not BIN.exists():
        print(f"seal-host-rs not built at {BIN}. One-time build: bash scripts/build_all.sh")
        return 1

    from test_host_rs import write_config, PUBKEY as CONFIG_PUB  # noqa: E402

    with tempfile.TemporaryDirectory(prefix="dogfood-tg-") as td:
        work = Path(td)
        tokens = work / "tokens.ndjson"
        tokens.write_text("", encoding="utf-8")
        trusted = write_config(work, work / "dummy.ndjson")
        priv, pub = generate_approval_keypair()

        host = subprocess.Popen(
            [str(BIN), "--config", str(trusted), "--pubkey", CONFIG_PUB,
             "--channel", "ed25519", "--token-file", str(tokens),
             "--approval-pubkey", pub, "--",
             "python3", str(ROOT / "test" / "integration" / "synthetic_ledger.py")],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env_with_ld())

        bridge_env = os.environ.copy()
        bridge_env["SEAL_APPROVAL_KEY_HEX"] = priv
        bridge = subprocess.Popen(
            [sys.executable, str(ROOT / "demo" / "approve_telegram.py"),
             "--token-file", str(tokens), "--allowed", allowed],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=bridge_env)
        try:
            host.stdin.write('{"jsonrpc":"2.0","id":0,"method":"initialize"}\n')
            host.stdin.flush()
            host.stdout.readline()
            call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": "db.execute",
                                          "arguments": {"database": "prod",
                                                        "sql": "drop table users"}}},
                              separators=(",", ":"))
            host.stdin.write(call + "\n")
            host.stdin.flush()
            blocked = ""
            for _ in range(20):
                blocked += host.stdout.readline()
                if "approval required:" in blocked:
                    break
                time.sleep(0.05)
            m = re.search(r"approval required: ([0-9a-f]{64})", blocked)
            if not m:
                print("BROKEN: no block/target. Raw:")
                print(blocked)
                return 1
            target = m.group(1)

            print("=" * 72)
            print("BLOCKED (raw host response):")
            print(blocked.rstrip())
            print("=" * 72)
            print("Now on your PHONE: paste this target into your bot chat, "
                  "then tap Approve or Deny:")
            print()
            print(f"  {target}")
            print()
            print("Waiting up to 300s for your signed decision via Telegram...")

            deadline = time.time() + 300
            while time.time() < deadline:
                if tokens.stat().st_size > 0:
                    break
                time.sleep(0.5)
            else:
                print("TIMEOUT: no decision arrived. Nothing flowed (fail-closed).")
                return 1

            print("Signed decision landed. Re-issuing the IDENTICAL call...")
            host.stdin.write(call + "\n")
            host.stdin.flush()
            second = ""
            for _ in range(20):
                line = host.stdout.readline()
                second += line
                if line.strip():
                    break
                time.sleep(0.05)
            try:
                # communicate() closes stdin itself; pre-closing it makes
                # communicate() raise (it flushes stdin) and the host audit on
                # stderr would be silently dropped from the "raw" output below.
                out2, err2 = host.communicate(timeout=3)
            except Exception:
                host.kill()
                out2, err2 = "", ""
            combined = second + (out2 or "") + "\n" + (err2 or "")
            print("=" * 72)
            print("SECOND RESPONSE + host audit (raw):")
            print(combined.rstrip())
            print("=" * 72)
            if "SYNTHETIC_LEDGER_ACTION" in combined:
                print("APPROVED PATH: the identical call FLOWED after your Telegram approval.")
                return 0
            if "refused" in combined.lower():
                print("DENIED PATH: host refused explicitly — fail-closed, as designed.")
                return 3
            print("BROKEN: neither flow nor explicit refusal observed.")
            return 1
        finally:
            for p in (host, bridge):
                try:
                    p.kill()
                except Exception:
                    pass


if __name__ == "__main__":
    raise SystemExit(main())
