#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Dogfood demo 1 — CLI approval, a REAL human in the loop.

One command:  python3 demo/dogfood_cli.py

What you will see, all real, no mocks:
  1. The real seal-host-rs binary spawns over a synthetic ledger child.
  2. A guarded `db.execute` (drop table) is issued -> BLOCKED, and the host
     prints the exact 64-hex target commitment.
  3. THIS script pauses. YOU approve (or deny) in another terminal with the
     real CLI approver, which ed25519-signs a target-bound token:
        python3 demo/approve_cli.py --token-file <printed> --target <printed> --key-file <printed>
  4. The identical call is re-issued: APPROVED -> it flows (you see the
     ledger side-effect); DENIED -> the host refuses, explicitly, fail-closed.

Raw host output is printed verbatim. Exit 0 = approved+flowed;
exit 3 = you denied (also a correct, fail-closed outcome); exit 1 = broken.
"""

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test" / "integration"))
sys.path.insert(0, str(ROOT / "test" / "tools"))

from approval_loop import env_with_ld  # noqa: E402
from sign_approval import generate_approval_keypair  # noqa: E402
import subprocess  # noqa: E402
import re  # noqa: E402


def main() -> int:
    BIN = ROOT / "rust" / "target" / "debug" / "seal-host-rs"
    if not BIN.exists():
        print(f"seal-host-rs not built at {BIN}.")
        print("One-time build: bash scripts/build_all.sh   (Lean + FFI + Rust)")
        return 1

    from test_host_rs import write_config, PUBKEY as CONFIG_PUB  # noqa: E402

    with tempfile.TemporaryDirectory(prefix="dogfood-cli-") as td:
        work = Path(td)
        tokens = work / "tokens.ndjson"
        tokens.write_text("", encoding="utf-8")
        trusted = write_config(work, work / "dummy.ndjson")

        priv, pub = generate_approval_keypair()
        keyfile = work / "approval.key"
        keyfile.write_text(priv, encoding="utf-8")

        cmd = [str(BIN), "--config", str(trusted), "--pubkey", CONFIG_PUB,
               "--channel", "ed25519", "--token-file", str(tokens),
               "--approval-pubkey", pub, "--",
               "python3", str(ROOT / "test" / "integration" / "synthetic_ledger.py")]
        proc = subprocess.Popen(cmd, cwd=ROOT, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=env_with_ld())
        try:
            proc.stdin.write('{"jsonrpc":"2.0","id":0,"method":"initialize"}\n')
            proc.stdin.flush()
            proc.stdout.readline()

            call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": "db.execute",
                                          "arguments": {"database": "prod",
                                                        "sql": "drop table users"}}},
                              separators=(",", ":"))
            proc.stdin.write(call + "\n")
            proc.stdin.flush()
            blocked = ""
            for _ in range(20):
                blocked += proc.stdout.readline()
                if "approval required:" in blocked:
                    break
                time.sleep(0.05)
            m = re.search(r"approval required: ([0-9a-f]{64})", blocked)
            if not m:
                print("BROKEN: no block/target from host. Raw output:")
                print(blocked)
                return 1
            target = m.group(1)

            print("=" * 72)
            print("BLOCKED (raw host response):")
            print(blocked.rstrip())
            print("=" * 72)
            print("Your move. In ANOTHER terminal, approve or deny this exact target:")
            print()
            print(f"  python3 demo/approve_cli.py \\\n"
                  f"      --token-file {tokens} \\\n"
                  f"      --target {target} \\\n"
                  f"      --key-file {keyfile}")
            print()
            print("(the CLI prompts approve/deny; the ed25519 KEY authorizes, "
                  "the button is only intent)")
            print("Waiting up to 300s for your signed decision...")

            deadline = time.time() + 300
            while time.time() < deadline:
                if tokens.stat().st_size > 0:
                    break
                time.sleep(0.5)
            else:
                print("TIMEOUT: no decision arrived. Nothing flowed (fail-closed).")
                return 1

            print("Signed decision landed. Re-issuing the IDENTICAL call...")
            proc.stdin.write(call + "\n")
            proc.stdin.flush()
            second = ""
            for _ in range(20):
                line = proc.stdout.readline()
                second += line
                if line.strip():
                    break
                time.sleep(0.05)
            try:
                # communicate() closes stdin itself; pre-closing it makes
                # communicate() raise (it flushes stdin) and the host audit on
                # stderr would be silently dropped from the "raw" output below.
                out2, err2 = proc.communicate(timeout=3)
            except Exception:
                proc.kill()
                out2, err2 = "", ""
            combined = second + (out2 or "") + "\n" + (err2 or "")
            print("=" * 72)
            print("SECOND RESPONSE + host audit (raw):")
            print(combined.rstrip())
            print("=" * 72)
            if "SYNTHETIC_LEDGER_ACTION" in combined:
                print("APPROVED PATH: the identical call FLOWED after your signed approval.")
                print("Re-check the decision evidence yourself: host stderr above; "
                      "see seal-check (browser) / seal-assurance-kit (`seal verify`).")
                return 0
            if "refused" in combined.lower():
                print("DENIED PATH: host refused explicitly — fail-closed, as designed.")
                return 3
            print("BROKEN: neither flow nor explicit refusal observed.")
            return 1
        finally:
            try:
                proc.kill()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
