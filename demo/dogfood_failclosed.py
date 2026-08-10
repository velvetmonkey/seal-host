#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Dogfood demo 3 — the seatbelt fails CLOSED. Two attacks, zero approvals flow.

One command:  python3 demo/dogfood_failclosed.py     (fully automated)

Leg 1 — SIGNED DECLINE: a real ed25519-signed DENY lands in the channel.
        The host refuses the call EXPLICITLY (not a timeout, a decision).
Leg 2 — TAMPERED TOKEN: a genuine allow token is signed, then one hex
        character of its signature is flipped. The real Ed25519TokenProvider
        must drop it with a warning, and the identical call must stay
        BLOCKED. A forged approval buys nothing.

Raw host output printed verbatim. Exit 0 only if BOTH denials held.
"""

import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test" / "integration"))
sys.path.insert(0, str(ROOT / "test" / "tools"))

from approval_loop import env_with_ld, run_signed_ed25519_loop  # noqa: E402
from process_witness import raise_with_child_stderr  # noqa: E402
from sign_approval import generate_approval_keypair, sign_approval_token  # noqa: E402


def leg2_tampered() -> bool:
    from test_host_rs import write_config, PUBKEY as CONFIG_PUB  # noqa: E402
    BIN = ROOT / "rust" / "target" / "debug" / "seal-host-rs"
    with tempfile.TemporaryDirectory(prefix="dogfood-tamper-") as td:
        work = Path(td)
        tokens = work / "tokens.ndjson"
        tokens.write_text("", encoding="utf-8")
        trusted = write_config(work, work / "dummy.ndjson")
        priv, pub = generate_approval_keypair()
        proc = subprocess.Popen(
            [str(BIN), "--insecure-development-mode", "--config", str(trusted), "--pubkey", CONFIG_PUB,
             "--channel", "ed25519", "--token-file", str(tokens),
             "--approval-pubkey", pub, "--",
             "python3", str(ROOT / "test" / "integration" / "synthetic_ledger.py")],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env_with_ld())
        try:
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
            except Exception as error:
                raise_with_child_stderr(proc, error)
            m = re.search(r"approval required: ([0-9a-f]{64})", blocked)
            if not m:
                print("LEG 2 BROKEN: no block/target. Raw:", blocked)
                return False
            target = m.group(1)
            print("Leg 2 target:", target)

            genuine = sign_approval_token(priv, target, int(time.time() * 1000),
                                          "tamper-n1", allow=True)
            env_obj = json.loads(genuine)
            sig = env_obj["signature"]
            env_obj["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
            tampered = json.dumps(env_obj, separators=(",", ":"))
            tokens.write_text(tampered + "\n", encoding="utf-8")
            print("Appended TAMPERED token (one signature hex char flipped).")

            proc.stdin.write(call + "\n")
            proc.stdin.flush()
            second = ""
            for _ in range(20):
                line = proc.stdout.readline()
                second += line
                if "approval required:" in line or line.strip():
                    break
                time.sleep(0.05)
            try:
                # communicate() closes stdin itself (sending EOF). Do NOT
                # pre-close it: communicate() flushes stdin internally, so a
                # prior close() raises ValueError and the stderr — which carries
                # the approval_drop warning — would be silently discarded.
                out2, err2 = proc.communicate(timeout=3)
            except Exception:
                proc.kill()
                out2, err2 = "", ""
            combined = second + (out2 or "") + "\n" + (err2 or "")
            print("=" * 72)
            print("LEG 2 RAW (second response + host stderr):")
            print(combined.rstrip())
            print("=" * 72)
            flowed = "SYNTHETIC_LEDGER_ACTION" in combined
            still_blocked = "approval required:" in combined
            # The provider emits an approval_drop / bad_signature warning to the
            # host's stderr when it rejects a tampered signature (providers.rs
            # Ed25519TokenProvider::poll -> main.rs emit_approval_drop_warnings).
            # This is a real, deterministic signal — assert it, don't hope for it.
            warned = "approval_drop" in combined and "bad_signature" in combined
            if flowed:
                print("LEG 2 FAILED: a TAMPERED token flowed. That would be a real bug.")
                return False
            if not still_blocked:
                print("LEG 2 FAILED: expected the identical call to be blocked again.")
                return False
            if not warned:
                print("LEG 2 FAILED: expected an approval_drop/bad_signature warning "
                      "on host stderr; none observed. (call stayed blocked, but the "
                      "demo claims a warning — claim must match reality.)")
                return False
            print("LEG 2 OK: tampered signature dropped with an approval_drop "
                  "(bad_signature) warning; call stayed BLOCKED. Forgery bought nothing.")
            return True
        finally:
            try:
                proc.kill()
            except Exception:
                pass


def main() -> int:
    BIN = ROOT / "rust" / "target" / "debug" / "seal-host-rs"
    if not BIN.exists():
        print(f"seal-host-rs not built at {BIN}. One-time build: bash scripts/build_all.sh")
        return 1

    print("=== LEG 1: signed DECLINE -> explicit refusal ===")
    with tempfile.TemporaryDirectory(prefix="dogfood-decline-") as td:
        obs = run_signed_ed25519_loop(Path(td), allow=False,
                                      tool_name="db.execute",
                                      tool_args={"database": "prod",
                                                 "sql": "drop table users"})
        print("BLOCK (raw):")
        print((obs.get("block_text") or "").rstrip())
        print("AFTER SIGNED DENY (raw stdout+stderr):")
        print(((obs.get("stdout") or "") + "\n" + (obs.get("stderr") or "")).rstrip())
        if not obs.get("refused") or obs.get("flowed"):
            print("LEG 1 FAILED: expected explicit refusal, no flow.")
            return 1
        print("LEG 1 OK: host refused explicitly on the signed decline.")

    print("\n=== LEG 2: TAMPERED signature -> dropped, still blocked ===")
    if not leg2_tampered():
        return 1

    print("\nfail-closed dogfood: SUCCESS (both denials held)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
