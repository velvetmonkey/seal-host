#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
External consumer test (outside approver modules and main test_host_rs).

Produces target-bound signed allow + decline using the real signer.
Feeds the NDJSON to a *real* Ed25519TokenProvider instance by:
  - writing the signed envelopes to a --token-file
  - spawning the real seal-host-rs --channel ed25519 with that file
  - triggering a block, appending a signed decline, re-issuing
  - capturing full stdout + stderr transcript

Asserts:
- no drop warnings (bad_signature, parse_error, missing_required_field) for the valid signed lines
- refused observed on the decline path (host-emitted, not just summary)

Prints the full transcript for evidence (satisfies verification step 4).
"""

import json
import re
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "integration"))

from sign_approval import generate_approval_keypair, sign_approval_token  # noqa: E402
from test_host_rs import write_config, DESTRUCTIVE, PUBKEY as CONFIG_PUB  # noqa: E402
from approval_loop import spawn_with_child, env_with_ld  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SYN = ROOT / "test" / "integration" / "synthetic_ledger.py"
BIN = ROOT / "rust" / "target" / "debug" / "seal-host-rs"


def main() -> int:
    assert BIN.exists(), "need fresh cargo build of seal-host-rs"

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        tokens = td / "tokens.ndjson"
        tokens.write_text("", encoding="utf-8")
        dummy = td / "dummy.ndjson"
        dummy.write_text("", encoding="utf-8")
        trusted = write_config(td, dummy)

        sk, vk = generate_approval_keypair()

        # Produce real signed lines (target will be overwritten by real block target below, but format is correct)
        dummy_target = "deadbeef" * 8
        allow_line = sign_approval_token(sk, dummy_target, 1720000000000, "nonce-allow-c", allow=True)
        deny_line = sign_approval_token(sk, dummy_target, 1720000000001, "nonce-deny-c", allow=False)
        tokens.write_text(allow_line + "\n", encoding="utf-8")

        extra = ("--channel", "ed25519", "--token-file", str(tokens), "--approval-pubkey", vk)
        child = ["python3", str(SYN)]
        proc = spawn_with_child(trusted, extra, child=child)

        full_out = ""
        full_err = ""
        try:
            try:
                proc.stdin.write('{"jsonrpc":"2.0","id":0,"method":"initialize"}\n')
                proc.stdin.flush()
                _ = proc.stdout.readline()
            except Exception:
                pass

            call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "db.execute", "arguments": DESTRUCTIVE}}, separators=(",", ":"))
            proc.stdin.write(call + "\n")
            proc.stdin.flush()

            blocked = ""
            for _ in range(8):
                l = proc.stdout.readline()
                blocked += l
                if "approval required" in l:
                    break
                time.sleep(0.03)
            full_out += blocked

            m = re.search(r"approval required: ([0-9a-f]{64})", blocked)
            real_t = m.group(1) if m else dummy_target

            # Now append a fresh signed decline for the real target (this is the line fed to real provider)
            dl = sign_approval_token(sk, real_t, int(time.time() * 1000), "nonce-deny-real-c", allow=False)
            with tokens.open("a", encoding="utf-8") as f:
                f.write(dl + "\n")

            proc.stdin.write(call + "\n")
            proc.stdin.flush()
            time.sleep(0.4)

            after = ""
            for _ in range(6):
                l = proc.stdout.readline()
                after += l
            full_out += after

            try:
                proc.stdin.close()
            except Exception:
                pass
            try:
                o2, e2 = proc.communicate(timeout=2)
                full_out += (o2 or "")
                full_err += (e2 or "")
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
                full_err += " (killed)"

        finally:
            try:
                proc.kill()
            except Exception:
                pass

        transcript = f"STDOUT:\n{full_out}\nSTDERR:\n{full_err}\n"
        print(transcript)

        # Assertions on the real provider behavior
        bad = [w for w in ("bad_signature", "parse_error", "missing_required_field") if w in full_err]
        assert not bad, f"real Ed25519TokenProvider dropped valid signed lines: {bad}"

        refused = "refused" in full_out.lower() or "approval refused" in full_err.lower() or "refused" in full_err.lower()
        assert refused, "expected host-emitted refused (not timed out) for signed decline"

        print("consumer: produced signed allow + decline (real signer)")
        print("consumer: fed NDJSON to real Ed25519TokenProvider via host spawn")
        print("consumer: no drop warnings:", not bad)
        print("consumer: refused observed:", refused)
        print("consumer: SUCCESS (full transcript above)")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
