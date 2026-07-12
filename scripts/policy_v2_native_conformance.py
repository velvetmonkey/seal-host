#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise policy-v2 through the real native host and receipt producer.

This is the producer-side promotion gate. It intentionally does not claim
public-wasm parity; `scripts/v2_receipt_conformance.py` remains the three-
verifier gate once the public wasm is rebuilt from the promoted revision.
"""

import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "rust" / "target" / "debug" / "seal-host-rs"

sys.path.insert(0, str(ROOT / "test" / "tools"))
from sign_config import generate_keypair, sign_payload  # noqa: E402


def compact(value) -> str:
    return json.dumps(value, separators=(",", ":"))


def lean_canonical(value) -> str:
    # Lean.Json objects are RBMaps; `Json.compress` emits keys in lexical order.
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def target(parts: list[str]) -> str:
    preimage = "".join(f"{len(part)}:{part}" for part in parts)
    return hashlib.sha256(preimage.encode()).hexdigest()


def main() -> int:
    if not HOST.is_file():
        raise RuntimeError(f"host binary missing: {HOST}")

    with tempfile.TemporaryDirectory(prefix="seal-policy-v2-native-") as td:
        work = Path(td)
        approvals = work / "approvals.ndjson"
        approvals.write_text("", encoding="utf-8")
        receipts = work / "receipts"
        private, public = generate_keypair()
        payload = {
            "epoch": 1,
            "server": "conformance-server",
            "safety": {
                "approval": {"control_file": str(approvals), "ttl_seconds": 120},
                "tools": [
                    {
                        "name": "fs.call",
                        "mode": "allow",
                        "match": {
                            "type": "all",
                            "matches": [
                                {"type": "equals", "arg": "operation", "value": "read"},
                                {"type": "starts_with", "arg": "path", "value": "/safe/"},
                            ],
                        },
                    },
                    {
                        "name": "fs.call",
                        "mode": "guard",
                        "match": {"type": "equals", "arg": "operation", "value": "write"},
                        "target": [{"full_arguments": True}],
                    },
                    {
                        "name": "fs.call",
                        "mode": "deny",
                        "match": {"type": "starts_with", "arg": "path", "value": "/safe/secrets/"},
                    },
                ],
            },
        }
        trusted = work / "trusted.json"
        trusted.write_text(sign_payload(payload, private), encoding="utf-8")

        proc = subprocess.Popen(
            [
                str(HOST), "--config", str(trusted), "--pubkey", public,
                "--receipt-dir", str(receipts), "--", "/bin/cat",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        def call(request_id: int, arguments: dict) -> tuple[str, str]:
            line = compact({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": "fs.call", "arguments": arguments},
            })
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
            return line, proc.stdout.readline().rstrip("\n")

        safe = {"operation": "read", "path": "/safe/readme.txt"}
        line, response = call(1, safe)
        if response == "":
            proc.stdin.close()
            proc.wait(timeout=10)
            raise RuntimeError(
                f"host ended before first response (exit {proc.returncode}): {proc.stderr.read()}"
            )
        assert response == line, f"conditional explicit allow did not forward: {response}"

        _, denied = call(2, {"operation": "read", "path": "/other/readme.txt"})
        assert "no matching policy rule" in denied, denied

        secret = {"operation": "read", "path": "/safe/secrets/key"}
        _, denied = call(3, secret)
        assert "flat deny" in denied, denied

        write_args = {"operation": "write", "path": "/safe/output.txt", "content": "one"}
        _, blocked = call(4, write_args)
        found = re.search(r"approval required: ([0-9a-f]{64})", blocked)
        assert found, blocked
        expected = target(["conformance-server", "fs.call", lean_canonical(write_args)])
        assert found.group(1) == expected, (found.group(1), expected)
        approvals.write_text(compact({"target": expected}) + "\n", encoding="utf-8")

        changed = {**write_args, "content": "two"}
        _, mismatch = call(5, changed)
        assert "approval required" in mismatch, mismatch

        line, response = call(6, write_args)
        assert response == line, f"exact approved call did not forward: {response}"

        _, replay = call(7, write_args)
        assert "approval required" in replay, replay

        proc.stdin.close()
        proc.wait(timeout=10)
        stderr = proc.stderr.read()
        if proc.returncode != 0:
            raise RuntimeError(f"host exited {proc.returncode}: {stderr}")

        produced = sorted(receipts.glob("receipt-*.json"))
        assert len(produced) == 7, f"expected seven decision receipts: {produced}\n{stderr}"
        records = [json.loads(path.read_text(encoding="utf-8")) for path in produced]
        explicit = [r for r in records if r.get("authorization") == "explicit_policy_allow"]
        approved = [r for r in records if r.get("authorization") == "approval"]
        assert len(explicit) == 1 and explicit[0]["verdict"] == "ALLOW"
        assert "approval" not in explicit[0]
        assert len(approved) == 1 and approved[0]["verdict"] == "ALLOW"
        assert approved[0]["approval"]["policy_hash"]

    print("PASS policy-v2 conditional allow/default-deny/deny precedence through native host")
    print("PASS server+tool+full-arguments target, mismatch rejection, and one-shot replay")
    print("PASS every decision emitted v2; ALLOW authorization origin is explicit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
