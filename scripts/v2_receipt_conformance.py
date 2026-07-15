#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Produce native-host v2 receipts and verify the exact files three ways."""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT.parent
HOST = ROOT / "rust" / "target" / "debug" / "seal-host-rs"
CHECK = SRC / "seal-check" / "test" / "verify-file.cjs"
KIT = SRC / "seal-assurance-kit" / "bin" / "seal"
ACTION = SRC / "seal-verify-action"

sys.path.insert(0, str(ROOT / "test" / "tools"))
from sign_config import generate_keypair, sign_payload  # noqa: E402


def run(command, *, cwd=None, env=None, expect=0):
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True)
    if result.returncode != expect:
        raise RuntimeError(
            f"expected exit {expect}, got {result.returncode}: {' '.join(map(str, command))}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def verify_action(receipt_dir: Path, expect: int, config_pub: str):
    env = os.environ.copy()
    env.update({
        "INPUT_RECEIPTS": "*.json",
        "INPUT_EXPECTED-CONFIG-PUBKEY": config_pub,
        "INPUT_WORKING-DIRECTORY": str(receipt_dir),
        "GITHUB_OUTPUT": str(receipt_dir / "github-output"),
        "GITHUB_STEP_SUMMARY": str(receipt_dir / "github-summary"),
    })
    code = "require('./lib/main.js').run().then(code => process.exit(code))"
    return run(["node", "-e", code], cwd=ACTION, env=env, expect=expect)


def main():
    # Cargo's incremental build keeps this cheap while ensuring the embedded
    # verifier body and producer code are the sources under test.
    run(["cargo", "build"], cwd=ROOT / "rust")

    with tempfile.TemporaryDirectory(prefix="seal-v2-conformance-") as td:
        work = Path(td)
        approvals = work / "approvals.ndjson"
        approvals.write_text("", encoding="utf-8")
        receipts = work / "receipts"
        config_key, config_pub = generate_keypair()
        payload = {
            "epoch": 1,
            "safety": {
                "approval": {"control_file": str(approvals), "ttl_seconds": 120},
                "tools": [{
                    "name": "db.execute",
                    "mode": "guarded",
                    "match": {"type": "contains_any_ci", "arg": "sql", "needles": ["drop"]},
                    "target": [
                        {"literal": "db"}, {"arg": "database"},
                        {"literal": "write"}, {"arg": "sql"},
                    ],
                }],
            },
        }
        trusted = work / "trusted.json"
        trusted.write_text(sign_payload(payload, config_key), encoding="utf-8")

        proc = subprocess.Popen(
            [str(HOST), "--config", str(trusted), "--pubkey", config_pub,
             "--receipt-dir", str(receipts), "--", "/bin/cat"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        arguments = {"database": "prod", "sql": "drop table receipt_sandbox"}

        def call(request_id):
            line = json.dumps({
                "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                "params": {"name": "db.execute", "arguments": arguments},
            }, separators=(",", ":"))
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
            return line, proc.stdout.readline().rstrip("\n")

        _, blocked = call(1)
        match = re.search(r"approval required: ([0-9a-f]{64})", blocked)
        if not match:
            raise RuntimeError(f"first call did not block with an exact target: {blocked}")
        approvals.write_text(json.dumps({"target": match.group(1)}) + "\n", encoding="utf-8")
        allowed_line, allowed = call(2)
        if allowed != allowed_line:
            raise RuntimeError(f"approved call did not forward verbatim: {allowed}")
        proc.stdin.close()
        proc.wait(timeout=10)
        stderr = proc.stderr.read()
        if proc.returncode != 0:
            raise RuntimeError(f"host exited {proc.returncode}: {stderr}")

        produced = sorted(receipts.glob("receipt-*.json"))
        if len(produced) != 2:
            raise RuntimeError(f"expected BLOCK+ALLOW receipts, got {produced}\n{stderr}")

        # The seal-check CLI and the action are authority-aware (tri-state):
        # without the operator pin they exit 3/UNPINNED by design, so the
        # harness supplies the pin it just generated. (This script predated
        # those exits and ran pinless — it could never have passed; found
        # 2026-07-15 while gating the kernel-request-commitment change.)
        for receipt in produced:
            run(["node", str(CHECK), str(receipt),
                 "--expected-config-pubkey", config_pub])
            run(["node", str(KIT), "verify", str(receipt)])
        verify_action(receipts, 0, config_pub)

        tamper_dir = work / "tampered"
        tamper_dir.mkdir()
        tampered = json.loads(produced[0].read_text(encoding="utf-8"))
        tampered["arguments"]["sql"] = "drop table different_target"
        tamper_path = tamper_dir / "tampered.json"
        tamper_path.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")
        run(["node", str(CHECK), str(tamper_path), "--expected-config-pubkey", config_pub], expect=1)
        run(["node", str(KIT), "verify", str(tamper_path)], expect=1)
        verify_action(tamper_dir, 1, config_pub)

        print("PASS native host produced BLOCK+ALLOW v2 receipts")
        print("PASS seal-check, seal verify, and CI action accepted the exact files")
        print("PASS argument tamper failed in all three verifiers")


if __name__ == "__main__":
    main()
