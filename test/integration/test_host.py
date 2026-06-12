#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Integration regression suite for the seal-host binary.

Ported from mcp-seal test/integration/test_seal.py: identical policy content
(nested as the `safety` section of a signed trusted config), identical case
set and expected allow/block outcomes, plus host-specific cases: a
non-canonical tools/call is blocked, and a tampered config refuses to start.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PUBKEY = "test-pk"

sys.path.insert(0, str(ROOT / "test" / "tools"))
from sign_config import sign_payload  # noqa: E402


def stable_hash(parts) -> int:
    """Mirror of Seal.Hash.stableHashParts (FNV-style over '|'-joined parts)."""
    acc = 14695981039346656037
    for ch in "|".join(parts):
        acc = (acc * 1099511628211 + ord(ch)) % 2**64
    return acc


def safety_section(approval_file: Path) -> dict:
    return {
        "approval": {"control_file": str(approval_file), "ttl_seconds": 120},
        "tools": [
            {
                "name": "db.execute",
                "mode": "guarded",
                "match": {
                    "type": "contains_any_ci",
                    "arg": "sql",
                    "needles": ["drop", "delete", "truncate"],
                },
                "target": [
                    {"literal": "db"},
                    {"arg": "database"},
                    {"literal": "write"},
                    {"arg": "sql"},
                ],
            },
            {
                "name": "session.revoke",
                "mode": "guarded",
                "match": {"type": "always"},
                "target": [{"literal": "revoke"}],
            },
            {"name": "approve", "mode": "deny", "match": {"type": "always"}, "target": []},
        ],
    }


def temporal_section() -> dict:
    return {
        "policies": [
            {
                "name": "no-destructive-after-revoke",
                "type": "no_after",
                "trigger": ["session.revoke"],
                "forbidden": ["db.execute"],
            }
        ]
    }


def write_config(tmp: Path, approval_file: Path, epoch: int = 1, tamper: bool = False) -> Path:
    payload = {
        "epoch": epoch,
        "safety": safety_section(approval_file),
        "temporal": temporal_section(),
    }
    envelope = sign_payload(payload, PUBKEY)
    if tamper:
        env = json.loads(envelope)
        env["payload"] = env["payload"].replace('"ttl_seconds":120', '"ttl_seconds":999')
        envelope = json.dumps(env, separators=(",", ":"))
    path = tmp / "trusted.json"
    path.write_text(envelope, encoding="utf-8")
    return path


def rpc(mid, name, arguments):
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call", "params": {"name": name, "arguments": arguments}}


def spawn(config: Path):
    return subprocess.Popen(
        [
            str(ROOT / ".lake" / "build" / "bin" / "seal-host"),
            "--config",
            str(config),
            "--pubkey",
            PUBKEY,
            "--",
            "python3",
            str(ROOT / "test" / "integration" / "mock_mcp_server.py"),
        ],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def run_case(messages, approval_records=(), raw_lines=None):
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        approvals = tmp / "approvals.ndjson"
        approvals.write_text("".join(json.dumps(r) + "\n" for r in approval_records), encoding="utf-8")
        config = write_config(tmp, approvals)
        proc = spawn(config)
        assert proc.stdin is not None
        assert proc.stdout is not None
        lines = []
        wire = raw_lines if raw_lines is not None else [
            json.dumps(m, separators=(",", ":")) for m in messages
        ]
        for line in wire:
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
            lines.append(json.loads(proc.stdout.readline()))
        proc.stdin.close()
        proc.wait(timeout=5)
        return lines


def main() -> int:
    # 1. Guarded destructive call without approval -> blocked.
    blocked = run_case([rpc(1, "db.execute", {"database": "prod", "sql": "drop table users"})])
    assert blocked[0]["result"]["isError"] is True
    assert "approval required" in blocked[0]["result"]["content"][0]["text"]

    # 2. Approval allows exactly once; replay is consumed -> blocked.
    target = 7653913048106253087
    approved = run_case(
        [
            rpc(1, "db.execute", {"database": "prod", "sql": "drop table users"}),
            rpc(2, "db.execute", {"database": "prod", "sql": "drop table users"}),
        ],
        approval_records=[{"target": target}],
    )
    assert approved[0]["result"]["isError"] is False
    assert approved[1]["result"]["isError"] is True

    # 3. Agent cannot self-approve: `approve` is flat-denied, and the guarded
    #    call still blocks.
    self_approval = run_case(
        [
            rpc(1, "approve", {"target": target}),
            rpc(2, "db.execute", {"database": "prod", "sql": "drop table users"}),
        ]
    )
    assert self_approval[0]["result"]["isError"] is True
    assert self_approval[1]["result"]["isError"] is True

    # 4. Host-specific: a tools/call Lean.Json accepts but the SealV2 canonical
    #    parser rejects (escape sequence) is blocked, fail-closed.
    malformed = run_case(
        [],
        raw_lines=[
            '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"db.execute","arguments":{"sql":"a\\tb"}}}'
        ],
    )
    assert malformed[0]["result"]["isError"] is True

    # 5. Temporal kernel T: no destructive call after revoke, even with a
    #    fresh, valid approval (S allows; T denies; AND is fail-closed).
    db_target = stable_hash(["db.execute", "db", "prod", "write", "drop table users"])
    assert db_target == target, "python stable_hash drifted from Seal.Hash"
    revoke_target = stable_hash(["session.revoke", "revoke"])
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        approvals = tmp / "approvals.ndjson"
        approvals.write_text(json.dumps({"target": db_target}) + "\n", encoding="utf-8")
        config = write_config(tmp, approvals)
        proc = spawn(config)
        assert proc.stdin is not None and proc.stdout is not None

        def call(mid, name, arguments):
            proc.stdin.write(json.dumps(rpc(mid, name, arguments), separators=(",", ":")) + "\n")
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())

        destructive = {"database": "prod", "sql": "drop table users"}
        # Approved destructive call before revoke: allowed.
        r1 = call(1, "db.execute", destructive)
        assert r1["result"]["isError"] is False
        # Approved revoke: allowed; T records the trigger.
        with approvals.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"target": revoke_target}) + "\n")
        r2 = call(2, "session.revoke", {})
        assert r2["result"]["isError"] is False
        # Fresh approval, but destructive-after-revoke: T must deny.
        with approvals.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"target": db_target}) + "\n")
        r3 = call(3, "db.execute", destructive)
        assert r3["result"]["isError"] is True
        assert "temporal policy violated" in r3["result"]["content"][0]["text"]
        proc.stdin.close()
        proc.wait(timeout=5)

    # 6. Host-specific: tampered config -> startup refusal, nothing mediated.
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        approvals = tmp / "approvals.ndjson"
        approvals.write_text("", encoding="utf-8")
        config = write_config(tmp, approvals, tamper=True)
        proc = spawn(config)
        out, err = proc.communicate(
            json.dumps(rpc(1, "db.execute", {"database": "prod", "sql": "drop table users"}), separators=(",", ":")) + "\n",
            timeout=5,
        )
        assert proc.returncode == 3, f"expected startup refusal, got rc={proc.returncode}"
        assert out == "", "tampered config must mediate nothing"
        assert "trusted config rejected" in err

    print("all integration tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
