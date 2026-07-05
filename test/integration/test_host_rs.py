#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""E2E for the Rust FFI host (seal-host-rs): all kernels over real MCP stdio,
approval through swappable channels (control-file and Ed25519 token),
A3 replay/TTL enforced.

Requires: cargo build done (rust/target/debug/seal-host-rs), lake build
Ffi:shared done. Ed25519 keys are generated here with the cryptography
package if available; the ed25519 scenarios are skipped (loudly) without it.
"""

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "rust" / "target" / "debug" / "seal-host-rs"

sys.path.insert(0, str(ROOT / "test" / "tools"))
from sign_config import generate_keypair, sign_payload  # noqa: E402
from test_host import safety_section, temporal_section, stable_hash  # noqa: E402

CONFIG_SK, PUBKEY = generate_keypair()


def config_payload(tmp: Path, approval_file: Path) -> dict:
    return {
        "epoch": 1,
        "safety": safety_section(approval_file),
        "temporal": temporal_section(),
        "consensus": {
            "roster": [1, 2, 3],
            "votes_file": str(tmp / "votes.ndjson"),
            "high_stakes": ["payments.send"],
        },
        "convergence": {"tools": [{"tool": "store.update", "op_arg": "op"}]},
        "linear": {
            "grants_file": str(tmp / "grants.ndjson"),
            "tools": [{"tool": "key.use", "cap_arg": "key"}],
        },
        "budget": {"budgets": [{"name": "db-calls", "cap": 2, "tools": ["db.execute"]}]},
    }


def write_config(tmp: Path, approval_file: Path) -> Path:
    payload = config_payload(tmp, approval_file)
    path = tmp / "trusted.json"
    path.write_text(sign_payload(payload, CONFIG_SK), encoding="utf-8")
    return path


def write_unsigned_config(tmp: Path, approval_file: Path) -> Path:
    payload = json.dumps(config_payload(tmp, approval_file), separators=(",", ":"))
    path = tmp / "trusted-unsigned.json"
    path.write_text(json.dumps({"payload": payload}, separators=(",", ":")), encoding="utf-8")
    return path


def rpc(mid, name, arguments):
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call", "params": {"name": name, "arguments": arguments}}


def spawn(config: Path, extra_args=()):
    return subprocess.Popen(
        [str(BIN), "--config", str(config), "--pubkey", PUBKEY, *extra_args,
         "--", "python3", str(ROOT / "test" / "integration" / "mock_mcp_server.py")],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def call(proc, mid, name, arguments):
    proc.stdin.write(json.dumps(rpc(mid, name, arguments), separators=(",", ":")) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


DB_TARGET = stable_hash(["db.execute", "db", "prod", "write", "drop table users"])
DESTRUCTIVE = {"database": "prod", "sql": "drop table users"}


def test_file_channel_all_kernels():
    """Control-file channel; exercises S, T-noop, B and convergence V."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        approvals = tmp / "approvals.ndjson"
        approvals.write_text("", encoding="utf-8")
        config = write_config(tmp, approvals)
        proc = spawn(config)

        # Passthrough of non-tools/call.
        proc.stdin.write('{"jsonrpc":"2.0","id":0,"method":"initialize"}\n')
        proc.stdin.flush()
        assert json.loads(proc.stdout.readline())["method"] == "initialize"

        # S: guarded without approval -> blocked.
        r = call(proc, 1, "db.execute", DESTRUCTIVE)
        assert r["result"]["isError"] is True

        # S: approve -> allowed once -> consumed.
        approvals.write_text(json.dumps({"target": DB_TARGET}) + "\n", encoding="utf-8")
        r = call(proc, 2, "db.execute", DESTRUCTIVE)
        assert r["result"]["isError"] is False
        r = call(proc, 3, "db.execute", DESTRUCTIVE)
        assert r["result"]["isError"] is True

        # B: second executed call fits cap 2; third (fresh approval) over budget.
        with approvals.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"target": DB_TARGET}) + "\n")
        r = call(proc, 4, "db.execute", DESTRUCTIVE)
        assert r["result"]["isError"] is False
        with approvals.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"target": DB_TARGET}) + "\n")
        r = call(proc, 5, "db.execute", DESTRUCTIVE)
        assert r["result"]["isError"] is True
        assert "over budget" in r["result"]["content"][0]["text"]

        # V: convergent op admitted, LWW refused (store.update approved).
        store_target = stable_hash(["store.update", "store"])
        with approvals.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"target": store_target}) + "\n")
        r = call(proc, 6, "store.update", {"op": "orset.add"})
        assert r["result"]["isError"] is False
        with approvals.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"target": store_target}) + "\n")
        r = call(proc, 7, "store.update", {"op": "assign"})
        assert r["result"]["isError"] is True

        # Non-canonical tools/call (escape) is mediated, not refused: here it
        # denies as unmatched policy (no destructive needle), not a parser veto.
        proc.stdin.write('{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"db.execute","arguments":{"sql":"a\\tb"}}}\n')
        proc.stdin.flush()
        r = json.loads(proc.stdout.readline())
        assert r["result"]["isError"] is True

        proc.stdin.close()
        proc.wait(timeout=10)


def make_ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None
    sk = Ed25519PrivateKey.generate()
    pk_hex = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return sk, pk_hex


def sign_token(sk, target, issued_at, nonce):
    payload = json.dumps({"target": target, "issuedAt": issued_at, "nonce": nonce},
                         separators=(",", ":"))
    sig = sk.sign(payload.encode()).hex()
    return json.dumps({"payload": payload, "signature": sig}, separators=(",", ":"))


def test_ed25519_channel_and_a3():
    keys = make_ed25519()
    if keys is None:
        print("SKIP: python cryptography not available; ed25519 e2e not run", file=sys.stderr)
        return
    sk, pk_hex = keys
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        approvals = tmp / "approvals.ndjson"
        approvals.write_text("", encoding="utf-8")
        tokens = tmp / "tokens.ndjson"
        tokens.write_text("", encoding="utf-8")
        config = write_config(tmp, approvals)
        proc = spawn(config, ("--channel", "ed25519", "--token-file", str(tokens),
                              "--approval-pubkey", pk_hex))

        now = int(time.time() * 1000)
        # Valid signed token approves exactly one call.
        tokens.write_text(sign_token(sk, DB_TARGET, now, "nonce-1") + "\n", encoding="utf-8")
        r = call(proc, 1, "db.execute", DESTRUCTIVE)
        assert r["result"]["isError"] is False

        # A3 replay: same nonce re-minted -> rejected, call blocked.
        with tokens.open("a", encoding="utf-8") as f:
            f.write(sign_token(sk, DB_TARGET, int(time.time() * 1000), "nonce-1") + "\n")
        r = call(proc, 2, "db.execute", DESTRUCTIVE)
        assert r["result"]["isError"] is True

        # A3 TTL: token issued far in the past -> rejected.
        with tokens.open("a", encoding="utf-8") as f:
            f.write(sign_token(sk, DB_TARGET, now - 10_000_000, "nonce-2") + "\n")
        r = call(proc, 3, "db.execute", DESTRUCTIVE)
        assert r["result"]["isError"] is True

        # Fresh nonce works again (proves the channel, not the cap: budget
        # cap 2 would deny a THIRD execution; this is only the second).
        with tokens.open("a", encoding="utf-8") as f:
            f.write(sign_token(sk, DB_TARGET, int(time.time() * 1000), "nonce-3") + "\n")
        r = call(proc, 4, "db.execute", DESTRUCTIVE)
        assert r["result"]["isError"] is False

        _, err = proc.communicate(timeout=10)
        assert "replayed_nonce" in err, "A3 must log the replay drop"
        assert "expired" in err, "A3 must log the TTL drop"


def test_ed25519_requires_signed_config_and_key_separation():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        approvals = tmp / "approvals.ndjson"
        approvals.write_text("", encoding="utf-8")
        tokens = tmp / "tokens.ndjson"
        tokens.write_text("", encoding="utf-8")

        unsigned = write_unsigned_config(tmp, approvals)
        proc = spawn(unsigned, ("--channel", "ed25519", "--token-file", str(tokens),
                                "--approval-pubkey", "00" * 32))
        out, err = proc.communicate(timeout=10)
        assert proc.returncode == 3
        assert out == ""
        assert "trusted config rejected" in err

        signed = write_config(tmp, approvals)
        proc = spawn(signed, ("--channel", "ed25519", "--token-file", str(tokens),
                              "--approval-pubkey", PUBKEY))
        out, err = proc.communicate(timeout=10)
        assert proc.returncode == 3
        assert out == ""
        assert "config signing key must differ from approval signing key" in err


def main() -> int:
    assert BIN.exists(), f"build first: cargo build (missing {BIN})"
    test_file_channel_all_kernels()
    test_ed25519_channel_and_a3()
    test_ed25519_requires_signed_config_and_key_separation()
    print("all rust-host e2e tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
