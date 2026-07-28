#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""E2E for the Rust FFI host (seal-host-rs): all kernels over real MCP stdio,
approval through swappable channels (control-file and Ed25519 token),
A3 replay/TTL enforced.

Requires: cargo build done (rust/target/debug/seal-host-rs), lake build
Ffi:shared done. Ed25519 keys and ApprovalRecord v2 fixtures are minted
through test/tools/sign_approval.py.
"""

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "rust" / "target" / "debug" / "seal-host-rs"

sys.path.insert(0, str(ROOT / "test" / "tools"))
from process_witness import raise_with_child_stderr  # noqa: E402
from sign_approval import (  # noqa: E402
    generate_approval_keypair,
    sign_approval_token,
    sign_approval_v2_token,
)
from sign_config import generate_keypair, sign_payload  # noqa: E402
from test_host import extract_approval_target, safety_section, temporal_section  # noqa: E402

CONFIG_SK, PUBKEY = generate_keypair()
APPROVAL_RENDERER_NAME = "seal-host-integration-raw-mcp-frame"
APPROVAL_RENDERER_VERSION = "1.0.0"
APPROVAL_RENDERER_MANIFEST = (
    b'{"name":"seal-host-integration-raw-mcp-frame","version":"1.0.0",'
    b'"format":"heading, target line, then exact UTF-8 MCP request frame including delimiter"}'
)
APPROVAL_RENDERER_MANIFEST_SHA256 = hashlib.sha256(
    APPROVAL_RENDERER_MANIFEST
).hexdigest()


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


def spawn(config: Path, extra_args=(), child=None):
    """Spawn the real rust host. child: list for the command after -- (defaults to mock)."""
    if child is None:
        child = ["python3", str(ROOT / "test" / "integration" / "mock_mcp_server.py")]
    return subprocess.Popen(
        [str(BIN), "--insecure-development-mode", "--config", str(config), "--pubkey", PUBKEY, *extra_args,
         "--", *child],
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


def framed_call(mid, name, arguments) -> bytes:
    return (json.dumps(rpc(mid, name, arguments), separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def send_frame(proc, frame: bytes):
    proc.stdin.write(frame.decode("utf-8"))
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def mint_v2_approval(
    token_file: Path,
    private_key: str,
    blocked_response: dict,
    frame: bytes,
    nonce: str,
    *,
    authorized_at: int | None = None,
) -> str:
    """Sign the kernel target for the exact blocked request frame."""
    target = extract_approval_target(blocked_response)
    shown = (
        "Seal host integration approval\n"
        f"target: {target}\n"
        "exact MCP request frame (including delimiter):\n"
    ).encode("utf-8") + frame
    issued = int(time.time() * 1000) if authorized_at is None else authorized_at
    line = sign_approval_v2_token(
        private_key,
        target=target,
        authorized_at=issued,
        expiry=issued + 120_000,
        nonce=nonce,
        session=f"test-host-rs/{uuid.uuid4().hex}",
        framed_bytes=frame,
        shown_bytes=shown,
        renderer_name=APPROVAL_RENDERER_NAME,
        renderer_version=APPROVAL_RENDERER_VERSION,
        renderer_manifest_sha256=APPROVAL_RENDERER_MANIFEST_SHA256,
        approver="seal-host integration test",
    )
    with token_file.open("a", encoding="utf-8") as stream:
        stream.write(line + "\n")
    return target


DESTRUCTIVE = {"database": "prod", "sql": "drop table users"}


def test_signed_channel_all_kernels():
    """Signed v2 channel; exercises S, T-noop, B and convergence V."""
    approval_sk, approval_pub = generate_approval_keypair()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        approvals = tmp / "approvals.ndjson"
        approvals.write_text("", encoding="utf-8")
        tokens = tmp / "tokens.ndjson"
        tokens.write_text("", encoding="utf-8")
        config = write_config(tmp, approvals)
        proc = spawn(
            config,
            (
                "--channel",
                "ed25519",
                "--token-file",
                str(tokens),
                "--approval-pubkey",
                approval_pub,
            ),
        )

        # Passthrough of non-tools/call.
        try:
            proc.stdin.write('{"jsonrpc":"2.0","id":0,"method":"initialize"}\n')
            proc.stdin.flush()
            assert json.loads(proc.stdout.readline())["method"] == "initialize"
        except Exception as error:
            raise_with_child_stderr(proc, error)

        # S: guarded without approval -> blocked.
        db_first = framed_call(1, "db.execute", DESTRUCTIVE)
        r = send_frame(proc, db_first)
        assert r["result"]["isError"] is True

        # S: approve -> allowed once -> consumed.
        mint_v2_approval(tokens, approval_sk, r, db_first, "all-kernels-db-first")
        r = send_frame(proc, db_first)
        assert r["result"]["isError"] is False
        r = send_frame(proc, db_first)
        assert r["result"]["isError"] is True

        # B: second executed call fits cap 2; third (fresh approval) over budget.
        db_second = framed_call(2, "db.execute", DESTRUCTIVE)
        r = send_frame(proc, db_second)
        assert r["result"]["isError"] is True
        mint_v2_approval(tokens, approval_sk, r, db_second, "all-kernels-db-second")
        r = send_frame(proc, db_second)
        assert r["result"]["isError"] is False

        db_third = framed_call(3, "db.execute", DESTRUCTIVE)
        r = send_frame(proc, db_third)
        assert r["result"]["isError"] is True
        mint_v2_approval(tokens, approval_sk, r, db_third, "all-kernels-db-third")
        r = send_frame(proc, db_third)
        assert r["result"]["isError"] is True
        assert "over budget" in r["result"]["content"][0]["text"]

        # V: convergent op admitted, LWW refused (store.update approved).
        convergent_update = {"op": "orset.add"}
        divergent_update = {"op": "assign"}
        store_add = framed_call(4, "store.update", convergent_update)
        r = send_frame(proc, store_add)
        assert r["result"]["isError"] is True
        mint_v2_approval(tokens, approval_sk, r, store_add, "all-kernels-store-add")
        r = send_frame(proc, store_add)
        assert r["result"]["isError"] is False

        store_assign = framed_call(5, "store.update", divergent_update)
        r = send_frame(proc, store_assign)
        assert r["result"]["isError"] is True
        mint_v2_approval(tokens, approval_sk, r, store_assign, "all-kernels-store-assign")
        r = send_frame(proc, store_assign)
        assert r["result"]["isError"] is True

        # Non-canonical tools/call (escape) is mediated, not refused: here it
        # denies as unmatched policy (no destructive needle), not a parser veto.
        proc.stdin.write('{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"db.execute","arguments":{"sql":"a\\tb"}}}\n')
        proc.stdin.flush()
        r = json.loads(proc.stdout.readline())
        assert r["result"]["isError"] is True

        proc.stdin.close()
        proc.wait(timeout=10)


def test_ed25519_channel_and_a3():
    sk_hex, pk_hex = generate_approval_keypair()
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
        first = framed_call(1, "db.execute", DESTRUCTIVE)
        blocked = send_frame(proc, first)
        assert blocked["result"]["isError"] is True

        # Valid signed token approves exactly one call.
        mint_v2_approval(
            tokens, sk_hex, blocked, first, "nonce-1", authorized_at=now
        )
        r = send_frame(proc, first)
        assert r["result"]["isError"] is False

        # A3 replay: same nonce re-minted -> rejected, call blocked.
        replay = framed_call(2, "db.execute", DESTRUCTIVE)
        r = send_frame(proc, replay)
        assert r["result"]["isError"] is True
        mint_v2_approval(tokens, sk_hex, r, replay, "nonce-1")
        r = send_frame(proc, replay)
        assert r["result"]["isError"] is True

        # A3 TTL: token issued far in the past -> rejected.
        expired = framed_call(3, "db.execute", DESTRUCTIVE)
        r = send_frame(proc, expired)
        assert r["result"]["isError"] is True
        mint_v2_approval(
            tokens, sk_hex, r, expired, "nonce-2", authorized_at=now - 10_000_000
        )
        r = send_frame(proc, expired)
        assert r["result"]["isError"] is True

        # Fresh nonce works again (proves the channel, not the cap: budget
        # cap 2 would deny a THIRD execution; this is only the second).
        fresh = framed_call(4, "db.execute", DESTRUCTIVE)
        r = send_frame(proc, fresh)
        assert r["result"]["isError"] is True
        mint_v2_approval(tokens, sk_hex, r, fresh, "nonce-3")
        r = send_frame(proc, fresh)
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


def test_ed25519_signed_decline_produces_refused():
    """Real Ed25519TokenProvider + main short-circuit for explicit signed decline.
    After a block, a signed decline for the target must produce 'refused' response
    and 'approval refused' / 'refused' in audit (not a plain timeout or generic deny).
    """
    sk_hex, pk_hex = generate_approval_keypair()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        approvals = tmp / "approvals.ndjson"; approvals.write_text("", encoding="utf-8")
        tokens = tmp / "tokens.ndjson"; tokens.write_text("", encoding="utf-8")
        config = write_config(tmp, approvals)
        proc = spawn(config, ("--channel", "ed25519", "--token-file", str(tokens), "--approval-pubkey", pk_hex))
        r = call(proc, 99, "db.execute", DESTRUCTIVE)
        assert r["result"]["isError"] is True
        t = None
        for c in r.get("result", {}).get("content", []):
            mm = re.search(r"approval required: ([0-9a-f]{64})", c.get("text", ""))
            if mm: t = mm.group(1)
        assert t is not None, f"kernel block response did not contain an approval target: {r}"
        now = int(time.time() * 1000)
        dl = sign_approval_token(sk_hex, t, now, "decline-e2e-1", allow=False)
        with tokens.open("a", encoding="utf-8") as f:
            f.write(dl + "\n")
        r2 = call(proc, 100, "db.execute", DESTRUCTIVE)
        txt = ""
        for c in r2.get("result", {}).get("content", []):
            txt += c.get("text", "")
        assert "refused" in txt.lower() or "refused" in str(r2).lower(), f"decline must produce refused: {r2}"
        _, e = proc.communicate(timeout=5)
        assert "refused" in (e or "").lower() or "approval refused" in (e or "").lower()


def test_control_file_plain_decline_produces_refused():
    """Control-file channel + real providers decline support + main short-circuit.
    After a real block, write a plain decline record (with decision:"deny").
    The host must short-circuit to explicit refused (not timed out/generic deny).
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        approvals = tmp / "approvals.ndjson"
        approvals.write_text("", encoding="utf-8")
        config = write_config(tmp, approvals)
        # Use synthetic child so we have a real observable child (optional for this test)
        child = ["python3", str(ROOT / "test" / "integration" / "synthetic_ledger.py")]
        proc = spawn(config, child=child)
        r = call(proc, 300, "db.execute", DESTRUCTIVE)
        assert r["result"]["isError"] is True
        t = None
        for c in r.get("result", {}).get("content", []):
            mm = re.search(r"approval required: ([0-9a-f]{64})", c.get("text", ""))
            if mm:
                t = mm.group(1)
                break
        assert t is not None, f"kernel block response did not contain an approval target: {r}"
        # plain decline line supported by ControlFileProvider
        dl = json.dumps({"target": t, "issuedAt": int(time.time() * 1000), "nonce": "plain-decline-cf-1", "decision": "deny"}, separators=(",", ":"))
        with approvals.open("a", encoding="utf-8") as f:
            f.write(dl + "\n")
        r2 = call(proc, 301, "db.execute", DESTRUCTIVE)
        txt = ""
        for c in r2.get("result", {}).get("content", []):
            txt += c.get("text", "")
        assert "refused" in txt.lower() or "refused" in str(r2).lower(), f"control decline must produce refused: {r2}"
        _, e = proc.communicate(timeout=5)
        assert "refused" in (e or "").lower() or "approval refused" in (e or "").lower()


def main() -> int:
    assert BIN.exists(), f"build first: cargo build (missing {BIN})"
    test_signed_channel_all_kernels()
    test_ed25519_channel_and_a3()
    test_ed25519_requires_signed_config_and_key_separation()
    test_ed25519_signed_decline_produces_refused()
    test_control_file_plain_decline_produces_refused()
    print("all rust-host e2e tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
