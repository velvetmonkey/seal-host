#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""G7 — end-to-end verified-mediation demo.

Part A drives the full Rust host (all seven kernels, live audit certs) over
real MCP stdio against a real tool server, demonstrating the six blocks:

  S  poisoned-source destructive call blocked (no approval)
  T  out-of-order replay blocked (approved destructive call AFTER revoke)
  C  multi-party action gated on quorum (denied at 1-of-3, ratified at 2-of-3)
  V  divergent write refused (LWW assign), convergent op admitted
  B  over-budget call denied (cap on executed db calls)
  HU human approval (Ed25519-signed token back-channel) unlocks a legit retry

Part B puts the whole host in front of a REAL LangGraph agent: canary's
offline P3 compliance pipeline, with SEAL_BIN pointed at the seal-host shim,
so every vault write the agent makes is mediated by the verified host.

Reproducible and offline: mock MCP server for Part A, canary's frozen
fixtures for Part B, no API keys. Output: /tmp/seal-host-g7/G7-REPORT.md.
"""

import json
import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test" / "tools"))
sys.path.insert(0, str(ROOT / "test" / "integration"))
from sign_approval import (  # noqa: E402
    generate_approval_keypair,
    sign_approval_v2_token,
)
from sign_config import generate_keypair, public_key_hex_from_private, sign_payload  # noqa: E402

WORK = Path("/tmp/seal-host-g7")
CONFIG_SK = os.environ.get("SEAL_CONFIG_SIGNING_KEY_HEX")
if CONFIG_SK:
    PUBKEY = public_key_hex_from_private(CONFIG_SK)
else:
    CONFIG_SK, PUBKEY = generate_keypair()
BIN = ROOT / "rust" / "target" / "debug" / "seal-host-rs"
MOCK = ROOT / "test" / "integration" / "mock_mcp_server.py"
CANARY = Path(os.environ.get("CANARY_ROOT", Path(__file__).resolve().parents[2] / "canary"))

REPORT: list[str] = []
AUDIT: list[str] = []
APPROVAL_RENDERER_NAME = "seal-demo-raw-mcp-frame"
APPROVAL_RENDERER_VERSION = "1.0.0"
APPROVAL_RENDERER_MANIFEST = (
    b'{"name":"seal-demo-raw-mcp-frame","version":"1.0.0",'
    b'"format":"heading, target line, then exact UTF-8 MCP request frame including delimiter"}'
)
APPROVAL_RENDERER_MANIFEST_SHA256 = hashlib.sha256(
    APPROVAL_RENDERER_MANIFEST
).hexdigest()


def say(tag: str, msg: str) -> None:
    line = f"[{tag}] {msg}"
    print(line, flush=True)
    REPORT.append(line)


def config_payload(tmp: Path) -> dict:
    return {
        "epoch": 1,
        "safety": {
            "approval": {
                "control_file": str(tmp / "approvals.ndjson"),
                "ttl_seconds": 120,
                "replay_store": {"sqlite_path": str(tmp / "replay.sqlite")},
            },
            "tools": [
                {"name": "db.execute", "mode": "guarded",
                 "match": {"type": "contains_any_ci", "arg": "sql",
                           "needles": ["drop", "delete", "truncate"]},
                 "target": [{"full_arguments": True}]},
                {"name": "session.revoke", "mode": "guarded",
                 "match": {"type": "always"}, "target": [{"full_arguments": True}]},
                {"name": "payments.send", "mode": "guarded",
                 "match": {"type": "always"}, "target": [{"full_arguments": True}]},
                {"name": "store.update", "mode": "guarded",
                 "match": {"type": "always"}, "target": [{"full_arguments": True}]},
                {"name": "shell.run", "mode": "deny",
                 "match": {"type": "always"}, "target": []},
            ],
        },
        "temporal": {"policies": [
            {"name": "no-destructive-after-revoke", "type": "no_after",
             "trigger": ["session.revoke"], "forbidden": ["db.execute"]},
        ]},
        "consensus": {"roster": [1, 2, 3], "votes_file": str(tmp / "votes.ndjson"),
                      "high_stakes": ["payments.send"]},
        "convergence": {"tools": [{"tool": "store.update", "op_arg": "op"}]},
        "budget": {"budgets": [
            {"name": "db-calls", "cap": 2, "tools": ["db.execute"]},
        ]},
    }


class Host:
    def __init__(self, tmp: Path):
        config = tmp / "trusted.json"
        config.write_text(sign_payload(config_payload(tmp), CONFIG_SK), encoding="utf-8")
        (tmp / "approvals.ndjson").touch()
        self.tokens = tmp / "tokens.ndjson"
        self.tokens.touch()
        self.approval_sk, approval_pub = generate_approval_keypair()
        self.approval_session = f"g7/{tmp.name}/{uuid.uuid4().hex}"
        self.proc = subprocess.Popen(
            [
                str(BIN), "--insecure-development-mode", "--config", str(config),
                "--pubkey", PUBKEY, "--channel", "ed25519",
                "--token-file", str(self.tokens),
                "--approval-pubkey", approval_pub,
                "--", "python3", str(MOCK),
            ],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        self.mid = 0
        self.last_frame: bytes | None = None
        self.last_response: dict | None = None

    def _send(self, frame: bytes) -> dict:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(frame.decode("utf-8"))
        self.proc.stdin.flush()
        response = json.loads(self.proc.stdout.readline())
        self.last_frame = frame
        self.last_response = response
        return response

    def call(self, name: str, arguments: dict) -> dict:
        self.mid += 1
        msg = {"jsonrpc": "2.0", "id": self.mid, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}
        frame = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
        return self._send(frame)

    def approve_last_block(self, label: str) -> None:
        assert self.last_frame is not None and self.last_response is not None
        found = re.search(
            r"approval required: ([0-9a-f]{64})",
            json.dumps(self.last_response, separators=(",", ":")),
        )
        assert found, f"{label}: response did not contain an approval target"
        target = found.group(1)
        shown = (
            f"G7 approval {label}\n"
            f"target: {target}\n"
            "exact MCP request frame (including delimiter):\n"
        ).encode("utf-8") + self.last_frame
        sys.stdout.buffer.write(shown)
        sys.stdout.buffer.flush()
        authorized_at = int(time.time() * 1000)
        line = sign_approval_v2_token(
            self.approval_sk,
            target=target,
            authorized_at=authorized_at,
            expiry=authorized_at + 120_000,
            nonce=f"g7-{label}-{uuid.uuid4().hex}",
            session=self.approval_session,
            framed_bytes=self.last_frame,
            shown_bytes=shown,
            renderer_name=APPROVAL_RENDERER_NAME,
            renderer_version=APPROVAL_RENDERER_VERSION,
            renderer_manifest_sha256=APPROVAL_RENDERER_MANIFEST_SHA256,
            approver="G7 scripted demo operator",
        )
        with self.tokens.open("a", encoding="utf-8") as token_file:
            token_file.write(line + "\n")

    def retry_last(self) -> dict:
        assert self.last_frame is not None
        return self._send(self.last_frame)

    def close(self) -> str:
        assert self.proc.stdin and self.proc.stderr
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        return self.proc.stderr.read()


def blocked(r: dict) -> bool:
    return r["result"]["isError"] is True


def part_a() -> None:
    say("DEMO", "── Part A: six blocks under one fail-closed host ──")
    tmp = WORK / "part-a"
    tmp.mkdir(parents=True)
    # The signed-token replay store lives here; the host requires a 0700
    # host-owned parent for it (bounds who can substitute the store).
    os.chmod(tmp, 0o700)
    votes = tmp / "votes.ndjson"
    host = Host(tmp)
    destructive = {"database": "prod", "sql": "drop table users"}

    # S — poisoned-source destructive call, no human approval: blocked.
    r = host.call("db.execute", destructive)
    assert blocked(r), "S failed"
    say("S", f"poisoned destructive call BLOCKED: {r['result']['content'][0]['text']!r}")

    # ApprovalRecord v2 binds the exact framed request, including its delimiter.
    host.approve_last_block("S-first-db")
    r = host.retry_last()
    assert not blocked(r), "approved retry failed"
    say("S", "human-approved retry ALLOWED (one-shot ticket consumed)")

    # B — second executed call fits cap 2; the third is over budget even
    # with a fresh valid approval.
    r = host.call("db.execute", destructive)
    assert blocked(r), "second call did not request a fresh approval"
    host.approve_last_block("B-second-db")
    r = host.retry_last()
    assert not blocked(r), "second in-budget call failed"
    r = host.call("db.execute", destructive)
    assert blocked(r) and "approval required" in r["result"]["content"][0]["text"]
    host.approve_last_block("B-over-budget")
    r = host.retry_last()
    assert blocked(r) and "over budget" in r["result"]["content"][0]["text"], "B failed"
    say("B", f"over-budget call DENIED: {r['result']['content'][0]['text']!r}")

    # C — multi-party action: approved but unratified -> denied; 1-of-3 is
    # not a quorum; 2-of-3 ratifies.
    r = host.call("payments.send", {"amount": 9000})
    assert blocked(r) and "approval required" in r["result"]["content"][0]["text"]
    host.approve_last_block("C-payment")
    r = host.retry_last()
    assert blocked(r) and "quorum missing" in r["result"]["content"][0]["text"], "C failed"
    say("C", f"single-signer high-stakes action DENIED: {r['result']['content'][0]['text']!r}")
    votes.write_text(json.dumps({"acceptor": 1, "value": "payments.send"}) + "\n",
                     encoding="utf-8")
    r = host.call("payments.send", {"amount": 9000})
    assert blocked(r), "C minority failed"
    say("C", "1-of-3 votes still DENIED (strict majority required)")
    with votes.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"acceptor": 2, "value": "payments.send"}) + "\n")
    r = host.call("payments.send", {"amount": 9000})
    assert not blocked(r), "C quorum failed"
    say("C", "2-of-3 ratified quorum ALLOWED (validB certificate checked)")

    # V — divergent write refused; convergent op admitted.
    r = host.call("store.update", {"op": "assign", "key": "k"})
    assert blocked(r) and "approval required" in r["result"]["content"][0]["text"]
    host.approve_last_block("V-store")
    r = host.retry_last()
    assert blocked(r) and "proven-convergent" in r["result"]["content"][0]["text"], "V failed"
    say("V", f"divergent LWW write REFUSED: {r['result']['content'][0]['text']!r}")
    r = host.call("store.update", {"op": "orset.add", "key": "k"})
    assert blocked(r) and "approval required" in r["result"]["content"][0]["text"]
    host.approve_last_block("V-convergent-store")
    r = host.retry_last()
    assert not blocked(r), "V convergent failed"
    say("V", "convergent op (orset.add) ADMITTED")

    # T — out-of-order replay: revoke executes, then a previously-legitimate
    # destructive call (fresh approval, in budget on a NEW session) replays
    # AFTER revoke and is blocked by the trace monitor.
    r = host.call("session.revoke", {})
    assert blocked(r) and "approval required" in r["result"]["content"][0]["text"]
    host.approve_last_block("T-revoke")
    r = host.retry_last()
    assert not blocked(r), "revoke failed"
    say("T", "session.revoke executed (trigger recorded in trace)")
    stderr = host.close()
    AUDIT.extend(l for l in stderr.splitlines() if l.startswith("{"))

    # New session for the T replay (budget cap already consumed above).
    tmp2 = WORK / "part-a-replay"
    tmp2.mkdir(parents=True)
    os.chmod(tmp2, 0o700)
    host2 = Host(tmp2)
    r = host2.call("session.revoke", {})
    assert blocked(r) and "approval required" in r["result"]["content"][0]["text"]
    host2.approve_last_block("T-replay-revoke")
    r = host2.retry_last()
    assert not blocked(r)
    r = host2.call("db.execute", destructive)
    assert blocked(r) and "approval required" in r["result"]["content"][0]["text"]
    host2.approve_last_block("T-replay-db")
    r = host2.retry_last()
    assert blocked(r) and "temporal policy violated" in r["result"]["content"][0]["text"], "T failed"
    say("T", f"approved destructive call replayed AFTER revoke BLOCKED: "
             f"{r['result']['content'][0]['text']!r}")
    stderr = host2.close()
    AUDIT.extend(l for l in stderr.splitlines() if l.startswith("{"))

    # HU — Ed25519 signed-token back-channel: a human-signed approval unlocks
    # a legit retry through a swappable channel (and A3 rejects its replay).
    tmp3 = WORK / "part-a-ed25519"
    tmp3.mkdir(parents=True)
    os.chmod(tmp3, 0o700)
    host3 = Host(tmp3)
    r = host3.call("db.execute", destructive)
    assert blocked(r)
    say("HU", "destructive call blocked; asking the human (Ed25519 channel)...")
    host3.approve_last_block("HU-db")
    token_line = host3.tokens.read_text(encoding="utf-8")
    r = host3.retry_last()
    assert not blocked(r), "HU retry failed"
    say("HU", "human-signed ApprovalRecord v2 verified; legit retry ALLOWED")
    # Reissue the same exact frame without a fresh token to establish the
    # matching v2 challenge, then replay the original token against it.
    r = host3.retry_last()
    assert blocked(r) and "approval required" in r["result"]["content"][0]["text"]
    with host3.tokens.open("a", encoding="utf-8") as f:
        f.write(token_line)
    r = host3.retry_last()
    assert blocked(r), "HU replay failed"
    stderr = host3.close()
    assert "replayed_nonce" in stderr, "HU replay did not report replayed_nonce"
    say("HU", "replayed token REJECTED by A3 (replayed_nonce)")
    AUDIT.extend(l for l in stderr.splitlines() if l.startswith("{"))


def part_b() -> None:
    say("DEMO", "── Part B: whole host in front of a real LangGraph agent ──")
    if not (CANARY / "demo" / "run_p3.py").exists():
        say("AGENT", f"SKIPPED (canary not found at {CANARY}; set CANARY_ROOT)")
        return
    env = os.environ.copy()
    env["SEAL_BIN"] = str(ROOT / "demo" / "seal_host_shim.py")
    proc = subprocess.run(
        ["uv", "run", "python", "demo/run_p3.py"],
        cwd=CANARY, env=env, capture_output=True, text=True, timeout=600,
    )
    tail = "\n".join(proc.stdout.splitlines()[-12:])
    REPORT.append(tail)
    print(tail)
    assert proc.returncode == 0, (
        f"canary-through-seal-host failed (rc={proc.returncode}):\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    say("AGENT", "canary LangGraph pipeline ran through the verified host: "
                 "report written via approved note/create; destructive "
                 "note/delete blocked at the gate (see P3-REPORT.md)")


def main() -> int:
    assert BIN.exists(), f"build first: cargo build (missing {BIN})"
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    os.chmod(WORK, 0o700)

    part_a()
    part_b()

    report = WORK / "G7-REPORT.md"
    lines = ["# G7 — end-to-end verified-mediation demo", ""]
    lines += REPORT
    lines += ["", "## Audit certificates (per mediated call)", ""]
    lines += [f"    {l}" for l in AUDIT]
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    say("DEMO", f"report: {report} ({len(AUDIT)} audit certs)")
    print("G7 DEMO PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
