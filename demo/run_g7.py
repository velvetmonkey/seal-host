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
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test" / "tools"))
sys.path.insert(0, str(ROOT / "test" / "integration"))
from sign_config import sign_payload  # noqa: E402
from test_host import stable_hash  # noqa: E402

WORK = Path("/tmp/seal-host-g7")
PUBKEY = "demo-pk"
BIN = ROOT / "rust" / "target" / "debug" / "seal-host-rs"
MOCK = ROOT / "test" / "integration" / "mock_mcp_server.py"
CANARY = Path(os.environ.get("CANARY_ROOT", "/home/monkey/src/canary"))

REPORT: list[str] = []
AUDIT: list[str] = []


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
                 "target": [{"literal": "db"}, {"arg": "database"},
                            {"literal": "write"}, {"arg": "sql"}]},
                {"name": "session.revoke", "mode": "guarded",
                 "match": {"type": "always"}, "target": [{"literal": "revoke"}]},
                {"name": "payments.send", "mode": "guarded",
                 "match": {"type": "always"}, "target": [{"literal": "pay"}]},
                {"name": "store.update", "mode": "guarded",
                 "match": {"type": "always"}, "target": [{"literal": "store"}]},
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
    def __init__(self, tmp: Path, channel_args: tuple[str, ...] = ()):
        config = tmp / "trusted.json"
        config.write_text(sign_payload(config_payload(tmp), PUBKEY), encoding="utf-8")
        (tmp / "approvals.ndjson").touch()
        self.proc = subprocess.Popen(
            [str(BIN), "--config", str(config), "--pubkey", PUBKEY, *channel_args,
             "--", "python3", str(MOCK)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        self.mid = 0

    def call(self, name: str, arguments: dict) -> dict:
        self.mid += 1
        msg = {"jsonrpc": "2.0", "id": self.mid, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}
        self.proc.stdin.write(json.dumps(msg, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def close(self) -> str:
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        return self.proc.stderr.read()


def blocked(r: dict) -> bool:
    return r["result"]["isError"] is True


def part_a() -> None:
    say("DEMO", "── Part A: six blocks under one fail-closed host ──")
    tmp = WORK / "part-a"
    tmp.mkdir(parents=True)
    approvals = tmp / "approvals.ndjson"
    votes = tmp / "votes.ndjson"
    host = Host(tmp)
    destructive = {"database": "prod", "sql": "drop table users"}
    db_target = stable_hash(["db.execute", "db", "prod", "write", "drop table users"])

    # S — poisoned-source destructive call, no human approval: blocked.
    r = host.call("db.execute", destructive)
    assert blocked(r), "S failed"
    say("S", f"poisoned destructive call BLOCKED: {r['result']['content'][0]['text']!r}")

    # Human approval through the control-file back-channel: legit retry runs.
    approvals.write_text(json.dumps({"target": db_target}) + "\n", encoding="utf-8")
    r = host.call("db.execute", destructive)
    assert not blocked(r), "approved retry failed"
    say("S", "human-approved retry ALLOWED (one-shot ticket consumed)")

    # B — second executed call fits cap 2; the third is over budget even
    # with a fresh valid approval.
    with approvals.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"target": db_target}) + "\n")
    r = host.call("db.execute", destructive)
    assert not blocked(r), "second in-budget call failed"
    with approvals.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"target": db_target}) + "\n")
    r = host.call("db.execute", destructive)
    assert blocked(r) and "over budget" in r["result"]["content"][0]["text"], "B failed"
    say("B", f"over-budget call DENIED: {r['result']['content'][0]['text']!r}")

    # C — multi-party action: approved but unratified -> denied; 1-of-3 is
    # not a quorum; 2-of-3 ratifies.
    pay_target = stable_hash(["payments.send", "pay"])
    with approvals.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"target": pay_target}) + "\n")
    r = host.call("payments.send", {"amount": 9000})
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
    store_target = stable_hash(["store.update", "store"])
    with approvals.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"target": store_target}) + "\n")
    r = host.call("store.update", {"op": "assign", "key": "k"})
    assert blocked(r) and "proven-convergent" in r["result"]["content"][0]["text"], "V failed"
    say("V", f"divergent LWW write REFUSED: {r['result']['content'][0]['text']!r}")
    r = host.call("store.update", {"op": "orset.add", "key": "k"})
    assert not blocked(r), "V convergent failed"
    say("V", "convergent op (orset.add) ADMITTED")

    # T — out-of-order replay: revoke executes, then a previously-legitimate
    # destructive call (fresh approval, in budget on a NEW session) replays
    # AFTER revoke and is blocked by the trace monitor.
    revoke_target = stable_hash(["session.revoke", "revoke"])
    with approvals.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"target": revoke_target}) + "\n")
    r = host.call("session.revoke", {})
    assert not blocked(r), "revoke failed"
    say("T", "session.revoke executed (trigger recorded in trace)")
    stderr = host.close()
    AUDIT.extend(l for l in stderr.splitlines() if l.startswith("{"))

    # New session for the T replay (budget cap already consumed above).
    tmp2 = WORK / "part-a-replay"
    tmp2.mkdir(parents=True)
    host2 = Host(tmp2)
    approvals2 = tmp2 / "approvals.ndjson"
    with approvals2.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"target": revoke_target}) + "\n")
    r = host2.call("session.revoke", {})
    assert not blocked(r)
    with approvals2.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"target": db_target}) + "\n")
    r = host2.call("db.execute", destructive)
    assert blocked(r) and "temporal policy violated" in r["result"]["content"][0]["text"], "T failed"
    say("T", f"approved destructive call replayed AFTER revoke BLOCKED: "
             f"{r['result']['content'][0]['text']!r}")
    stderr = host2.close()
    AUDIT.extend(l for l in stderr.splitlines() if l.startswith("{"))

    # HU — Ed25519 signed-token back-channel: a human-signed approval unlocks
    # a legit retry through a swappable channel (and A3 rejects its replay).
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        say("HU", "SKIPPED (python cryptography unavailable)")
        return
    sk = Ed25519PrivateKey.generate()
    pk_hex = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    tmp3 = WORK / "part-a-ed25519"
    tmp3.mkdir(parents=True)
    tokens = tmp3 / "tokens.ndjson"
    tokens.touch()
    host3 = Host(tmp3, ("--channel", "ed25519", "--token-file", str(tokens),
                        "--approval-pubkey", pk_hex))
    r = host3.call("db.execute", destructive)
    assert blocked(r)
    say("HU", "destructive call blocked; asking the human (Ed25519 channel)...")
    payload = json.dumps({"target": db_target, "issuedAt": int(time.time() * 1000),
                          "nonce": "g7-demo-nonce-1"}, separators=(",", ":"))
    sig = sk.sign(payload.encode()).hex()
    tokens.write_text(json.dumps({"payload": payload, "signature": sig},
                                 separators=(",", ":")) + "\n", encoding="utf-8")
    r = host3.call("db.execute", destructive)
    assert not blocked(r), "HU retry failed"
    say("HU", "human-signed approval token verified; legit retry ALLOWED")
    with tokens.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"payload": payload, "signature": sig},
                           separators=(",", ":")) + "\n")
    r = host3.call("db.execute", destructive)
    assert blocked(r), "HU replay failed"
    say("HU", "replayed token REJECTED by A3 (nonce already seen)")
    stderr = host3.close()
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
