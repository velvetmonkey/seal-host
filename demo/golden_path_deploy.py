#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""C3 deterministic deploy: Safety + Consensus + one-use Linear capability."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from difflib import unified_diff
from pathlib import Path

import golden_path as gp
from doctrine import DemoTrace

ROOT = gp.ROOT
KIT = gp.KIT
HOST = gp.HOST
PHASE_B_KIT_REV = "bd1cf89ec5d6da6501299e0963f1ef9f5bd5d837"
SERVER_IDENTITY = "seal-c3-deploy-demo@1.0.0"
DEPLOY_TOOL = "deploy"
ROLLBACK_TOOL = "rollback"
ROSTER = [101, 202, 303]
CAPABILITY = "deploy-cap-c3-001"
SHORT_VOTES = '{"acceptor":101,"value":"deploy"}'
QUORUM_VOTES = SHORT_VOTES + '\n{"acceptor":202,"value":"deploy"}'
GRANT = '{"cap":"deploy-cap-c3-001","uses":1}'
C3_THEOREMS = [
    "Host.composed_non_bypass",
    "Host.composed_no_conflicting_agreement",
    "Host.composed_linear_conservation",
    "Host.registry_closed_algebra",
    "Host.pureCommit_deny_of_member",
    "Host.registry_deny_no_capability_consumed",
    "Host.linear_committed_trace_no_double_spend",
]

C3_TIER = {
    "tier": "dev-box deterministic-tested (local run); CI configured but not run; operator-verified: NO",
    "evidence_scope": (
        "live Safety approvals, 1-of-3 Consensus veto, 2-of-3 composed allow, "
        "one committed deploy, one-use Linear replay denial, byte-exact trace replay and controls"
    ),
    "proven": "Safety+Consensus+Linear reference invariants are machine-checked; this integration is not universally proven",
    "ci_tested": False,
    "ci_status": "configured; pending this local commit and the first green workflow",
    "operator_verified": False,
    "operator_status": "operator-untested until run by Ben",
}

ADAPTER_SOURCE = r'''#!/usr/bin/env python3
import hashlib
import json
import sys

TOOLS = [
    {
        "name": "deploy",
        "description": "Deploy one named release using an explicitly supplied one-use capability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "release": {"type": "string"},
                "environment": {"type": "string"},
                "capability": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                    "additionalProperties": False,
                },
            },
            "required": ["release", "environment", "capability"],
            "additionalProperties": False,
        },
        "annotations": {"destructiveHint": True},
    },
    {
        "name": "rollback",
        "description": "Rollback one named release.",
        "inputSchema": {
            "type": "object",
            "properties": {"release": {"type": "string"}},
            "required": ["release"],
            "additionalProperties": False,
        },
        "annotations": {"destructiveHint": True},
    },
]

def send(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()

def result(mid, text, error=False):
    send({"jsonrpc": "2.0", "id": mid, "result": {
        "content": [{"type": "text", "text": text}], "isError": error,
    }})

print("SEAL_C3_ADAPTER_READY", file=sys.stderr, flush=True)
for line in sys.stdin:
    try:
        message = json.loads(line)
    except Exception:
        continue
    mid = message.get("id")
    method = message.get("method")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "seal-c3-deploy-demo", "version": "1.0.0"},
        }})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "deploy" and isinstance(args.get("release"), str):
            digest = hashlib.sha256(json.dumps(args, sort_keys=True).encode()).hexdigest()[:16]
            print(f"SEAL_C3_EXECUTED tool=deploy args_sha256={digest}", file=sys.stderr, flush=True)
            result(mid, f"deterministic-deploy-ok args_sha256={digest}")
        elif name == "rollback" and isinstance(args.get("release"), str):
            print("SEAL_C3_EXECUTED tool=rollback", file=sys.stderr, flush=True)
            result(mid, "deterministic-rollback-ok")
        else:
            result(mid, "unknown tool or invalid arguments", True)
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}})
'''


def check(name: str, evidence: str) -> None:
    gp.check(name, "PASS", evidence)


def preflight() -> None:
    branch = gp.run(["git", "branch", "--show-current"]).stdout.strip()
    head = gp.run(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()
    for binary in ["node", "npm", "cargo", "lake", "python3"]:
        if not shutil.which(binary):
            raise gp.DemoSkip(f"required command missing: {binary}")
    if gp.run(["git", "rev-parse", "HEAD"], cwd=KIT).stdout.strip() != PHASE_B_KIT_REV:
        raise gp.DemoSkip("pinned assurance kit checkout is required")
    check("base + prerequisites", f"{branch}@{head}; pinned kit; deterministic local adapter")


def write_adapter(work: Path) -> Path:
    path = work / "c3_mcp_server.py"
    path.write_text(ADAPTER_SOURCE, encoding="utf-8")
    os.chmod(path, 0o500)
    return path


def adapter_command(adapter: Path) -> list[str]:
    return [sys.executable, "-u", str(adapter)]


def capture_manifest(adapter: Path, work: Path) -> Path:
    proc = gp.LineProcess(adapter_command(adapter))
    try:
        proc.send(gp.request(1, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "seal-c3-capture", "version": "1"},
        }))
        initialized = json.loads(proc.line())
        proc.send(gp.request(2, "tools/list"))
        listed = json.loads(proc.line())
        identity = initialized["result"]["serverInfo"]
        manifest = {"server": f"{identity['name']}@{identity['version']}", "tools": listed["result"]["tools"]}
        if manifest["server"] != SERVER_IDENTITY or [tool["name"] for tool in manifest["tools"]] != [DEPLOY_TOOL, ROLLBACK_TOOL]:
            raise gp.DemoFailure(f"unexpected C3 manifest: {manifest}")
        path = work / "c3-deploy.tools.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        check("live tools/list manifest", "captured deploy capability.id and rollback schemas")
        return path
    finally:
        proc.close()


def prepare_policy(seal: Path, manifest: Path, work: Path):
    policy = work / "c3-deploy.policy.json"
    initialized = gp.run([str(seal), "init", "--recipe", "deploy", str(manifest), "--out", str(policy)])
    output = (initialized.stdout or "") + (initialized.stderr or "")
    if "ACTIVE {S,C,L}" not in output or "PRESENT-BUT-INACTIVE {}" not in output:
        raise gp.DemoFailure("deploy recipe did not report exactly ACTIVE {S,C,L}")
    before = policy.read_text(encoding="utf-8")
    value = json.loads(before)
    if value.get("consensus") != {"roster": [], "votes_file": "EDIT-ME/seal-votes.ndjson", "high_stakes": [DEPLOY_TOOL]}:
        raise gp.DemoFailure(f"deploy Consensus scaffold drift: {value.get('consensus')}")
    if value.get("linear") != {"grants_file": "EDIT-ME/seal-grants.ndjson", "tools": [{"tool": DEPLOY_TOOL, "cap_arg": "capability.id"}]}:
        raise gp.DemoFailure(f"deploy Linear scaffold drift: {value.get('linear')}")

    approvals = work / "c3-approvals.ndjson"
    votes = work / "c3-votes.ndjson"
    grants = work / "c3-grants.ndjson"
    replay = work / "c3-approval-replay.sqlite"
    approvals.write_text("", encoding="utf-8")
    votes.write_text(SHORT_VOTES + "\n", encoding="utf-8")
    grants.write_text(GRANT + "\n", encoding="utf-8")
    value["safety"]["approval"]["control_file"] = str(approvals)
    value["safety"]["approval"]["replay_store"] = {"sqlite_path": str(replay)}
    value["consensus"]["roster"] = ROSTER
    value["consensus"]["votes_file"] = str(votes)
    value["linear"]["grants_file"] = str(grants)
    rules = value["safety"]["tools"]
    if [rule.get("name") for rule in rules] != [DEPLOY_TOOL, ROLLBACK_TOOL] or any(rule.get("mode") != "guard" for rule in rules):
        raise gp.DemoFailure(f"unexpected C3 Safety scaffold: {rules}")
    for rule in rules:
        role = "high-stakes deploy" if rule["name"] == DEPLOY_TOOL else "rollback"
        rule["_comment"] = (
            f"reviewed C3 mapping: {role} is Safety-guarded; deploy requires tool-name quorum "
            "and the real nested capability.id one-use grant"
        )
        rule["_seal_demo_tier"] = C3_TIER
    after = json.dumps(value, indent=2) + "\n"
    if "EDIT-ME" in after:
        raise gp.DemoFailure("reviewed deploy policy still contains EDIT-ME")
    print("\n=== VISIBLE DEPLOY RECIPE REVIEW / RUNTIME EDIT ===")
    print("".join(unified_diff(
        before.splitlines(True), after.splitlines(True),
        fromfile="deploy scaffold", tofile="reviewed C3 S+C+L",
    )))
    policy.write_text(after, encoding="utf-8")

    config_key = work / "c3-policy-signing.seed"
    approval_key = work / "c3-approval-signing.seed"
    config_key.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    approval_key.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    os.chmod(config_key, 0o600)
    os.chmod(approval_key, 0o600)
    config_pub = gp.node_public_key(config_key)
    approval_pub = gp.node_public_key(approval_key)
    trusted = work / "c3-deploy.policy.signed.json"
    signed = gp.run([str(seal), "policy", "sign", str(policy), "--key", str(config_key), "--out", str(trusted), "--yes"])
    signed_output = (signed.stdout or "") + (signed.stderr or "")
    if "ACTIVE (3)" not in signed_output or "PRESENT-BUT-INACTIVE (0)" not in signed_output:
        raise gp.DemoFailure("signed C3 policy did not report exactly three active kernels")
    check("deploy recipe review + signed policy", "ACTIVE {S,C,L}; real roster/votes/grant; zero placeholders")
    return policy, trusted, config_pub, approval_key, approval_pub, approvals, votes, grants


def host_command(trusted: Path, config_pub: str, approval_pub: str, tokens: Path,
                 receipts: Path, adapter: Path) -> list[str]:
    return [
        str(HOST), "--insecure-development-mode", "--config", str(trusted), "--pubkey", config_pub,
        "--channel", "ed25519", "--token-file", str(tokens),
        "--approval-pubkey", approval_pub, "--receipt-dir", str(receipts),
        "--", *adapter_command(adapter),
    ]


class HostSession:
    def __init__(self, trusted: Path, config_pub: str, approval_pub: str,
                 approvals: Path, votes: Path, work: Path, adapter: Path):
        self.tokens = approvals
        self.votes = votes
        self.receipts = work / "c3-receipts"
        self.proc = gp.LineProcess(host_command(trusted, config_pub, approval_pub, self.tokens, self.receipts, adapter))
        self.proc.send(gp.request(100, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "seal-c3", "version": "1"},
        }))
        json.loads(self.proc.line())
        self.proc.send(gp.request(101, "tools/list"))
        json.loads(self.proc.line())
        self.wait_stderr("SEAL_C3_ADAPTER_READY")

    def wait_stderr(self, text: str, timeout: float = 5) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(text in line for line in self.proc.stderr_lines):
                return
            time.sleep(0.02)
        raise gp.DemoFailure(f"C3 stderr marker missing: {text}")

    def append_token(self, token: dict) -> None:
        with self.tokens.open("a", encoding="utf-8") as handle:
            handle.write(gp.compact(token) + "\n")

    def reach_quorum(self) -> None:
        self.votes.write_text(QUORUM_VOTES + "\n", encoding="utf-8")

    def call(self, arguments: dict) -> tuple[dict, Path]:
        before = set(self.receipts.glob("receipt-*.json")) if self.receipts.exists() else set()
        self.proc.send(gp.request(1, "tools/call", {"name": DEPLOY_TOOL, "arguments": arguments}))
        response = json.loads(self.proc.line())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            after = set(self.receipts.glob("receipt-*.json")) if self.receipts.exists() else set()
            created = sorted(after - before)
            if len(created) == 1:
                return response, created[0]
            if len(created) > 1:
                raise gp.DemoFailure(f"multiple receipts for one deploy call: {created}")
            time.sleep(0.02)
        raise gp.DemoFailure("C3 deploy receipt missing")

    def deploy_count(self) -> int:
        return sum("SEAL_C3_EXECUTED tool=deploy" in line for line in self.proc.stderr_lines)

    def close(self) -> None:
        self.proc.close()


def signed_token(key: Path, refusal: dict, label: str) -> dict:
    return gp.approval_token(key, refusal, f"c3-{label}-{uuid.uuid4().hex}")


def assert_block(response: dict, text: str) -> None:
    if response.get("result", {}).get("isError") is not True or text.lower() not in gp.compact(response).lower():
        raise gp.DemoFailure(f"expected C3 BLOCK containing {text!r}, got {response}")


def assert_allow(response: dict) -> None:
    if response.get("result", {}).get("isError") is not False:
        raise gp.DemoFailure(f"expected C3 forwarded success, got {response}")


def receipt_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def require_cert(record: dict, kernel: str, verdict: str, reason: str) -> None:
    matches = [cert for cert in record.get("certs", []) if cert.get("kernel") == kernel]
    if len(matches) != 1 or matches[0].get("verdict") != verdict or matches[0].get("reason") != reason:
        raise gp.DemoFailure(f"missing exact {kernel}:{verdict}:{reason} certificate")


def standalone_scope(seal: Path, receipt: Path, live_verdict: str) -> dict:
    result = subprocess.run([str(seal), "verify", str(receipt)], cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = (result.stdout or "") + (result.stderr or "")
    match = re.search(r"re-derived (ALLOW|BLOCK) / claimed (ALLOW|BLOCK)", output)
    if result.returncode == 0 or "FAIL  NOT VERIFIED" not in output or not match:
        raise gp.DemoFailure(f"C3 receipt unexpectedly standalone-verifiable: {receipt}\n{output}")
    return {
        "command": "seal verify", "status": "TRACE-SCOPED", "exit_code": result.returncode,
        "rederived_verdict": match.group(1), "live_session_verdict": live_verdict,
        "artifact_lane_reason": "combined receipt omits votes/grants; verifier replays both empty",
    }


def hero_flow(seal: Path, trusted: Path, config_pub: str, approval_key: Path,
              approval_pub: str, approvals: Path, votes: Path, work: Path, adapter: Path) -> dict:
    short_args = {
        "release": "release-c3-quorum-short", "environment": "production",
        "capability": {"id": CAPABILITY},
    }
    deploy_args = {
        "release": "release-c3-approved", "environment": "production",
        "capability": {"id": CAPABILITY},
    }
    session = HostSession(trusted, config_pub, approval_pub, approvals, votes, work, adapter)
    try:
        short_refusal, short_discovery = session.call(short_args)
        assert_block(short_refusal, "approval required")
        session.append_token(signed_token(approval_key, short_refusal, "quorum-short"))
        denied, short_receipt = session.call(short_args)
        assert_block(denied, "quorum missing (1/3)")
        short_record = receipt_json(short_receipt)
        require_cert(short_record, "safety", "allow", gp.target_from(short_refusal))
        require_cert(short_record, "consensus", "deny", "quorum missing (1/3): deploy")
        require_cert(short_record, "linear", "allow", f"capability spent (0 uses left): {CAPABILITY}")
        if short_record.get("deny_kernel") != "consensus" or session.deploy_count() != 0:
            raise gp.DemoFailure("QUORUM-SHORT did not veto before downstream execution")

        session.reach_quorum()
        deploy_refusal, deploy_discovery = session.call(deploy_args)
        assert_block(deploy_refusal, "approval required")
        session.append_token(signed_token(approval_key, deploy_refusal, "deploy-ok"))
        allowed, ok_receipt = session.call(deploy_args)
        assert_allow(allowed)
        ok_record = receipt_json(ok_receipt)
        require_cert(ok_record, "safety", "allow", gp.target_from(deploy_refusal))
        require_cert(ok_record, "consensus", "allow", "quorum ok (2/3): deploy")
        require_cert(ok_record, "linear", "allow", f"capability spent (0 uses left): {CAPABILITY}")
        if session.deploy_count() != 1:
            raise gp.DemoFailure("DEPLOY-OK did not execute exactly once")

        replay_refusal, replay_discovery = session.call(deploy_args)
        assert_block(replay_refusal, "approval required")
        session.append_token(signed_token(approval_key, replay_refusal, "replay-deny"))
        replay, replay_receipt = session.call(deploy_args)
        assert_block(replay, "capability exhausted")
        replay_record = receipt_json(replay_receipt)
        require_cert(replay_record, "safety", "allow", gp.target_from(replay_refusal))
        require_cert(replay_record, "consensus", "allow", "quorum ok (2/3): deploy")
        require_cert(replay_record, "linear", "deny", f"capability exhausted, double-spend denied: {CAPABILITY}")
        if replay_record.get("deny_kernel") != "linear" or session.deploy_count() != 1:
            raise gp.DemoFailure("REPLAY-DENY did not stay out of the adapter")
        check("quorum-short veto", "1-of-3 Consensus DENY; valid Safety+Linear candidates; committed capability remains 1")
        check("one-use deploy", "2-of-3 + Safety + Linear ALLOW; deploy executed exactly once; capability 1->0")
        check("linear replay denial", "identical deploy denied by Linear after consumption; downstream count remains one")
        return {
            "receipt_root": session.receipts,
            "discovery_receipts": [short_discovery, deploy_discovery, replay_discovery],
            "receipts": [short_receipt, ok_receipt, replay_receipt],
            "records": [short_record, ok_record, replay_record],
            "arguments": [short_args, deploy_args, deploy_args],
        }
    finally:
        session.close()


def replay_input(record: dict, votes: str, grants: str) -> dict:
    return {
        "line": record["canonical_request"], "now": record["now"],
        "approvals": [{"target": grant["target"]} for grant in record["granted_capabilities"]],
        "votes": votes, "grants": grants, "forecasts": "",
    }


def build_transcript(artifact_dir: Path, flow: dict) -> tuple[Path, str]:
    records = [
        item
        for pair in zip(
            [
                receipt_json(receipt)
                for receipt in flow["discovery_receipts"]
            ],
            flow["records"],
        )
        for item in pair
    ]
    receipts = [
        item
        for pair in zip(flow["discovery_receipts"], flow["receipts"])
        for item in pair
    ]
    if any(record.get("signed_config") != records[0].get("signed_config") for record in records[1:]):
        raise gp.DemoFailure("C3 runtime receipts disagree on signed config")
    wasm_sha = records[0].get("kernel_identity", {}).get("wasm_sha256")
    roles = [
        gp.APPROVAL_SUBJECT_ROLE, "QUORUM-SHORT",
        gp.APPROVAL_SUBJECT_ROLE, "DEPLOY-OK",
        gp.APPROVAL_SUBJECT_ROLE, "REPLAY-DENY",
    ]
    votes = [
        SHORT_VOTES, SHORT_VOTES,
        QUORUM_VOTES, QUORUM_VOTES,
        QUORUM_VOTES, QUORUM_VOTES,
    ]
    grants = [GRANT, GRANT, "", "", "", ""]
    steps = []
    for sequence, (role, receipt, record, vote_text, grant_text) in enumerate(
            zip(roles, receipts, records, votes, grants), 1):
        receipt_bytes = receipt.read_bytes()
        step = {
            "sequence": sequence,
            "role": role,
            "commit": role != gp.APPROVAL_SUBJECT_ROLE,
            "canonical_request": record["canonical_request"],
            "canonical_request_sha256": record["canonical_request_sha256"],
            "step_input": replay_input(record, vote_text, grant_text),
            "raw_kernel_output": record["emitted_bytes"],
            "receipt_path": f"receipts/step-{sequence:02d}-{receipt.name}",
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "receipt_bytes_base64": base64.b64encode(receipt_bytes).decode("ascii"),
        }
        steps.append(step)
    quorum_variant = copy.deepcopy(steps[1]["step_input"])
    quorum_variant["votes"] = QUORUM_VOTES
    steps[1]["input_variants"] = {"quorum-met": quorum_variant}
    transcript = {
        "schema": "seal-demo-trace-transcript/v1", "demo_id": "c3",
        "harness": "demo/trace_replay.cjs",
        "kit_commit": gp.run(["git", "rev-parse", "HEAD"], cwd=KIT).stdout.strip(),
        "wasm_sha256": wasm_sha, "signed_config": records[0]["signed_config"], "steps": steps,
    }
    path = artifact_dir / "trace-transcript.json"
    path.write_text(json.dumps(transcript, indent=2) + "\n", encoding="utf-8")
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def replay_command(transcript: Path, *extra: str) -> list[str]:
    return ["node", str(ROOT / "demo" / "trace_replay.cjs"), str(transcript), "--kit", str(KIT), *extra]


def exercise_trace_controls(transcript: Path, transcript_sha: str) -> dict:
    full = gp.run(replay_command(transcript))
    if "PASS trace transcript steps=6" not in full.stdout:
        raise gp.DemoFailure("C3 full replay did not pass all six calls")
    quorum = gp.run(replay_command(transcript, "--variant", "quorum-met"), expect=1)
    quorum_output = (quorum.stdout or "") + (quorum.stderr or "")
    if "expected_route=block actual_route=forward" not in quorum_output:
        raise gp.DemoFailure("C3 quorum-met control did not flip Consensus BLOCK to ALLOW")
    dropped = gp.run(replay_command(transcript, "--drop-sequence", "4"), expect=1)
    dropped_output = (dropped.stdout or "") + (dropped.stderr or "")
    if "byte mismatch" not in dropped_output or "actual_route=block" not in dropped_output:
        raise gp.DemoFailure("C3 drop-DEPLOY-OK control did not change replay-discovery bytes")

    original = transcript.read_bytes()
    role = original.find(b'"role": "REPLAY-DENY"')
    marker = b'\\"route\\":\\"block\\"'
    start = original.find(marker, role)
    if role < 0 or start < 0:
        raise gp.DemoFailure("cannot locate REPLAY-DENY output byte for transcript control")
    offset = start + len(b'\\"route\\":\\"')
    tampered = bytearray(original)
    tampered[offset] = ord("c") if tampered[offset] != ord("c") else ord("b")
    transcript.write_bytes(tampered)
    flipped = gp.run(replay_command(transcript), expect=1)
    flipped_output = (flipped.stdout or "") + (flipped.stderr or "")
    if "transcript raw output differs from embedded runtime receipt" not in flipped_output and "byte mismatch" not in flipped_output:
        transcript.write_bytes(original)
        raise gp.DemoFailure("C3 transcript byte flip failed for an unrelated reason")
    transcript.write_bytes(original)
    restored_sha = hashlib.sha256(transcript.read_bytes()).hexdigest()
    if restored_sha != transcript_sha or transcript.read_bytes() != original:
        raise gp.DemoFailure("C3 transcript did not restore byte-exact")
    restored = gp.run(replay_command(transcript))
    if "PASS trace transcript steps=6" not in restored.stdout:
        raise gp.DemoFailure("restored C3 transcript did not replay")
    check("trace controls", "full PASS; quorum-met FAIL; drop-DEPLOY-OK FAIL; byte-flip FAIL; restore SHA+PASS")
    return {"exit_code": flipped.returncode, "original_sha256": transcript_sha, "restored_sha256": restored_sha}


def verify_scan(seal: Path, manifest: Path, policy: Path) -> None:
    scanned = gp.run([str(seal), "scan", str(manifest), str(policy)])
    if "ACTIVE (3)" not in scanned.stdout or "PRESENT-BUT-INACTIVE (0)" not in scanned.stdout:
        raise gp.DemoFailure("C3 scan did not report exactly ACTIVE {S,C,L}")
    if not re.search(r"^\s*PASS\s+0 uncovered, 0 ungated,", scanned.stdout, re.M):
        raise gp.DemoFailure("C3 scan did not report clean finite manifest coverage")
    check("seal scan composition", "ACTIVE {S,C,L}; zero vacuous, uncovered, or ungated tools")


def boundary_card() -> None:
    print("""
====================== C3 DEPLOY BOUNDARY ======================
PROVEN REFERENCE ENFORCEMENT
  Safety non-bypass, tool-name Consensus agreement, composed Linear
  conservation, committed-trace no-double-spend, and deny-without-consumption.
RUNTIME EVIDENCE
  One-of-three veto; two-of-three approved one-use deploy executed exactly
  once; identical replay denied by Linear and never reached the adapter.
NON-CLAIM
  Consensus binds the deployed tool name, not full argument bytes. This receipt
  does not establish intent, full-system non-occurrence, alternative deployment
  impossibility, or the H1 topology x config matrix.
===============================================================
""", flush=True)
    check("boundary card", "mediation-only scope and fixed non-claims printed")


def execute(artifact_dir: Path, color: str) -> int:
    preflight()
    gp.build_named_targets()
    with tempfile.TemporaryDirectory(prefix="seal-c3-deploy-") as td:
        work = Path(td)
        adapter = write_adapter(work)
        seal = gp.temporary_install(work)
        manifest = capture_manifest(adapter, work)
        policy, trusted, config_pub, approval_key, approval_pub, approvals, votes, _grants = prepare_policy(seal, manifest, work)
        flow = hero_flow(seal, trusted, config_pub, approval_key, approval_pub, approvals, votes, work, adapter)
        transcript, transcript_sha = build_transcript(artifact_dir, flow)
        control = exercise_trace_controls(transcript, transcript_sha)
        standalone = [
            item
            for pair in zip(
                [
                    standalone_scope(seal, receipt, "BLOCK")
                    for receipt in flow["discovery_receipts"]
                ],
                [
                    standalone_scope(seal, flow["receipts"][0], "BLOCK"),
                    standalone_scope(seal, flow["receipts"][1], "ALLOW"),
                    standalone_scope(seal, flow["receipts"][2], "BLOCK"),
                ],
            )
            for item in pair
        ]

        trace = DemoTrace(artifact_dir, "c3", seal, C3_THEOREMS, color)
        trace.configure(
            "deploy", policy, active=["safety", "consensus", "linear"], inactive=[], experimental=[],
            trace_transcript={
                "path": "trace-transcript.json", "sha256": transcript_sha,
                "wasm_sha256": flow["records"][0]["kernel_identity"]["wasm_sha256"],
                "harness": "demo/trace_replay.cjs", "status": "PASS",
                "lanes": {
                    "standalone": "not applicable: combined receipts omit votes/grants evidence",
                    "trace": "one init plus exact ordered requests and evidence; raw outputs byte-compared",
                },
            },
        )
        for index, (discovery, receipt) in enumerate(
                zip(flow["discovery_receipts"], flow["receipts"])):
            trace.record_receipt(
                discovery, role=gp.APPROVAL_SUBJECT_ROLE,
                theorem_ids=[
                    "Host.pureCommit_deny_of_member",
                    "Host.registry_deny_no_capability_consumed",
                ],
                verification_lane="trace", requires_trace=transcript_sha,
                standalone_failure=standalone[index * 2],
            )
            roles = ["QUORUM-SHORT", "DEPLOY-OK", "REPLAY-DENY"]
            theorem_sets = [
                ["Host.pureCommit_deny_of_member", "Host.registry_deny_no_capability_consumed"],
                ["Host.registry_closed_algebra", "Host.composed_non_bypass",
                 "Host.composed_no_conflicting_agreement", "Host.composed_linear_conservation"],
                ["Host.linear_committed_trace_no_double_spend", "Host.pureCommit_deny_of_member",
                 "Host.registry_deny_no_capability_consumed"],
            ]
            consensus = [
                {"roster": ROSTER, "value": "deploy", "votes": 1, "required": 2, "quorum_met": False},
                {"roster": ROSTER, "value": "deploy", "votes": 2, "required": 2, "quorum_met": True},
                {"roster": ROSTER, "value": "deploy", "votes": 2, "required": 2, "quorum_met": True},
            ]
            linear = [
                {"cap_arg": "capability.id", "capability_id": CAPABILITY, "grant_events": 1,
                 "remaining_before": 1, "remaining_after": 1, "consumed": False},
                {"cap_arg": "capability.id", "capability_id": CAPABILITY, "grant_events": 0,
                 "remaining_before": 1, "remaining_after": 0, "consumed": True},
                {"cap_arg": "capability.id", "capability_id": CAPABILITY, "grant_events": 0,
                 "remaining_before": 0, "remaining_after": 0, "consumed": False},
            ]
            trace.record_receipt(
                receipt, role=roles[index], theorem_ids=theorem_sets[index],
                consensus=consensus[index], linear=linear[index],
                verification_lane="trace", requires_trace=transcript_sha,
                standalone_failure=standalone[index * 2 + 1],
            )
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "trace_replay", "status": "PASS",
            "transcript_path": "trace-transcript.json", "transcript_sha256": transcript_sha,
            "wasm_sha256": flow["records"][0]["kernel_identity"]["wasm_sha256"],
            "steps": 6, "harness": "demo/trace_replay.cjs",
        })
        controls = [
            ("quorum-met", "1-of-3 Consensus BLOCK changed to 2-of-3 forward/ALLOW and mismatched receipt bytes"),
            ("drop-deploy-ok", "without DEPLOY-OK the later replay-discovery BLOCK carried different capability-state bytes"),
            ("byte-flip", "one byte flipped in the REPLAY-DENY raw kernel output"),
        ]
        for name, evidence in controls:
            trace.emit({"schema": "seal-demo-trace/v1", "event": "trace_negative_control", "name": name,
                        "expected": "FAIL", "observed": "FAIL", "status": "PASS", "evidence": evidence})
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "trace_negative_control", "name": "restore",
            "expected": "SHA-MATCH+PASS", "observed": "SHA-MATCH+PASS", "status": "PASS",
            "evidence": f"restored transcript sha256={transcript_sha}; full ordered replay PASS",
        })
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "anti_forge", "subject": "trace-transcript",
            "receipt_path": "trace-transcript.json", "mutation": "one byte flipped in REPLAY-DENY raw output",
            "tampered_verify_exit": control["exit_code"], "original_sha256": control["original_sha256"],
            "restored_sha256": control["restored_sha256"], "restored_verify": "PASS",
        })
        verify_scan(seal, manifest, policy)
        boundary_card()
        trace.finalize([flow["receipt_root"]])
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deterministic", action="store_true")
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    args = parser.parse_args()
    if not args.deterministic:
        parser.error("C3 is a deterministic evidence demo; --deterministic is required")
    try:
        return execute(args.artifact_dir, args.color)
    except gp.DemoSkip as error:
        gp.check("demo", "SKIP", str(error))
        return 2
    except Exception as error:
        gp.check("demo", "FAIL", str(error))
        return 1
    finally:
        gp.print_table()


if __name__ == "__main__":
    raise SystemExit(main())
