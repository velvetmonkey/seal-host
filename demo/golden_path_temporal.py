#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""C6 trigger-driven freeze: deterministic mediation with Safety + Temporal."""

from __future__ import annotations

import argparse
import base64
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
PHASE_B_KIT_REV = "62f5fe5d2f3f9d1d700b524aa1d415db449799fc"
SERVER_IDENTITY = "seal-temporal-freeze-demo@1.0.0"
TRIGGER_TOOL = "session.revoke"
FORBIDDEN_TOOL = "audit.destroy"
TOOLS = [TRIGGER_TOOL, FORBIDDEN_TOOL]
POLICY_NAME = "freeze-destructive-after-trigger"
C6_THEOREMS = [
    "Host.composed_temporal_safety",
    "Host.registry_closed_algebra",
    "Host.registry_deny_no_capability_consumed",
    "Host.registry_deny_temporal_frozen",
]

C6_TIER = {
    "tier": "dev-box deterministic-tested (local run); CI configured but not run; operator-verified: NO",
    "evidence_scope": (
        "real Safety approvals on both calls, trigger execution exactly once, "
        "the specific forbidden call denied by Temporal with no downstream execution, "
        "standalone trigger receipt verified, trace-scoped deny fully replayed byte-identically, "
        "receipt/transcript negative controls passed, and scan passed"
    ),
    "proven": (
        "Safety+Temporal reference invariants and deny-state guarantees are machine-checked; "
        "this integration is not universally proven"
    ),
    "ci_tested": False,
    "ci_status": "configured; pending this local commit and the first green workflow",
    "operator_verified": False,
    "operator_status": "operator-untested until run by Ben",
}

TEMPORAL_POLICY = {
    "name": POLICY_NAME,
    "type": "no_after",
    "trigger": TOOLS,
    "forbidden": TOOLS,
}

ADAPTER_SOURCE = r'''#!/usr/bin/env python3
import hashlib
import json
import sys

TOOLS = [
    {
        "name": "session.revoke",
        "description": "Revoke the deterministic demo session and arm the configured Temporal freeze.",
        "inputSchema": {
            "type": "object",
            "properties": {"session": {"type": "string"}},
            "required": ["session"],
            "additionalProperties": False,
        },
        "annotations": {"destructiveHint": True},
    },
    {
        "name": "audit.destroy",
        "description": "Destroy one deterministic demo audit record if mediation permits it.",
        "inputSchema": {
            "type": "object",
            "properties": {"record": {"type": "string"}},
            "required": ["record"],
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

print("SEAL_TEMPORAL_ADAPTER_READY", file=sys.stderr, flush=True)
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
            "serverInfo": {"name": "seal-temporal-freeze-demo", "version": "1.0.0"},
        }})
    elif method == "tools/list":
        print("SEAL_TEMPORAL_TOOLS_LIST_RECEIVED", file=sys.stderr, flush=True)
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "session.revoke" and isinstance(args.get("session"), str):
            digest = hashlib.sha256(args["session"].encode()).hexdigest()[:16]
            print(f"SEAL_TEMPORAL_EXECUTED tool=session.revoke session_sha256={digest}", file=sys.stderr, flush=True)
            result(mid, f"deterministic-revoke-ok session_sha256={digest}")
        elif name == "audit.destroy" and isinstance(args.get("record"), str):
            digest = hashlib.sha256(args["record"].encode()).hexdigest()[:16]
            print(f"SEAL_TEMPORAL_EXECUTED tool=audit.destroy record_sha256={digest}", file=sys.stderr, flush=True)
            result(mid, f"deterministic-destroy-ok record_sha256={digest}")
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
    if not KIT.joinpath("package.json").is_file():
        raise gp.DemoSkip(f"assurance kit missing: {KIT}")
    kit_head = gp.run(["git", "rev-parse", "HEAD"], cwd=KIT).stdout.strip()
    if kit_head != PHASE_B_KIT_REV:
        raise gp.DemoSkip(f"pinned assurance kit required: got {kit_head}, need {PHASE_B_KIT_REV}")
    check("base + prerequisites", f"{branch}@{head}; pinned kit; deterministic local adapter")


def write_adapter(work: Path) -> Path:
    path = work / "temporal_mcp_server.py"
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
            "clientInfo": {"name": "seal-c6-capture", "version": "1"},
        }))
        initialized = json.loads(proc.line())
        proc.send(gp.request(2, "tools/list"))
        listed = json.loads(proc.line())
        identity = initialized["result"]["serverInfo"]
        manifest = {
            "server": f"{identity['name']}@{identity['version']}",
            "tools": listed["result"]["tools"],
        }
        if manifest["server"] != SERVER_IDENTITY or [tool["name"] for tool in manifest["tools"]] != TOOLS:
            raise gp.DemoFailure(f"unexpected live Temporal manifest: {manifest}")
        path = work / "temporal-freeze.tools.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        check("live tools/list manifest", "captured real session.revoke and audit.destroy schemas")
        return path
    finally:
        proc.close()


def prepare_policy(seal: Path, manifest: Path, work: Path):
    policy = work / "temporal-freeze.policy.json"
    gp.run([str(seal), "init", str(manifest), "--out", str(policy)])
    added = gp.run([str(seal), "add-kernel", "T", str(manifest), "--policy", str(policy)])
    add_output = (added.stdout or "") + (added.stderr or "")
    if "temporal (T)" not in add_output or "ACTIVE" not in add_output:
        raise gp.DemoFailure("add-kernel T did not report Temporal ACTIVE")

    before = policy.read_text(encoding="utf-8")
    value = json.loads(before)
    policies = value.get("temporal", {}).get("policies")
    if policies != [TEMPORAL_POLICY]:
        raise gp.DemoFailure(f"shipped temporalFor policy drift: {policies}")
    if any(section in value for section in ["consensus", "convergence", "calibration", "linear", "budget"]):
        raise gp.DemoFailure("C6 scaffold contains a non-Safety/Temporal kernel section")

    approvals = work / "temporal-approvals.ndjson"
    approvals.write_text("", encoding="utf-8")
    replay = work / "temporal-approval-replay.sqlite"
    value["safety"]["approval"]["control_file"] = str(approvals)
    value["safety"]["approval"]["replay_store"] = {"sqlite_path": str(replay)}
    rules = value["safety"]["tools"]
    if [rule.get("name") for rule in rules] != TOOLS or any(rule.get("mode") != "guard" for rule in rules):
        raise gp.DemoFailure(f"unexpected Safety scaffold: {rules}")
    for rule in rules:
        rule["_comment"] = (
            "reviewed C6 mapping: both destructive tools require a live Safety approval; "
            "the shipped trigger-driven no_after Temporal policy arms after the first executed mapped tool"
        )
        rule["_seal_demo_tier"] = C6_TIER
    after = json.dumps(value, indent=2) + "\n"
    if "EDIT-ME" in after:
        raise gp.DemoFailure("reviewed Safety+Temporal policy still contains EDIT-ME")
    print("\n=== VISIBLE INIT + ADD-KERNEL T REVIEW / RUNTIME EDIT ===")
    print("".join(unified_diff(
        before.splitlines(True), after.splitlines(True),
        fromfile="init + add-kernel T scaffold", tofile="reviewed C6 S+T",
    )))
    policy.write_text(after, encoding="utf-8")

    config_key = work / "temporal-policy-signing.seed"
    approval_key = work / "temporal-approval-signing.seed"
    config_key.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    approval_key.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    os.chmod(config_key, 0o600)
    os.chmod(approval_key, 0o600)
    config_pub = gp.node_public_key(config_key)
    approval_pub = gp.node_public_key(approval_key)
    if config_pub == approval_pub:
        raise gp.DemoFailure("policy and approval keys unexpectedly match")
    trusted = work / "temporal-freeze.policy.signed.json"
    signed = gp.run([
        str(seal), "policy", "sign", str(policy), "--key", str(config_key),
        "--out", str(trusted), "--yes",
    ])
    signed_output = (signed.stdout or "") + (signed.stderr or "")
    if "ACTIVE (2)" not in signed_output or "PRESENT-BUT-INACTIVE (0)" not in signed_output:
        raise gp.DemoFailure("sign acknowledgement did not report exactly two active kernels")
    check(
        "init + add-kernel T review + signed policy",
        "ACTIVE {S,T}; freeze-destructive-after-trigger/no_after; zero placeholders",
    )
    return policy, trusted, config_pub, approval_key, approval_pub


def host_command(trusted: Path, config_pub: str, approval_pub: str, tokens: Path,
                 receipts: Path, adapter: Path) -> list[str]:
    return [
        str(HOST), "--config", str(trusted), "--pubkey", config_pub,
        "--channel", "ed25519", "--token-file", str(tokens),
        "--approval-pubkey", approval_pub, "--receipt-dir", str(receipts),
        "--", *adapter_command(adapter),
    ]


class HostSession:
    def __init__(self, trusted: Path, config_pub: str, approval_pub: str,
                 work: Path, adapter: Path):
        self.tokens = work / "hero-tokens.ndjson"
        self.tokens.write_text("", encoding="utf-8")
        self.receipts = work / "hero-receipts"
        self.proc = gp.LineProcess(host_command(
            trusted, config_pub, approval_pub, self.tokens, self.receipts, adapter,
        ))
        self.proc.send(gp.request(100, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "seal-c6", "version": "1"},
        }))
        json.loads(self.proc.line())
        self.proc.send(gp.request(101, "tools/list"))
        json.loads(self.proc.line())
        self.wait_stderr("SEAL_TEMPORAL_ADAPTER_READY")

    def wait_stderr(self, text: str, timeout: float = 5) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(text in line for line in self.proc.stderr_lines):
                return
            time.sleep(0.02)
        raise gp.DemoFailure(f"Temporal session stderr marker missing: {text}")

    def append(self, token: dict) -> None:
        with self.tokens.open("a", encoding="utf-8") as handle:
            handle.write(gp.compact(token) + "\n")

    def call(self, tool: str, arguments: dict) -> tuple[dict, Path]:
        before = set(self.receipts.glob("receipt-*.json")) if self.receipts.exists() else set()
        self.proc.send(gp.request(1, "tools/call", {"name": tool, "arguments": arguments}))
        response = json.loads(self.proc.line())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            after = set(self.receipts.glob("receipt-*.json")) if self.receipts.exists() else set()
            created = sorted(after - before)
            if len(created) == 1:
                return response, created[0]
            if len(created) > 1:
                raise gp.DemoFailure(f"multiple receipts for one {tool} call: {created}")
            time.sleep(0.02)
        raise gp.DemoFailure(f"receipt missing for {tool}")

    def marker_count(self, tool: str) -> int:
        marker = f"SEAL_TEMPORAL_EXECUTED tool={tool}"
        return sum(marker in line for line in self.proc.stderr_lines)

    def close(self) -> None:
        self.proc.close()


def stable_hash_parts(parts: list[str]) -> str:
    framed = "".join(f"{len(part)}:{part}" for part in parts)
    return hashlib.sha256(framed.encode("utf-8")).hexdigest()


def approval_target(tool: str, arguments: dict) -> str:
    canonical_args = json.dumps(arguments, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return stable_hash_parts([SERVER_IDENTITY, tool, canonical_args])


def signed_token(key: Path, tool: str, arguments: dict, label: str) -> dict:
    target = approval_target(tool, arguments)
    return gp.approval_token(key, target, f"c6-{label}-{uuid.uuid4().hex}")


def receipt_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def inspect_receipt(seal: Path, receipt: Path, verdict: str, *, standalone: bool) -> dict:
    record = receipt_json(receipt)
    rules = record.get("kernel_config", {}).get("safety", {}).get("tools", [])
    if [rule.get("name") for rule in rules] != TOOLS or any(rule.get("_seal_demo_tier") != C6_TIER for rule in rules):
        raise gp.DemoFailure(f"receipt tier or Safety mapping mismatch: {receipt}")
    if record.get("kernel_config", {}).get("temporal", {}).get("policies") != [TEMPORAL_POLICY]:
        raise gp.DemoFailure(f"receipt Temporal policy mismatch: {receipt}")
    if record.get("verdict") != verdict:
        raise gp.DemoFailure(f"runtime receipt verdict differs from {verdict}: {receipt}")
    if standalone:
        result = gp.run([str(seal), "verify", str(receipt)])
        if "PASS  VERIFIED" not in result.stdout:
            raise gp.DemoFailure(f"receipt did not independently verify as {verdict}: {receipt}")
    return record


def assert_block(response: dict, text: str) -> None:
    if response.get("result", {}).get("isError") is not True or text.lower() not in gp.compact(response).lower():
        raise gp.DemoFailure(f"expected BLOCK containing {text!r}, got {response}")


def assert_allow(response: dict) -> None:
    if response.get("result", {}).get("isError") is not False:
        raise gp.DemoFailure(f"expected forwarded success, got {response}")


def require_cert(record: dict, kernel: str, verdict: str, reason: str) -> None:
    matches = [cert for cert in record.get("certs", []) if cert.get("kernel") == kernel]
    if len(matches) != 1 or matches[0].get("verdict") != verdict or matches[0].get("reason") != reason:
        raise gp.DemoFailure(f"missing exact {kernel}:{verdict}:{reason} certificate: {record.get('certs')}")


def temporal_evidence(*, before: int, after: int, evidence: str, scope: str,
                      deny_state: dict | None = None) -> dict:
    value = {
        "policy_name": POLICY_NAME,
        "policy_type": "no_after",
        "trigger": TOOLS,
        "forbidden": TOOLS,
        "trace_events_before": before,
        "trace_events_after": after,
        "trace_evidence": evidence,
        "freeze_scope": scope,
        "wall_clock_claim": False,
    }
    if deny_state is not None:
        value["deny_state"] = deny_state
    return value


def hero_pair(seal: Path, trusted: Path, config_pub: str, approval_key: Path,
              approval_pub: str, work: Path, adapter: Path) -> dict:
    trigger_args = {"session": "demo-session-c6"}
    forbidden_args = {"record": "audit-record-c6"}
    session = HostSession(trusted, config_pub, approval_pub, work, adapter)
    try:
        # Mint both exact full-argument approvals before either mediated call.
        # The first recorded call is therefore the executed Temporal trigger,
        # not an approval-discovery probe.
        session.append(signed_token(approval_key, TRIGGER_TOOL, trigger_args, "trigger"))
        session.append(signed_token(approval_key, FORBIDDEN_TOOL, forbidden_args, "forbidden"))

        allowed, trigger_receipt = session.call(TRIGGER_TOOL, trigger_args)
        assert_allow(allowed)
        trigger_record = inspect_receipt(seal, trigger_receipt, "ALLOW", standalone=True)
        require_cert(trigger_record, "safety", "allow", approval_target(TRIGGER_TOOL, trigger_args))
        require_cert(trigger_record, "temporal", "allow", "trace ok (1 events)")
        session.wait_stderr(f"SEAL_TEMPORAL_EXECUTED tool={TRIGGER_TOOL}")
        if session.marker_count(TRIGGER_TOOL) != 1 or session.marker_count(FORBIDDEN_TOOL) != 0:
            raise gp.DemoFailure("trigger must execute exactly once before the forbidden call")

        denied, deny_receipt = session.call(FORBIDDEN_TOOL, forbidden_args)
        assert_block(denied, "temporal policy violated")
        deny_record = inspect_receipt(seal, deny_receipt, "BLOCK", standalone=False)
        if deny_record.get("deny_kernel") != "temporal":
            raise gp.DemoFailure(f"forbidden call deny_kernel is not Temporal: {deny_record.get('deny_kernel')}")
        require_cert(deny_record, "safety", "allow", approval_target(FORBIDDEN_TOOL, forbidden_args))
        require_cert(
            deny_record, "temporal", "deny",
            "temporal policy violated: freeze-destructive-after-trigger",
        )
        if session.marker_count(TRIGGER_TOOL) != 1 or session.marker_count(FORBIDDEN_TOOL) != 0:
            raise gp.DemoFailure("Temporal-denied audit.destroy reached the adapter or trigger re-executed")
        check(
            "trigger arms freeze",
            "approved session.revoke ALLOW; downstream execution exactly once; Temporal trace 0->1",
        )
        check(
            "specific forbidden call freezes",
            "approved audit.destroy DENY by Temporal; trace theorem-backed unchanged at 1; downstream execution zero",
        )
        return {
            "receipt_root": session.receipts,
            "trigger_receipt": trigger_receipt,
            "trigger_record": trigger_record,
            "deny_receipt": deny_receipt,
            "deny_record": deny_record,
        }
    finally:
        session.close()


def build_transcript(artifact_dir: Path, pair: dict) -> tuple[Path, str]:
    trigger_receipt = pair["trigger_receipt"]
    deny_receipt = pair["deny_receipt"]
    trigger_record = pair["trigger_record"]
    deny_record = pair["deny_record"]
    if trigger_record.get("signed_config") != deny_record.get("signed_config"):
        raise gp.DemoFailure("runtime receipts disagree on the pinned signed config")
    wasm_sha = trigger_record.get("kernel_identity", {}).get("wasm_sha256")
    if not isinstance(wasm_sha, str) or deny_record.get("kernel_identity", {}).get("wasm_sha256") != wasm_sha:
        raise gp.DemoFailure("runtime receipts disagree on the vendored WASM identity")
    steps = []
    for sequence, role, receipt, record in [
        (1, "LEGIT-TRIGGER", trigger_receipt, trigger_record),
        (2, "ATTACK-DENY", deny_receipt, deny_record),
    ]:
        receipt_bytes = receipt.read_bytes()
        steps.append({
            "sequence": sequence,
            "role": role,
            "canonical_request": record["canonical_request"],
            "canonical_request_sha256": record["canonical_request_sha256"],
            "raw_kernel_output": record["emitted_bytes"],
            "receipt_path": f"receipts/step-{sequence:02d}-{receipt.name}",
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "receipt_bytes_base64": base64.b64encode(receipt_bytes).decode("ascii"),
        })
    transcript = {
        "schema": "seal-demo-trace-transcript/v1",
        "demo_id": "c6",
        "harness": "demo/trace_replay.cjs",
        "kit_commit": gp.run(["git", "rev-parse", "HEAD"], cwd=KIT).stdout.strip(),
        "wasm_sha256": wasm_sha,
        "signed_config": trigger_record["signed_config"],
        "steps": steps,
    }
    path = artifact_dir / "trace-transcript.json"
    path.write_text(json.dumps(transcript, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def replay_command(transcript: Path, *extra: str) -> list[str]:
    return [
        "node", str(ROOT / "demo" / "trace_replay.cjs"), str(transcript),
        "--kit", str(KIT), *extra,
    ]


def exercise_trace_controls(transcript: Path, transcript_sha: str) -> None:
    full = gp.run(replay_command(transcript))
    if "PASS trace transcript steps=2" not in full.stdout:
        raise gp.DemoFailure("full transcript replay did not report both byte-identical steps")

    dropped = gp.run(replay_command(transcript, "--drop-trigger"), expect=1)
    dropped_output = (dropped.stdout or "") + (dropped.stderr or "")
    if "expected_route=block actual_route=forward" not in dropped_output:
        raise gp.DemoFailure("drop-trigger control did not exhibit fresh-state ALLOW versus live-session BLOCK")

    original = transcript.read_bytes()
    marker = b'\\"route\\":\\"block\\"'
    start = original.find(marker)
    if start < 0:
        raise gp.DemoFailure("cannot locate post-trigger raw output byte for transcript control")
    offset = start + len(b'\\"route\\":\\"')
    tampered = bytearray(original)
    tampered[offset] = ord("c") if tampered[offset] != ord("c") else ord("b")
    transcript.write_bytes(tampered)
    flipped = gp.run(replay_command(transcript), expect=1)
    flipped_output = (flipped.stdout or "") + (flipped.stderr or "")
    if "transcript raw output differs from embedded runtime receipt" not in flipped_output and "byte mismatch" not in flipped_output:
        transcript.write_bytes(original)
        raise gp.DemoFailure("one-byte transcript mutation failed for an unrelated reason")
    transcript.write_bytes(original)
    restored_sha = hashlib.sha256(transcript.read_bytes()).hexdigest()
    if restored_sha != transcript_sha or transcript.read_bytes() != original:
        raise gp.DemoFailure("trace transcript did not restore byte-exact")
    restored = gp.run(replay_command(transcript))
    if "PASS trace transcript steps=2" not in restored.stdout:
        raise gp.DemoFailure("restored transcript did not replay byte-identically")
    check(
        "trace transcript controls",
        "full replay PASS; drop-trigger FAIL (fresh ALLOW vs live BLOCK); byte-flip FAIL; restore SHA match + PASS",
    )


def standalone_trace_scope(seal: Path, receipt: Path) -> dict:
    result = subprocess.run(
        [str(seal), "verify", str(receipt)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0 or "re-derived ALLOW / claimed BLOCK" not in output or "FAIL  NOT VERIFIED" not in output:
        raise gp.DemoFailure("post-trigger receipt did not exhibit the expected fresh-state standalone boundary")
    check(
        "trace-scoped receipt label",
        "plain seal verify fails honestly: fresh-state ALLOW differs from live-session BLOCK",
    )
    return {
        "command": "seal verify", "status": "TRACE-SCOPED", "exit_code": result.returncode,
        "fresh_state_verdict": "ALLOW", "live_session_verdict": "BLOCK",
    }


def verify_scan(seal: Path, manifest: Path, policy: Path) -> None:
    scanned = gp.run([str(seal), "scan", str(manifest), str(policy)])
    if "ACTIVE (2)" not in scanned.stdout or "PRESENT-BUT-INACTIVE (0)" not in scanned.stdout:
        raise gp.DemoFailure("scan did not report exactly ACTIVE {S,T}")
    if not re.search(r"^\s*PASS\s+0 uncovered, 0 ungated,", scanned.stdout, re.M):
        raise gp.DemoFailure("scan did not report clean finite manifest coverage")
    check("seal scan composition", "ACTIVE {S,T}; zero vacuous, uncovered, or ungated tools")


def boundary_card() -> None:
    print("""
===================== C6 TEMPORAL FREEZE BOUNDARY =====================
PROVEN REFERENCE ENFORCEMENT
  Safety approval binding and the closed registry algebra; Temporal composed
  acceptance; any-kernel deny leaves the Temporal trace unchanged and consumes
  no Linear capability at the deployed registry selection.
RUNTIME EVIDENCE
  Approved session.revoke executed exactly once and armed the trigger-driven
  freeze; the specific separately approved audit.destroy call was then denied
  by Temporal and never reached the deterministic adapter.
NON-CLAIM
  No wall-clock or time-window claim. This receipt does not establish intent,
  full-system non-occurrence, that no destructive action can ever occur, or the
  H1 topology x config matrix. Scope is this mediation under the signed policy.
=======================================================================
""", flush=True)
    check("boundary card", "trigger-driven scope and fixed non-claims printed")


def execute(artifact_dir: Path, color: str) -> int:
    preflight()
    gp.build_named_targets()
    with tempfile.TemporaryDirectory(prefix="seal-temporal-freeze-") as td:
        work = Path(td)
        adapter = write_adapter(work)
        seal = gp.temporary_install(work)
        manifest = capture_manifest(adapter, work)
        policy, trusted, config_pub, approval_key, approval_pub = prepare_policy(seal, manifest, work)
        pair = hero_pair(
            seal, trusted, config_pub, approval_key, approval_pub, work, adapter,
        )
        transcript, transcript_sha = build_transcript(artifact_dir, pair)
        exercise_trace_controls(transcript, transcript_sha)
        trace_scope = standalone_trace_scope(seal, pair["deny_receipt"])
        trace = DemoTrace(artifact_dir, "c6", seal, C6_THEOREMS, color)
        trace.configure(
            "init+add-kernel-T", policy,
            active=["safety", "temporal"], inactive=[], experimental=[],
            trace_transcript={
                "path": "trace-transcript.json",
                "sha256": transcript_sha,
                "wasm_sha256": pair["trigger_record"]["kernel_identity"]["wasm_sha256"],
                "harness": "demo/trace_replay.cjs",
                "status": "PASS",
                "lanes": {
                    "standalone": "fresh-state receipt; plain seal verify required",
                    "trace": "one init plus exact ordered requests; raw outputs byte-compared",
                },
            },
        )
        trace.record_receipt(
            pair["trigger_receipt"], role="LEGIT-TRIGGER",
            theorem_ids=["Host.composed_temporal_safety", "Host.registry_closed_algebra"],
            temporal=temporal_evidence(
                before=0, after=1, evidence="runtime-certificate:trace ok (1 events)",
                scope="session.revoke armed the trigger-driven freeze",
            ),
        )
        trace.record_receipt(
            pair["deny_receipt"], role="ATTACK-DENY",
            theorem_ids=[
                "Host.registry_deny_temporal_frozen",
                "Host.registry_deny_no_capability_consumed",
            ],
            temporal=temporal_evidence(
                before=1, after=1,
                evidence="theorem:Host.registry_deny_temporal_frozen",
                scope="this specific audit.destroy call was mediated to DENY under the armed policy",
                deny_state={
                    "trace_theorem": "Host.registry_deny_temporal_frozen",
                    "capability_consumed": False,
                    "capability_theorem": "Host.registry_deny_no_capability_consumed",
                },
            ),
            verification_lane="trace", requires_trace=transcript_sha,
            standalone_failure=trace_scope,
        )
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "trace_replay", "status": "PASS",
            "transcript_path": "trace-transcript.json", "transcript_sha256": transcript_sha,
            "wasm_sha256": pair["trigger_record"]["kernel_identity"]["wasm_sha256"],
            "steps": 2, "harness": "demo/trace_replay.cjs",
        })
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "trace_negative_control",
            "name": "drop-trigger", "expected": "FAIL", "observed": "FAIL", "status": "PASS",
            "evidence": "fresh-state audit.destroy re-derived forward/ALLOW, mismatching live-session BLOCK bytes",
        })
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "trace_negative_control",
            "name": "byte-flip", "expected": "FAIL", "observed": "FAIL", "status": "PASS",
            "evidence": "one byte flipped in the post-trigger raw kernel output",
        })
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "trace_negative_control",
            "name": "restore", "expected": "SHA-MATCH+PASS", "observed": "SHA-MATCH+PASS", "status": "PASS",
            "evidence": f"restored transcript sha256={transcript_sha}; full ordered replay PASS",
        })
        verify_scan(seal, manifest, policy)
        boundary_card()
        trace.finalize([pair["receipt_root"]])
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deterministic", action="store_true")
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    args = parser.parse_args()
    if not args.deterministic:
        parser.error("C6 is a deterministic evidence demo; --deterministic is required")
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
