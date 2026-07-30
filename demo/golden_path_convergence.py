#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""C5 replicated-store mesh: deterministic mediation with Safety + Convergence."""

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
import mcp_eras
from doctrine import DemoTrace

MCP_ERAS = mcp_eras.declared_eras(__file__)

ROOT = gp.ROOT
KIT = gp.KIT
HOST = gp.HOST
PHASE_B_KIT_REV = "bd1cf89ec5d6da6501299e0963f1ef9f5bd5d837"
SERVER_IDENTITY = "seal-convergence-mesh-demo@1.0.0"
TOOL = "store.update"
CONVERGENT_OP = "orset.add"
NONCONVERGENT_OP = "assign"
PROVEN_CONVERGENT_OPS = [
    "gset.add",
    "gcounter.inc",
    "pncounter.inc",
    "pncounter.dec",
    "orset.add",
    "orset.remove",
    "rga.insert",
    "rga.remove",
]
C5_THEOREMS = [
    "Host.composed_convergent",
    "Host.registry_closed_algebra",
    "Host.pureCommit_deny_of_member",
    "Kernels.convergence_verdict_allow_iff",
]

C5_TIER = {
    "tier": "dev-box deterministic-tested (local run); CI configured but not run; operator-verified: NO",
    "evidence_scope": (
        "real Safety approvals on both calls, one proven-convergent store update executed exactly once, "
        "the specific non-convergent update denied by Convergence with no downstream execution, "
        "standalone allow receipt verified, trace-scoped deny replayed byte-identically, "
        "receipt/transcript negative controls passed, and scan passed"
    ),
    "proven": (
        "Safety+Convergence reference invariants and fail-closed composition are machine-checked; "
        "this integration is not universally proven"
    ),
    "ci_tested": False,
    "ci_status": "configured; pending this local commit and the first green workflow",
    "operator_verified": False,
    "operator_status": "operator-untested until run by Ben",
}

ADAPTER_SOURCE = r'''#!/usr/bin/env python3
import hashlib
import json
import sys

TOOLS = [{
    "name": "store.update",
    "description": "Update a replicated shared store with an explicit operation kind.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "op": {"type": "string"},
            "key": {"type": "string"},
            "value": {"type": "string"},
        },
        "required": ["op", "key", "value"],
        "additionalProperties": False,
    },
    "annotations": {"destructiveHint": True},
}]

def send(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()

def result(mid, text, error=False):
    send({"jsonrpc": "2.0", "id": mid, "result": {
        "content": [{"type": "text", "text": text}], "isError": error,
    }})

print("SEAL_CONVERGENCE_ADAPTER_READY", file=sys.stderr, flush=True)
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
            "serverInfo": {"name": "seal-convergence-mesh-demo", "version": "1.0.0"},
        }})
    elif method == "tools/list":
        print("SEAL_CONVERGENCE_TOOLS_LIST_RECEIVED", file=sys.stderr, flush=True)
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if (name == "store.update" and isinstance(args.get("op"), str)
                and isinstance(args.get("key"), str) and isinstance(args.get("value"), str)):
            digest = hashlib.sha256(
                json.dumps(args, separators=(",", ":"), sort_keys=True).encode()
            ).hexdigest()[:16]
            print(
                f"SEAL_CONVERGENCE_EXECUTED tool=store.update op={args['op']} args_sha256={digest}",
                file=sys.stderr,
                flush=True,
            )
            result(mid, f"deterministic-store-update-ok op={args['op']} args_sha256={digest}")
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
    check("base + prerequisites", f"{branch}@{head}; pinned kit; deterministic replicated-store adapter")


def write_adapter(work: Path) -> Path:
    path = work / "convergence_mcp_server.py"
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
            "clientInfo": {"name": "seal-c5-capture", "version": "1"},
        }))
        initialized = json.loads(proc.line())
        proc.send(gp.request(2, "tools/list"))
        listed = json.loads(proc.line())
        identity = initialized["result"]["serverInfo"]
        manifest = {
            "server": f"{identity['name']}@{identity['version']}",
            "tools": listed["result"]["tools"],
        }
        if manifest["server"] != SERVER_IDENTITY or [tool["name"] for tool in manifest["tools"]] != [TOOL]:
            raise gp.DemoFailure(f"unexpected live Convergence manifest: {manifest}")
        path = work / "convergence-mesh.tools.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        check("live tools/list manifest", "captured real store.update schema with explicit op argument")
        return path
    finally:
        proc.close()


def prepare_policy(seal: Path, manifest: Path, work: Path):
    policy = work / "convergence-mesh.policy.json"
    initialized = gp.run([
        str(seal), "init", "--recipe", "mesh", str(manifest), "--out", str(policy),
    ])
    output = (initialized.stdout or "") + (initialized.stderr or "")
    if "ACTIVE {S,V}" not in output or "PRESENT-BUT-INACTIVE {}" not in output:
        raise gp.DemoFailure("mesh recipe did not report exactly ACTIVE {S,V}")

    before = policy.read_text(encoding="utf-8")
    value = json.loads(before)
    convergence = value.get("convergence")
    expected_scaffold = {"tools": [{"tool": TOOL, "op_arg": "operation.kind"}]}
    if convergence != expected_scaffold:
        raise gp.DemoFailure(f"mesh Convergence scaffold drift: {convergence}")
    if any(section in value for section in ["consensus", "calibration", "linear", "budget"]):
        raise gp.DemoFailure("C5 mesh scaffold contains a non-Safety/Convergence kernel section")

    approvals = work / "convergence-approvals.ndjson"
    approvals.write_text("", encoding="utf-8")
    replay = work / "convergence-approval-replay.sqlite"
    value["safety"]["approval"]["control_file"] = str(approvals)
    value["safety"]["approval"]["replay_store"] = {
        "sqlite_path": str(replay),
        "schema_version": 1,
        "namespace_encoding_version": 1,
    }
    value["convergence"]["tools"][0]["op_arg"] = "op"
    rules = value["safety"]["tools"]
    if len(rules) != 1 or rules[0].get("name") != TOOL or rules[0].get("mode") != "guard":
        raise gp.DemoFailure(f"unexpected mesh Safety scaffold: {rules}")
    rules[0]["_comment"] = (
        "reviewed C5 mapping: store.update is Safety-guarded; Convergence resolves the real op "
        "argument against the fixed proven-convergent operation set"
    )
    rules[0]["_seal_demo_tier"] = C5_TIER
    after = json.dumps(value, indent=2) + "\n"
    if "EDIT-ME" in after:
        raise gp.DemoFailure("reviewed Safety+Convergence policy still contains EDIT-ME")
    print("\n=== VISIBLE MESH RECIPE REVIEW / RUNTIME EDIT ===")
    print("".join(unified_diff(
        before.splitlines(True), after.splitlines(True),
        fromfile="mesh scaffold", tofile="reviewed C5 S+V",
    )))
    policy.write_text(after, encoding="utf-8")

    config_key = work / "convergence-policy-signing.seed"
    approval_key = work / "convergence-approval-signing.seed"
    config_key.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    approval_key.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    os.chmod(config_key, 0o600)
    os.chmod(approval_key, 0o600)
    config_pub = gp.node_public_key(config_key)
    approval_pub = gp.node_public_key(approval_key)
    if config_pub == approval_pub:
        raise gp.DemoFailure("policy and approval keys unexpectedly match")
    trusted = work / "convergence-mesh.policy.signed.json"
    signed = gp.run([
        str(seal), "policy", "sign", str(policy), "--key", str(config_key),
        "--out", str(trusted), "--yes",
    ])
    signed_output = (signed.stdout or "") + (signed.stderr or "")
    if "ACTIVE (2)" not in signed_output or "PRESENT-BUT-INACTIVE (0)" not in signed_output:
        raise gp.DemoFailure("sign acknowledgement did not report exactly two active kernels")
    gp.initialize_replay_store(trusted, config_pub)
    check("mesh recipe review + signed policy", "ACTIVE {S,V}; store.update opArg=op; zero placeholders")
    return policy, trusted, config_pub, approval_key, approval_pub


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
                 work: Path, adapter: Path):
        self.tokens = work / "hero-tokens.ndjson"
        self.tokens.write_text("", encoding="utf-8")
        self.receipts = work / "hero-receipts"
        self.proc = gp.LineProcess(host_command(
            trusted, config_pub, approval_pub, self.tokens, self.receipts, adapter,
        ))
        self.proc.send(gp.request(100, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "seal-c5", "version": "1"},
        }))
        json.loads(self.proc.line())
        self.proc.send(gp.request(101, "tools/list"))
        json.loads(self.proc.line())
        self.wait_stderr("SEAL_CONVERGENCE_ADAPTER_READY")

    def wait_stderr(self, text: str, timeout: float = 5) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(text in line for line in self.proc.stderr_lines):
                return
            time.sleep(0.02)
        raise gp.DemoFailure(f"Convergence session stderr marker missing: {text}")

    def append(self, token: dict) -> None:
        with self.tokens.open("a", encoding="utf-8") as handle:
            handle.write(gp.compact(token) + "\n")

    def call(self, arguments: dict) -> tuple[dict, Path]:
        before = set(self.receipts.glob("receipt-*.json")) if self.receipts.exists() else set()
        self.proc.send(gp.request(1, "tools/call", {"name": TOOL, "arguments": arguments}))
        response = json.loads(self.proc.line())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            after = set(self.receipts.glob("receipt-*.json")) if self.receipts.exists() else set()
            created = sorted(after - before)
            if len(created) == 1:
                return response, created[0]
            if len(created) > 1:
                raise gp.DemoFailure(f"multiple receipts for one store.update call: {created}")
            time.sleep(0.02)
        raise gp.DemoFailure("receipt missing for store.update")

    def marker_count(self, operation: str) -> int:
        marker = f"SEAL_CONVERGENCE_EXECUTED tool={TOOL} op={operation}"
        return sum(marker in line for line in self.proc.stderr_lines)

    def close(self) -> None:
        self.proc.close()


def signed_token(key: Path, refusal: dict, label: str) -> dict:
    return gp.approval_token(key, refusal, f"c5-{label}-{uuid.uuid4().hex}")


def receipt_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def inspect_receipt(seal: Path, receipt: Path, verdict: str, *, standalone: bool) -> dict:
    record = receipt_json(receipt)
    rules = record.get("kernel_config", {}).get("safety", {}).get("tools", [])
    if len(rules) != 1 or rules[0].get("_seal_demo_tier") != C5_TIER:
        raise gp.DemoFailure(f"receipt tier or Safety mapping mismatch: {receipt}")
    expected = {"tools": [{"tool": TOOL, "op_arg": "op"}]}
    if record.get("kernel_config", {}).get("convergence") != expected:
        raise gp.DemoFailure(f"receipt Convergence policy mismatch: {receipt}")
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


def hero_pair(seal: Path, trusted: Path, config_pub: str, approval_key: Path,
              approval_pub: str, work: Path, adapter: Path) -> dict:
    allowed_args = {"op": CONVERGENT_OP, "key": "team/c5", "value": "member-a"}
    denied_args = {"op": NONCONVERGENT_OP, "key": "team/c5", "value": "blind-overwrite"}
    session = HostSession(trusted, config_pub, approval_pub, work, adapter)
    try:
        allowed_refusal, allowed_discovery = session.call(allowed_args)
        assert_block(allowed_refusal, "approval required")
        session.append(signed_token(approval_key, allowed_refusal, "convergent"))
        allowed, allow_receipt = session.call(allowed_args)
        assert_allow(allowed)
        allow_record = inspect_receipt(seal, allow_receipt, "ALLOW", standalone=True)
        require_cert(allow_record, "safety", "allow", gp.target_from(allowed_refusal))
        require_cert(allow_record, "convergence", "allow", f"convergent op admitted: {CONVERGENT_OP}")
        session.wait_stderr(f"SEAL_CONVERGENCE_EXECUTED tool={TOOL} op={CONVERGENT_OP}")
        if session.marker_count(CONVERGENT_OP) != 1 or session.marker_count(NONCONVERGENT_OP) != 0:
            raise gp.DemoFailure("proven-convergent update must execute exactly once before the denied call")

        denied_refusal, denied_discovery = session.call(denied_args)
        assert_block(denied_refusal, "approval required")
        session.append(signed_token(approval_key, denied_refusal, "nonconvergent"))
        denied, deny_receipt = session.call(denied_args)
        assert_block(denied, f"op not in the proven-convergent set: {NONCONVERGENT_OP}")
        deny_record = inspect_receipt(seal, deny_receipt, "BLOCK", standalone=False)
        if deny_record.get("deny_kernel") != "convergence":
            raise gp.DemoFailure(f"non-convergent call deny_kernel is not Convergence: {deny_record.get('deny_kernel')}")
        require_cert(deny_record, "safety", "allow", gp.target_from(denied_refusal))
        require_cert(
            deny_record, "convergence", "deny",
            f"op not in the proven-convergent set: {NONCONVERGENT_OP}",
        )
        if session.marker_count(CONVERGENT_OP) != 1 or session.marker_count(NONCONVERGENT_OP) != 0:
            raise gp.DemoFailure("Convergence-denied assign reached the adapter or allowed op re-executed")
        check(
            "proven-convergent update",
            "approved orset.add ALLOW; downstream store.update execution exactly once",
        )
        check(
            "specific non-convergent update denied",
            "separately approved assign DENY by Convergence; downstream execution zero",
        )
        return {
            "receipt_root": session.receipts,
            "allow_discovery": allowed_discovery,
            "allow_discovery_record": receipt_json(allowed_discovery),
            "allow_receipt": allow_receipt,
            "allow_record": allow_record,
            "deny_discovery": denied_discovery,
            "deny_discovery_record": receipt_json(denied_discovery),
            "deny_receipt": deny_receipt,
            "deny_record": deny_record,
            "allow_target": gp.target_from(allowed_refusal),
            "deny_target": gp.target_from(denied_refusal),
        }
    finally:
        session.close()


def replay_input(record: dict, approvals: list[dict]) -> dict:
    return {
        "line": record["canonical_request"],
        "now": record["now"],
        "approvals": approvals,
        "approval_evidence": "trace-events",
        "votes": "",
        "grants": "",
        "forecasts": "",
    }


def build_transcript(artifact_dir: Path, pair: dict) -> tuple[Path, str]:
    allow_receipt = pair["allow_receipt"]
    deny_receipt = pair["deny_receipt"]
    allow_record = pair["allow_record"]
    deny_record = pair["deny_record"]
    if allow_record.get("signed_config") != deny_record.get("signed_config"):
        raise gp.DemoFailure("runtime receipts disagree on the pinned signed config")
    wasm_sha = allow_record.get("kernel_identity", {}).get("wasm_sha256")
    if not isinstance(wasm_sha, str) or deny_record.get("kernel_identity", {}).get("wasm_sha256") != wasm_sha:
        raise gp.DemoFailure("runtime receipts disagree on the vendored WASM identity")

    allow_approvals = [
        {"target": item["target"]}
        for item in allow_record.get("granted_capabilities", [])
    ]
    deny_approvals = [
        {"target": item["target"]}
        for item in deny_record.get("granted_capabilities", [])
    ]
    if ({item["target"] for item in allow_approvals} != {pair["allow_target"]}
            or {item["target"] for item in deny_approvals} != {pair["deny_target"]}):
        raise gp.DemoFailure("receipts do not each pin their just-in-time Safety approval")
    steps = []
    for sequence, role, receipt, record, step_approvals in [
        (1, gp.APPROVAL_SUBJECT_ROLE, pair["allow_discovery"],
         pair["allow_discovery_record"], []),
        (2, "LEGIT-TRIGGER", allow_receipt, allow_record, allow_approvals),
        (3, gp.APPROVAL_SUBJECT_ROLE, pair["deny_discovery"],
         pair["deny_discovery_record"], []),
        (4, "ATTACK-DENY", deny_receipt, deny_record, deny_approvals),
    ]:
        receipt_bytes = receipt.read_bytes()
        steps.append({
            "sequence": sequence,
            "role": role,
            "commit": role != gp.APPROVAL_SUBJECT_ROLE,
            "canonical_request": record["canonical_request"],
            "canonical_request_sha256": record["canonical_request_sha256"],
            "step_input": replay_input(record, step_approvals),
            "raw_kernel_output": record["emitted_bytes"],
            "receipt_path": f"receipts/step-{sequence:02d}-{receipt.name}",
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "receipt_bytes_base64": base64.b64encode(receipt_bytes).decode("ascii"),
        })
    transcript = {
        "schema": "seal-demo-trace-transcript/v1",
        "demo_id": "c5",
        "harness": "demo/trace_replay.cjs",
        "kit_commit": gp.run(["git", "rev-parse", "HEAD"], cwd=KIT).stdout.strip(),
        "wasm_sha256": wasm_sha,
        "signed_config": allow_record["signed_config"],
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
    if "PASS trace transcript steps=4" not in full.stdout:
        raise gp.DemoFailure("full transcript replay did not report all four byte-identical calls")

    dropped = gp.run(replay_command(transcript, "--drop-sequence", "2"), expect=1)
    dropped_output = (dropped.stdout or "") + (dropped.stderr or "")
    if "byte mismatch" not in dropped_output or "actual_route=block" not in dropped_output:
        raise gp.DemoFailure("drop-trigger control did not change the second call's raw decision bytes")

    original = transcript.read_bytes()
    marker = b'\\"route\\":\\"block\\"'
    start = original.find(marker)
    if start < 0:
        raise gp.DemoFailure("cannot locate denied raw output byte for transcript control")
    offset = start + len(b'\\"route\\":\\"')
    tampered = bytearray(original)
    tampered[offset] = ord("c") if tampered[offset] != ord("c") else ord("b")
    transcript.write_bytes(tampered)
    flipped = gp.run(replay_command(transcript), expect=1)
    flipped_output = (flipped.stdout or "") + (flipped.stderr or "")
    if ("transcript raw output differs from embedded runtime receipt" not in flipped_output
            and "byte mismatch" not in flipped_output):
        transcript.write_bytes(original)
        raise gp.DemoFailure("one-byte transcript mutation failed for an unrelated reason")
    transcript.write_bytes(original)
    restored_sha = hashlib.sha256(transcript.read_bytes()).hexdigest()
    if restored_sha != transcript_sha or transcript.read_bytes() != original:
        raise gp.DemoFailure("trace transcript did not restore byte-exact")
    restored = gp.run(replay_command(transcript))
    if "PASS trace transcript steps=4" not in restored.stdout:
        raise gp.DemoFailure("restored transcript did not replay byte-identically")
    check(
        "trace transcript controls",
        "full replay PASS; drop-trigger byte mismatch; byte-flip mismatch; restore SHA match + PASS",
    )


def standalone_trace_scope(seal: Path, receipt: Path) -> dict:
    result = subprocess.run(
        [str(seal), "verify", str(receipt)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    output = (result.stdout or "") + (result.stderr or "")
    if (result.returncode == 0
            or "re-derived BLOCK / claimed BLOCK" not in output
            or "emitted decision bytes byte-identical" not in output
            or "FAIL  NOT VERIFIED" not in output):
        raise gp.DemoFailure("C5 deny receipt did not exhibit its exact trace-indexed byte boundary")
    check(
        "trace-scoped receipt label",
        "plain seal verify re-derives BLOCK but fails byte identity: fresh Temporal trace differs from live step 2",
    )
    return {
        "command": "seal verify",
        "status": "TRACE-SCOPED",
        "exit_code": result.returncode,
        "fresh_state_verdict": "BLOCK",
        "live_session_verdict": "BLOCK",
        "artifact_lane_reason": (
            "Convergence is stateless, but the always-registered Temporal certificate "
            "is trace-indexed and changes the composite emitted bytes"
        ),
    }


def verify_scan(seal: Path, manifest: Path, policy: Path) -> None:
    scanned = gp.run([str(seal), "scan", str(manifest), str(policy)])
    if "ACTIVE (2)" not in scanned.stdout or "PRESENT-BUT-INACTIVE (0)" not in scanned.stdout:
        raise gp.DemoFailure("scan did not report exactly ACTIVE {S,V}")
    if not re.search(r"^\s*PASS\s+0 uncovered, 0 ungated,", scanned.stdout, re.M):
        raise gp.DemoFailure("scan did not report clean finite manifest coverage")
    check("seal scan composition", "ACTIVE {S,V}; zero vacuous, uncovered, or ungated tools")


def boundary_card() -> None:
    print("""
===================== C5 CONVERGENCE MESH BOUNDARY =====================
PROVEN REFERENCE ENFORCEMENT
  Safety approval binding and the closed registry algebra; composed
  Convergence admits only operations in the fixed proven-convergent set.
RUNTIME EVIDENCE
  Approved orset.add executed exactly once; the specific separately approved
  assign call was denied by Convergence and never reached the adapter.
NON-CLAIM
  Convergence is stateless. This receipt does not establish universal store
  convergence, intent, full-system non-occurrence, or the H1 topology x config
  matrix. Scope is these mediation decisions under the signed mesh policy.
========================================================================
""", flush=True)
    check("boundary card", "specific-call mediation scope and fixed non-claims printed")


def convergence_evidence(operation: str, admitted: bool) -> dict:
    return {
        "tool": TOOL,
        "op_arg": "op",
        "operation": operation,
        "in_proven_set": admitted,
        "proven_set": PROVEN_CONVERGENT_OPS,
        "stateful": False,
        "claim_scope": (
            "this specific operation was mediated under the fixed kernel set; "
            "no universal replicated-store convergence claim"
        ),
    }


def execute(artifact_dir: Path, color: str) -> int:
    preflight()
    gp.build_named_targets()
    with tempfile.TemporaryDirectory(prefix="seal-convergence-mesh-") as td:
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
        discovery_trace_scope = standalone_trace_scope(seal, pair["deny_discovery"])
        trace = DemoTrace(artifact_dir, "c5", seal, C5_THEOREMS, color)
        trace.configure(
            "mesh", policy,
            active=["safety", "convergence"], inactive=[], experimental=[],
            trace_transcript={
                "path": "trace-transcript.json",
                "sha256": transcript_sha,
                "wasm_sha256": pair["allow_record"]["kernel_identity"]["wasm_sha256"],
                "harness": "demo/trace_replay.cjs",
                "status": "PASS",
                "lanes": {
                    "standalone": "fresh first receipt; plain seal verify required",
                    "trace": (
                        "second verdict re-derives BLOCK fresh, but the composite Temporal certificate "
                        "is trace-indexed; ordered raw outputs byte-compared"
                    ),
                },
            },
        )
        trace.record_receipt(
            pair["allow_discovery"], role=gp.APPROVAL_SUBJECT_ROLE,
            theorem_ids=["Kernels.convergence_verdict_allow_iff", "Host.pureCommit_deny_of_member"],
        )
        trace.record_receipt(
            pair["allow_receipt"], role="LEGIT-TRIGGER",
            theorem_ids=["Host.composed_convergent", "Host.registry_closed_algebra"],
            convergence=convergence_evidence(CONVERGENT_OP, True),
        )
        trace.record_receipt(
            pair["deny_discovery"], role=gp.APPROVAL_SUBJECT_ROLE,
            theorem_ids=["Kernels.convergence_verdict_allow_iff", "Host.pureCommit_deny_of_member"],
            verification_lane="trace", requires_trace=transcript_sha,
            standalone_failure=discovery_trace_scope,
        )
        trace.record_receipt(
            pair["deny_receipt"], role="ATTACK-DENY",
            theorem_ids=["Kernels.convergence_verdict_allow_iff", "Host.pureCommit_deny_of_member"],
            convergence=convergence_evidence(NONCONVERGENT_OP, False),
            verification_lane="trace", requires_trace=transcript_sha,
            standalone_failure=trace_scope,
        )
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "trace_replay", "status": "PASS",
            "transcript_path": "trace-transcript.json", "transcript_sha256": transcript_sha,
            "wasm_sha256": pair["allow_record"]["kernel_identity"]["wasm_sha256"],
            "steps": 4, "harness": "demo/trace_replay.cjs",
        })
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "trace_negative_control",
            "name": "drop-trigger", "expected": "BYTE-MISMATCH", "observed": "BYTE-MISMATCH", "status": "PASS",
            "evidence": (
                "without step 1, step 2 keeps its own Safety approval but the trace-indexed "
                "composite bytes differ; the stateless Convergence denial itself is unchanged"
            ),
        })
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "trace_negative_control",
            "name": "byte-flip", "expected": "FAIL", "observed": "FAIL", "status": "PASS",
            "evidence": "one byte flipped in the non-convergent call's raw kernel output",
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
        parser.error("C5 is a deterministic evidence demo; --deterministic is required")
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
