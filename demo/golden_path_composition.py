#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""C7 flagship: all six non-experimental kernels in one composed verdict."""

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
SERVER_IDENTITY = "seal-c7-composition-demo@1.0.0"
ROSTER = [101, 202, 303]
CAP = 20
NORMAL_COST = 1
OVER_COST = 20
CONVERGENT_OP = "orset.add"
NONCONVERGENT_OP = "assign"

HEADLINE_TOOL = "compose.allow"
DENY_TOOLS = {
    "safety": "deny.safety",
    "temporal": "deny.temporal",
    "consensus": "deny.consensus",
    "convergence": "deny.convergence",
    "linear": "deny.linear",
    "budget": "deny.budget",
}
TOOLS = [HEADLINE_TOOL, *DENY_TOOLS.values()]
ROLES = [
    "COMPOSED-ALLOW", "S-DENY", "T-DENY", "C-DENY",
    "V-DENY", "L-DENY", "B-DENY",
]
ORDERED_TOOLS = [
    HEADLINE_TOOL,
    DENY_TOOLS["safety"],
    DENY_TOOLS["temporal"],
    DENY_TOOLS["consensus"],
    DENY_TOOLS["convergence"],
    DENY_TOOLS["linear"],
    DENY_TOOLS["budget"],
]
DENY_KERNELS = [None, "safety", "temporal", "consensus", "convergence", "linear", "budget"]
TEMPORAL_POLICY = {
    "name": "c7-headline-arms-temporal-veto",
    "type": "no_after",
    "trigger": [HEADLINE_TOOL],
    "forbidden": [DENY_TOOLS["temporal"]],
}
PROVEN_CONVERGENT_OPS = [
    "gset.add", "gcounter.inc", "pncounter.inc", "pncounter.dec",
    "orset.add", "orset.remove", "rga.insert", "rga.remove",
]

C7_THEOREMS = [
    "Host.registry_closed_algebra",
    "Host.composed_non_bypass",
    "Host.composed_temporal_safety",
    "Host.composed_no_conflicting_agreement",
    "Host.composed_convergent",
    "Host.composed_linear_conservation",
    "Host.composed_budget_cap",
    "Host.pureCommit_deny_of_member",
    "Host.registry_deny_no_budget_spend",
    "Host.registry_deny_no_capability_consumed",
    "Host.registry_deny_temporal_frozen",
    "Kernels.convergence_verdict_allow_iff",
]

C7_TIER = {
    "tier": "dev-box deterministic-tested (local run); CI configured but not run; operator-verified: NO",
    "evidence_scope": (
        "one signed ACTIVE {S,T,C,V,L,B} policy; one composed ALLOW with all six ALLOW "
        "certificates; one isolated veto by each active kernel; one downstream execution; "
        "deny-without-Linear/Budget-spend checks; byte-exact trace replay and controls"
    ),
    "proven": (
        "Host.registry_closed_algebra and the six membership-guarded reference invariants are "
        "machine-checked; this integration is not universally proven"
    ),
    "ci_tested": False,
    "ci_status": "configured; pending this local commit and the first green workflow",
    "operator_verified": False,
    "operator_status": "operator-untested until run by Ben",
}


def tool_definition(name: str) -> dict:
    return {
        "name": name,
        "description": (
            "Deploy a replicated composition operation with explicit capability and token charge; "
            "the C7 policy assigns the tool its reviewed kernel role."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "op": {"type": "string"},
                "capability": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                    "additionalProperties": False,
                },
                "usage": {
                    "type": "object",
                    "properties": {"tokens": {"type": "integer", "minimum": 0}},
                    "required": ["tokens"],
                    "additionalProperties": False,
                },
                "payload": {"type": "string"},
            },
            "required": ["op", "capability", "usage", "payload"],
            "additionalProperties": False,
        },
        "annotations": {"destructiveHint": True},
    }


ADAPTER_SOURCE = r'''#!/usr/bin/env python3
import hashlib
import json
import sys

TOOL_NAMES = __TOOL_NAMES__
TOOLS = []
for name in TOOL_NAMES:
    TOOLS.append({
        "name": name,
        "description": "C7 deterministic composed-kernel operation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "op": {"type": "string"},
                "capability": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"], "additionalProperties": False,
                },
                "usage": {
                    "type": "object",
                    "properties": {"tokens": {"type": "integer", "minimum": 0}},
                    "required": ["tokens"], "additionalProperties": False,
                },
                "payload": {"type": "string"},
            },
            "required": ["op", "capability", "usage", "payload"],
            "additionalProperties": False,
        },
        "annotations": {"destructiveHint": True},
    })

def send(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()

def result(mid, text, error=False):
    send({"jsonrpc": "2.0", "id": mid, "result": {
        "content": [{"type": "text", "text": text}], "isError": error,
    }})

print("SEAL_C7_ADAPTER_READY", file=sys.stderr, flush=True)
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
            "serverInfo": {"name": "seal-c7-composition-demo", "version": "1.0.0"},
        }})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        capability = args.get("capability")
        usage = args.get("usage")
        valid = (
            name in TOOL_NAMES and isinstance(args.get("op"), str)
            and isinstance(capability, dict) and isinstance(capability.get("id"), str)
            and isinstance(usage, dict) and isinstance(usage.get("tokens"), int)
            and not isinstance(usage.get("tokens"), bool) and usage.get("tokens") >= 0
            and isinstance(args.get("payload"), str)
        )
        if valid:
            digest = hashlib.sha256(
                json.dumps(args, separators=(",", ":"), sort_keys=True).encode()
            ).hexdigest()[:16]
            print(f"SEAL_C7_EXECUTED tool={name} args_sha256={digest}", file=sys.stderr, flush=True)
            result(mid, f"deterministic-c7-ok tool={name} args_sha256={digest}")
        else:
            result(mid, "unknown tool or invalid arguments", True)
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}})
'''.replace("__TOOL_NAMES__", json.dumps(TOOLS))


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
    check("base + prerequisites", f"{branch}@{head}; pinned kit; deterministic C7 adapter")


def write_adapter(work: Path) -> Path:
    path = work / "c7_mcp_server.py"
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
            "clientInfo": {"name": "seal-c7-capture", "version": "1"},
        }))
        initialized = json.loads(proc.line())
        proc.send(gp.request(2, "tools/list"))
        listed = json.loads(proc.line())
        identity = initialized["result"]["serverInfo"]
        manifest = {
            "server": f"{identity['name']}@{identity['version']}",
            "tools": listed["result"]["tools"],
        }
        if manifest["server"] != SERVER_IDENTITY or [item["name"] for item in manifest["tools"]] != TOOLS:
            raise gp.DemoFailure(f"unexpected C7 manifest: {manifest}")
        path = work / "c7-composition.tools.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        check("live tools/list manifest", "captured seven real composition/veto tools and typed arguments")
        return path
    finally:
        proc.close()


def _assert_added(output: str, symbol: str, section: str) -> None:
    if f"added kernel  {section} ({symbol}) — ACTIVE" not in output:
        raise gp.DemoFailure(f"add-kernel {symbol} did not report {section} ACTIVE")


def prepare_policy(seal: Path, manifest: Path, work: Path):
    policy = work / "c7-composition.policy.json"
    gp.run([str(seal), "init", str(manifest), "--out", str(policy)])
    for symbol, section in [
        ("T", "temporal"), ("C", "consensus"), ("V", "convergence"),
        ("L", "linear"), ("B", "budget"),
    ]:
        added = gp.run([str(seal), "add-kernel", symbol, str(manifest), "--policy", str(policy)])
        _assert_added((added.stdout or "") + (added.stderr or ""), symbol, section)

    before = policy.read_text(encoding="utf-8")
    value = json.loads(before)
    if set(value) != {"epoch", "server", "safety", "temporal", "consensus", "convergence", "linear", "budget"}:
        raise gp.DemoFailure(f"C7 scaffold section drift: {sorted(value)}")
    if "calibration" in value:
        raise gp.DemoFailure("experimental Calibration must be absent from C7")

    approvals = work / "c7-approvals.ndjson"
    votes = work / "c7-votes.ndjson"
    grants = work / "c7-grants.ndjson"
    approvals.write_text("", encoding="utf-8")
    votes.write_text(votes_for(HEADLINE_TOOL), encoding="utf-8")
    grants.write_text(grants_text(), encoding="utf-8")
    value["safety"]["approval"]["control_file"] = str(approvals)
    value["safety"]["approval"]["replay_store"] = {
        "sqlite_path": str(work / "c7-approval-replay.sqlite"),
    }
    rules = value["safety"]["tools"]
    if [rule.get("name") for rule in rules] != TOOLS or any(rule.get("mode") != "guard" for rule in rules):
        raise gp.DemoFailure(f"unexpected C7 Safety scaffold: {rules}")
    for rule in rules:
        rule["_comment"] = (
            "reviewed C7 mapping: every call is Safety-guarded and covered by the active "
            "Consensus, Convergence, Linear, and Budget gates; the narrow Temporal policy "
            "uses compose.allow only as trigger and deny.temporal only as forbidden"
        )
        rule["_seal_demo_tier"] = C7_TIER

    value["temporal"] = {"policies": [TEMPORAL_POLICY]}
    value["consensus"] = {
        "roster": ROSTER, "votes_file": str(votes), "high_stakes": TOOLS,
    }
    value["convergence"] = {
        "tools": [{"tool": tool, "op_arg": "op"} for tool in TOOLS],
    }
    value["linear"] = {
        "grants_file": str(grants),
        "tools": [{"tool": tool, "cap_arg": "capability.id"} for tool in TOOLS],
    }
    value["budget"] = {
        "budgets": [{
            "name": "c7-token-budget", "cap": CAP, "tools": TOOLS,
            "cost_arg": "usage.tokens",
        }],
    }
    after = json.dumps(value, indent=2) + "\n"
    if "EDIT-ME" in after:
        raise gp.DemoFailure("reviewed C7 policy still contains EDIT-ME")
    print("\n=== VISIBLE INIT + ADD-KERNEL T/C/V/L/B REVIEW / RUNTIME EDIT ===")
    print("".join(unified_diff(
        before.splitlines(True), after.splitlines(True),
        fromfile="incremental six-kernel scaffold", tofile="reviewed C7 S+T+C+V+L+B",
    )))
    policy.write_text(after, encoding="utf-8")

    config_key = work / "c7-policy-signing.seed"
    approval_key = work / "c7-approval-signing.seed"
    config_key.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    approval_key.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    os.chmod(config_key, 0o600)
    os.chmod(approval_key, 0o600)
    config_pub = gp.node_public_key(config_key)
    approval_pub = gp.node_public_key(approval_key)
    if config_pub == approval_pub:
        raise gp.DemoFailure("policy and approval keys unexpectedly match")
    trusted = work / "c7-composition.policy.signed.json"
    signed = gp.run([
        str(seal), "policy", "sign", str(policy), "--key", str(config_key),
        "--out", str(trusted), "--yes",
    ])
    signed_output = (signed.stdout or "") + (signed.stderr or "")
    for required in [
        "ACTIVE (6):", "Safety (S)", "Temporal (T)", "Consensus (C)",
        "Convergence (V)", "Linear (L)", "Budget (B)",
        "PRESENT-BUT-INACTIVE (0):", "ABSENT/OFF (1):", "Calibration (K, EXPERIMENTAL)",
    ]:
        if required not in signed_output:
            raise gp.DemoFailure(f"signed C7 participation missing {required!r}")
    active_line = "ACTIVE {S,T,C,V,L,B}; PRESENT-BUT-INACTIVE {}; K absent"
    check("six-kernel signed policy", f"{active_line}; zero placeholders")
    return policy, trusted, config_pub, approval_key, approval_pub, approvals, votes


def cap_for(tool: str) -> str:
    return f"c7-cap-{tool.replace('.', '-')}"


def arguments_for(tool: str) -> dict:
    operation = NONCONVERGENT_OP if tool == DENY_TOOLS["convergence"] else CONVERGENT_OP
    capability = "c7-cap-missing" if tool == DENY_TOOLS["linear"] else cap_for(tool)
    cost = OVER_COST if tool == DENY_TOOLS["budget"] else NORMAL_COST
    return {
        "op": operation,
        "capability": {"id": capability},
        "usage": {"tokens": cost},
        "payload": f"c7:{tool}",
    }


def votes_for(tool: str) -> str:
    voters = [101] if tool == DENY_TOOLS["consensus"] else [101, 202]
    return "\n".join(
        json.dumps({"acceptor": voter, "value": tool}, separators=(",", ":"))
        for voter in voters
    ) + "\n"


def grants_text() -> str:
    lines = []
    for tool in TOOLS:
        if tool == DENY_TOOLS["linear"]:
            continue
        lines.append(json.dumps({"cap": cap_for(tool), "uses": 1}, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def stable_hash_parts(parts: list[str]) -> str:
    framed = "".join(f"{len(part)}:{part}" for part in parts)
    return hashlib.sha256(framed.encode("utf-8")).hexdigest()


def approval_target(tool: str, arguments: dict) -> str:
    canonical_args = json.dumps(arguments, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return stable_hash_parts([SERVER_IDENTITY, tool, canonical_args])


def signed_token(key: Path, tool: str, arguments: dict) -> dict:
    return gp.approval_token(
        key, approval_target(tool, arguments), f"c7-{tool.replace('.', '-')}-{uuid.uuid4().hex}",
    )


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
                 approvals: Path, work: Path, adapter: Path):
        self.tokens = approvals
        self.receipts = work / "c7-receipts"
        self.proc = gp.LineProcess(host_command(
            trusted, config_pub, approval_pub, self.tokens, self.receipts, adapter,
        ))
        self.proc.send(gp.request(100, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "seal-c7", "version": "1"},
        }))
        json.loads(self.proc.line())
        self.proc.send(gp.request(101, "tools/list"))
        json.loads(self.proc.line())
        self.wait_stderr("SEAL_C7_ADAPTER_READY")

    def wait_stderr(self, marker: str, timeout: float = 5) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(marker in line for line in self.proc.stderr_lines):
                return
            time.sleep(0.02)
        raise gp.DemoFailure(f"C7 stderr marker missing: {marker}")

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

    def execution_count(self) -> int:
        return sum("SEAL_C7_EXECUTED" in line for line in self.proc.stderr_lines)

    def close(self) -> None:
        self.proc.close()


def require_cert(record: dict, kernel: str, verdict: str, reason: str | None = None) -> None:
    matches = [cert for cert in record.get("certs", []) if cert.get("kernel") == kernel]
    if len(matches) != 1 or matches[0].get("verdict") != verdict:
        raise gp.DemoFailure(f"missing {kernel}:{verdict} certificate: {record.get('certs')}")
    if reason is not None and matches[0].get("reason") != reason:
        raise gp.DemoFailure(f"unexpected {kernel} reason: {matches[0].get('reason')}")


def hero_series(trusted: Path, config_pub: str, approval_key: Path, approval_pub: str,
                approvals: Path, votes: Path, work: Path, adapter: Path) -> dict:
    arguments = [arguments_for(tool) for tool in ORDERED_TOOLS]
    session = HostSession(trusted, config_pub, approval_pub, approvals, work, adapter)
    try:
        for tool, args in zip(ORDERED_TOOLS, arguments):
            if tool != DENY_TOOLS["safety"]:
                session.append(signed_token(approval_key, tool, args))

        receipts = []
        records = []
        responses = []
        for index, (role, tool, args, expected_deny) in enumerate(
                zip(ROLES, ORDERED_TOOLS, arguments, DENY_KERNELS), 1):
            votes.write_text(votes_for(tool), encoding="utf-8")
            response, receipt = session.call(tool, args)
            record = json.loads(receipt.read_text(encoding="utf-8"))
            expected_verdict = "ALLOW" if expected_deny is None else "BLOCK"
            if record.get("verdict") != expected_verdict or record.get("deny_kernel") != expected_deny:
                raise gp.DemoFailure(
                    f"{role} expected {expected_verdict}/{expected_deny}, got "
                    f"{record.get('verdict')}/{record.get('deny_kernel')} certs={record.get('certs')}"
                )
            if response.get("result", {}).get("isError") is not (expected_deny is not None):
                raise gp.DemoFailure(f"{role} downstream response disagrees with mediated verdict: {response}")
            expected_kernels = ["safety", "temporal", "consensus", "convergence", "linear", "budget"]
            if [cert.get("kernel") for cert in record.get("certs", [])] != expected_kernels:
                raise gp.DemoFailure(f"{role} certificate set/order drift: {record.get('certs')}")
            denied = [cert.get("kernel") for cert in record["certs"] if cert.get("verdict") == "deny"]
            if denied != ([] if expected_deny is None else [expected_deny]):
                raise gp.DemoFailure(f"{role} is not an isolated one-kernel veto: {denied}")
            require_cert(record, "safety", "deny" if expected_deny == "safety" else "allow")
            require_cert(record, "temporal", "deny" if expected_deny == "temporal" else "allow")
            require_cert(record, "consensus", "deny" if expected_deny == "consensus" else "allow")
            require_cert(record, "convergence", "deny" if expected_deny == "convergence" else "allow")
            require_cert(record, "linear", "deny" if expected_deny == "linear" else "allow")
            require_cert(record, "budget", "deny" if expected_deny == "budget" else "allow")
            receipts.append(receipt)
            records.append(record)
            responses.append(response)
            expected_executions = 1 if index >= 1 else 0
            if session.execution_count() != expected_executions:
                raise gp.DemoFailure(f"{role} changed downstream count to {session.execution_count()}")

        check(
            "composed-ALLOW headline",
            "one mediated ALLOW; all six ACTIVE kernel certificates are ALLOW; downstream executed once",
        )
        for kernel, symbol in [
            ("safety", "S"), ("temporal", "T"), ("consensus", "C"),
            ("convergence", "V"), ("linear", "L"), ("budget", "B"),
        ]:
            check(
                f"{symbol}-only AND-gate veto",
                f"exactly {kernel} DENY; other five certificates ALLOW; downstream count remains one",
            )
        return {
            "receipt_root": session.receipts,
            "receipts": receipts,
            "records": records,
            "arguments": arguments,
            "responses": responses,
        }
    finally:
        session.close()


def replay_input(record: dict, approvals: list[dict], votes: str, grants: str) -> dict:
    return {
        "line": record["canonical_request"], "now": record["now"],
        "approvals": approvals, "votes": votes, "grants": grants, "forecasts": "",
    }


def build_transcript(artifact_dir: Path, flow: dict) -> tuple[Path, str]:
    records = flow["records"]
    receipts = flow["receipts"]
    if any(record.get("signed_config") != records[0].get("signed_config") for record in records[1:]):
        raise gp.DemoFailure("C7 receipts disagree on the one signed config")
    wasm_sha = records[0].get("kernel_identity", {}).get("wasm_sha256")
    if any(record.get("kernel_identity", {}).get("wasm_sha256") != wasm_sha for record in records[1:]):
        raise gp.DemoFailure("C7 receipts disagree on vendored WASM identity")
    steps = []
    for sequence, (role, receipt, record) in enumerate(zip(ROLES, receipts, records), 1):
        receipt_bytes = receipt.read_bytes()
        approvals = [{"target": item["target"]} for item in record.get("granted_capabilities", [])]
        steps.append({
            "sequence": sequence,
            "role": role,
            "canonical_request": record["canonical_request"],
            "canonical_request_sha256": record["canonical_request_sha256"],
            "step_input": replay_input(
                record, approvals, votes_for(record["tool"]), grants_text() if sequence == 1 else "",
            ),
            "raw_kernel_output": record["emitted_bytes"],
            "receipt_path": f"receipts/step-{sequence:02d}-{receipt.name}",
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "receipt_bytes_base64": base64.b64encode(receipt_bytes).decode("ascii"),
        })
    transcript = {
        "schema": "seal-demo-trace-transcript/v1",
        "demo_id": "c7",
        "harness": "demo/trace_replay.cjs",
        "kit_commit": gp.run(["git", "rev-parse", "HEAD"], cwd=KIT).stdout.strip(),
        "wasm_sha256": wasm_sha,
        "signed_config": records[0]["signed_config"],
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


def exercise_trace_controls(transcript: Path, transcript_sha: str) -> dict:
    full = gp.run(replay_command(transcript))
    if "PASS trace transcript steps=7" not in full.stdout:
        raise gp.DemoFailure("C7 full transcript replay did not pass all seven steps")

    dropped = gp.run(replay_command(transcript, "--drop-trigger"), expect=1)
    dropped_output = (dropped.stdout or "") + (dropped.stderr or "")
    if "byte mismatch" not in dropped_output:
        raise gp.DemoFailure("C7 drop-trigger control did not change the transcript bytes")

    original = transcript.read_bytes()
    marker = b'\\"route\\":\\"block\\"'
    start = original.find(marker)
    if start < 0:
        raise gp.DemoFailure("cannot locate a C7 BLOCK route byte for transcript control")
    offset = start + len(b'\\"route\\":\\"')
    tampered = bytearray(original)
    tampered[offset] = ord("c") if tampered[offset] != ord("c") else ord("b")
    transcript.write_bytes(tampered)
    flipped = gp.run(replay_command(transcript), expect=1)
    flipped_output = (flipped.stdout or "") + (flipped.stderr or "")
    if "transcript raw output differs from embedded runtime receipt" not in flipped_output and "byte mismatch" not in flipped_output:
        transcript.write_bytes(original)
        raise gp.DemoFailure("C7 transcript byte flip failed for an unrelated reason")
    transcript.write_bytes(original)
    restored_sha = hashlib.sha256(transcript.read_bytes()).hexdigest()
    if restored_sha != transcript_sha or transcript.read_bytes() != original:
        raise gp.DemoFailure("C7 transcript did not restore byte-exact")
    restored = gp.run(replay_command(transcript))
    if "PASS trace transcript steps=7" not in restored.stdout:
        raise gp.DemoFailure("restored C7 transcript did not replay")
    check(
        "trace transcript controls",
        "full replay PASS; drop-trigger mismatch; byte-flip mismatch; restore SHA match + PASS",
    )
    return {
        "exit_code": flipped.returncode,
        "original_sha256": transcript_sha,
        "restored_sha256": restored_sha,
    }


def standalone_scope(seal: Path, receipt: Path, live_verdict: str) -> dict:
    result = subprocess.run(
        [str(seal), "verify", str(receipt)], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    output = (result.stdout or "") + (result.stderr or "")
    match = re.search(r"re-derived (ALLOW|BLOCK) / claimed (ALLOW|BLOCK)", output)
    if result.returncode == 0 or "FAIL  NOT VERIFIED" not in output or not match:
        raise gp.DemoFailure(f"C7 receipt unexpectedly standalone-verifiable: {receipt}\n{output}")
    return {
        "command": "seal verify",
        "status": "TRACE-SCOPED",
        "exit_code": result.returncode,
        "rederived_verdict": match.group(1),
        "live_session_verdict": live_verdict,
        "artifact_lane_reason": (
            "combined receipt omits Consensus votes and Linear grant events; C7 also carries "
            "session-scoped Temporal/Linear/Budget state"
        ),
    }


def budget_evidence(index: int, deny_kernel: str | None) -> dict:
    before = CAP if index == 0 else CAP - NORMAL_COST
    cost = OVER_COST if deny_kernel == "budget" else NORMAL_COST
    after = before - cost if deny_kernel is None else before
    return {
        "name": "c7-token-budget", "cost_arg": "usage.tokens", "cap": CAP,
        "remaining_before": before, "remaining_after": after,
    }


def linear_evidence(tool: str, index: int, deny_kernel: str | None) -> dict:
    capability = arguments_for(tool)["capability"]["id"]
    missing = deny_kernel == "linear"
    return {
        "cap_arg": "capability.id",
        "capability_id": capability,
        "grant_events": 6 if index == 0 else 0,
        "remaining_before": 0 if missing else 1,
        "remaining_after": 0 if (deny_kernel is None or missing) else 1,
        "consumed": deny_kernel is None,
    }


def consensus_evidence(tool: str, deny_kernel: str | None) -> dict:
    votes = 1 if deny_kernel == "consensus" else 2
    return {
        "roster": ROSTER, "value": tool, "votes": votes,
        "required": 2, "quorum_met": votes == 2,
    }


def convergence_evidence(tool: str, deny_kernel: str | None) -> dict:
    operation = arguments_for(tool)["op"]
    return {
        "tool": tool, "op_arg": "op", "operation": operation,
        "in_proven_set": deny_kernel != "convergence",
        "proven_set": PROVEN_CONVERGENT_OPS,
        "stateful": False,
        "claim_scope": (
            "this specific operation was mediated under the fixed kernel set; "
            "no universal replicated-store convergence claim"
        ),
    }


def temporal_evidence(tool: str, index: int, deny_kernel: str | None) -> dict:
    value = {
        "policy_name": TEMPORAL_POLICY["name"],
        "policy_type": "no_after",
        "trigger": TEMPORAL_POLICY["trigger"],
        "forbidden": TEMPORAL_POLICY["forbidden"],
        "trace_events_before": 0 if index == 0 else 1,
        "trace_events_after": 1,
        "trace_evidence": (
            "theorem:Host.registry_deny_temporal_frozen"
            if deny_kernel is not None else "runtime-certificate:trace ok (1 events)"
        ),
        "freeze_scope": (
            "compose.allow armed only the dedicated deny.temporal veto"
            if index == 0 else f"this specific {tool} call under the armed C7 policy"
        ),
        "wall_clock_claim": False,
    }
    if deny_kernel is not None:
        value["deny_state"] = {
            "trace_theorem": "Host.registry_deny_temporal_frozen",
            "capability_consumed": False,
            "capability_theorem": "Host.registry_deny_no_capability_consumed",
        }
    return value


def theorem_ids_for(index: int, deny_kernel: str | None) -> list[str]:
    if index == 0:
        return [
            "Host.registry_closed_algebra", "Host.composed_non_bypass",
            "Host.composed_temporal_safety", "Host.composed_no_conflicting_agreement",
            "Host.composed_convergent", "Host.composed_linear_conservation",
            "Host.composed_budget_cap",
        ]
    ids = ["Host.pureCommit_deny_of_member", "Host.registry_deny_no_capability_consumed", "Host.registry_deny_no_budget_spend"]
    if deny_kernel == "temporal":
        ids.append("Host.registry_deny_temporal_frozen")
    if deny_kernel == "convergence":
        ids.append("Kernels.convergence_verdict_allow_iff")
    return ids


def verify_scan(seal: Path, manifest: Path, policy: Path) -> None:
    scanned = gp.run([str(seal), "scan", str(manifest), str(policy)])
    if "ACTIVE (6)" not in scanned.stdout or "PRESENT-BUT-INACTIVE (0)" not in scanned.stdout:
        raise gp.DemoFailure("C7 scan did not report exactly six active kernels")
    if "Calibration (K, EXPERIMENTAL)" not in scanned.stdout or "ABSENT/OFF (1)" not in scanned.stdout:
        raise gp.DemoFailure("C7 scan did not report Calibration absent")
    if not re.search(r"^\s*PASS\s+0 uncovered, 0 ungated,", scanned.stdout, re.M):
        raise gp.DemoFailure("C7 scan did not report clean finite manifest coverage")
    check("seal scan composition", "ACTIVE {S,T,C,V,L,B}; K absent; zero vacuous, uncovered, or ungated tools")


def boundary_card() -> None:
    print("""
===================== C7 FLAGSHIP COMPOSITION BOUNDARY =====================
PROVEN REFERENCE ENFORCEMENT
  Host.registry_closed_algebra: one composed ALLOW carries every present
  Safety, Temporal, Consensus, Convergence, Linear, and Budget invariant.
RUNTIME EVIDENCE
  One signed six-kernel policy; one all-six-certificate ALLOW; then exactly one
  isolated S/T/C/V/L/B veto per call. Only the headline reached the adapter;
  every denial left candidate Linear and Budget spend uncommitted.
NON-CLAIM
  Each receipt attests only this mediated call under the signed policy. It does
  not establish intent, full-system non-occurrence, or the H1 topology x config
  matrix. Calibration K is deliberately omitted because it is experimental.
=============================================================================
""", flush=True)
    check("boundary card", "mediation-only composed-ALLOW scope and fixed non-claims printed")


def execute(artifact_dir: Path, color: str) -> int:
    preflight()
    gp.build_named_targets()
    with tempfile.TemporaryDirectory(prefix="seal-c7-composition-") as td:
        work = Path(td)
        adapter = write_adapter(work)
        seal = gp.temporary_install(work)
        manifest = capture_manifest(adapter, work)
        policy, trusted, config_pub, approval_key, approval_pub, approvals, votes = prepare_policy(
            seal, manifest, work,
        )
        flow = hero_series(
            trusted, config_pub, approval_key, approval_pub, approvals, votes, work, adapter,
        )
        transcript, transcript_sha = build_transcript(artifact_dir, flow)
        control = exercise_trace_controls(transcript, transcript_sha)
        standalone = [
            standalone_scope(seal, receipt, "ALLOW" if index == 0 else "BLOCK")
            for index, receipt in enumerate(flow["receipts"])
        ]

        trace = DemoTrace(artifact_dir, "c7", seal, C7_THEOREMS, color)
        trace.configure(
            "init+add-kernel-T+C+V+L+B", policy,
            active=["safety", "temporal", "consensus", "convergence", "linear", "budget"],
            inactive=[], experimental=[],
            trace_transcript={
                "path": "trace-transcript.json", "sha256": transcript_sha,
                "wasm_sha256": flow["records"][0]["kernel_identity"]["wasm_sha256"],
                "harness": "demo/trace_replay.cjs", "status": "PASS",
                "lanes": {
                    "standalone": "not applicable: every receipt includes omitted votes/grants evidence",
                    "trace": "one init plus seven ordered requests/events; raw outputs byte-compared",
                },
            },
        )
        for index, (role, tool, deny_kernel, receipt) in enumerate(
                zip(ROLES, ORDERED_TOOLS, DENY_KERNELS, flow["receipts"])
        ):
            trace.record_receipt(
                receipt, role=role, theorem_ids=theorem_ids_for(index, deny_kernel),
                budget=budget_evidence(index, deny_kernel),
                temporal=temporal_evidence(tool, index, deny_kernel),
                consensus=consensus_evidence(tool, deny_kernel),
                linear=linear_evidence(tool, index, deny_kernel),
                convergence=convergence_evidence(tool, deny_kernel),
                verification_lane="trace", requires_trace=transcript_sha,
                standalone_failure=standalone[index],
            )
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "trace_replay", "status": "PASS",
            "transcript_path": "trace-transcript.json", "transcript_sha256": transcript_sha,
            "wasm_sha256": flow["records"][0]["kernel_identity"]["wasm_sha256"],
            "steps": 7, "harness": "demo/trace_replay.cjs",
        })
        for name, expected, evidence in [
            ("drop-trigger", "BYTE-MISMATCH", "without COMPOSED-ALLOW, approval/grant/Temporal state differs"),
            ("byte-flip", "FAIL", "one byte flipped in a denied raw kernel output"),
            ("restore", "SHA-MATCH+PASS", f"restored transcript sha256={transcript_sha}; full ordered replay PASS"),
        ]:
            trace.emit({
                "schema": "seal-demo-trace/v1", "event": "trace_negative_control",
                "name": name, "expected": expected, "observed": expected, "status": "PASS",
                "evidence": evidence,
            })
        trace.emit({
            "schema": "seal-demo-trace/v1", "event": "anti_forge", "subject": "trace-transcript",
            "receipt_path": "trace-transcript.json", "mutation": "one byte flipped in denied raw output",
            "tampered_verify_exit": control["exit_code"],
            "original_sha256": control["original_sha256"],
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
        parser.error("C7 is a deterministic evidence demo; --deterministic is required")
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
