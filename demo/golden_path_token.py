#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""C4 token governor: deterministic LLM-call mediation with Safety + Budget."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
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
PHASE_B_KIT_REV = "962823b22d179f3354f8b8cf1a7091029a23c715"
SERVER_IDENTITY = "seal-token-governor-demo@1.0.0"
TOOL = "llm_call"
CAP = 10
OVER_COST = 11
RETRY_COST = 4
C4_THEOREMS = [
    "BudgetCore.over_budget_denied",
    "Host.composed_budget_cap",
    "Host.registry_closed_algebra",
    "Host.registry_deny_no_budget_spend",
]

C4_TIER = {
    "tier": "dev-box deterministic-tested (local run); CI configured but not run; operator-verified: NO",
    "evidence_scope": (
        "real nested usage.tokens costArg, over-cap Budget denial, exact in-budget retry, "
        "one downstream execution, every receipt verified, anti-forge rejection, and scan passed"
    ),
    "proven": "Safety+Budget reference invariants are machine-checked; this integration is not universally proven",
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
    "name": "llm_call",
    "description": "Call an LLM model with an explicit token charge for reviewed Budget accounting.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "prompt": {"type": "string"},
            "usage": {
                "type": "object",
                "properties": {"tokens": {"type": "integer", "minimum": 0}},
                "required": ["tokens"],
                "additionalProperties": False,
            },
        },
        "required": ["prompt", "usage"],
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

print("SEAL_TOKEN_ADAPTER_READY", file=sys.stderr, flush=True)
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
            "serverInfo": {"name": "seal-token-governor-demo", "version": "1.0.0"},
        }})
    elif method == "tools/list":
        print("SEAL_TOKEN_TOOLS_LIST_RECEIVED", file=sys.stderr, flush=True)
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        usage = args.get("usage")
        tokens = usage.get("tokens") if isinstance(usage, dict) else None
        prompt = args.get("prompt")
        if name != "llm_call":
            result(mid, "unknown tool", True)
        elif not isinstance(prompt, str) or not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0:
            result(mid, "adapter requires prompt:string and usage.tokens:natural", True)
        else:
            digest = hashlib.sha256(prompt.encode()).hexdigest()[:16]
            print(f"SEAL_LLM_CALL_RECEIVED usage.tokens={tokens} prompt_sha256={digest}", file=sys.stderr, flush=True)
            result(mid, f"deterministic-llm-ok tokens={tokens} prompt_sha256={digest}")
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
    path = work / "token_mcp_server.py"
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
            "clientInfo": {"name": "seal-c4-capture", "version": "1"},
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
            raise gp.DemoFailure(f"unexpected live token manifest: {manifest}")
        path = work / "token-governor.tools.json"
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        check("live tools/list manifest", "captured real llm_call schema with nested usage.tokens natural")
        return path
    finally:
        proc.close()


def prepare_policy(seal: Path, manifest: Path, work: Path):
    policy = work / "token-governor.policy.json"
    init = gp.run([str(seal), "init", "--recipe", "token-governor", str(manifest), "--out", str(policy)])
    output = (init.stdout or "") + (init.stderr or "")
    if "ACTIVE {S,B}" not in output or "PRESENT-BUT-INACTIVE {}" not in output:
        raise gp.DemoFailure("token-governor recipe did not report exactly ACTIVE {S,B}")
    before = policy.read_text(encoding="utf-8")
    value = json.loads(before)
    budgets = value.get("budget", {}).get("budgets", [])
    expected = [{"name": "token-usage", "cap": 0, "tools": [TOOL], "cost_arg": "usage.tokens"}]
    if budgets != expected:
        raise gp.DemoFailure(f"token-governor recipe drift: {budgets}")
    approvals = work / "token-approvals.ndjson"
    approvals.write_text("", encoding="utf-8")
    replay = work / "token-approval-replay.sqlite"
    value["safety"]["approval"]["control_file"] = str(approvals)
    value["safety"]["approval"]["replay_store"] = {
        "sqlite_path": str(replay),
        "schema_version": 2,
        "namespace_encoding_version": 1,
    }
    value["budget"]["budgets"][0]["cap"] = CAP
    rules = value["safety"]["tools"]
    if len(rules) != 1 or rules[0]["name"] != TOOL or rules[0]["mode"] != "guard":
        raise gp.DemoFailure(f"unexpected Safety scaffold: {rules}")
    rules[0]["_comment"] = (
        "reviewed C4 mapping: llm_call is Safety-guarded; Budget charges the actual nested "
        "usage.tokens natural supplied in the tool schema; fixed demonstration cap=10"
    )
    rules[0]["_seal_demo_tier"] = C4_TIER
    after = json.dumps(value, indent=2) + "\n"
    if "EDIT-ME" in after:
        raise gp.DemoFailure("reviewed token-governor policy still contains EDIT-ME")
    print("\n=== VISIBLE TOKEN-GOVERNOR RECIPE REVIEW / RUNTIME EDIT ===")
    print("".join(unified_diff(
        before.splitlines(True), after.splitlines(True),
        fromfile="token-governor scaffold", tofile="reviewed C4 S+B",
    )))
    policy.write_text(after, encoding="utf-8")

    config_key = work / "token-policy-signing.seed"
    approval_key = work / "token-approval-signing.seed"
    config_key.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    approval_key.write_text(os.urandom(32).hex() + "\n", encoding="utf-8")
    os.chmod(config_key, 0o600)
    os.chmod(approval_key, 0o600)
    config_pub = gp.node_public_key(config_key)
    approval_pub = gp.node_public_key(approval_key)
    if config_pub == approval_pub:
        raise gp.DemoFailure("policy and approval keys unexpectedly match")
    trusted = work / "token-governor.policy.signed.json"
    signed = gp.run([
        str(seal), "policy", "sign", str(policy), "--key", str(config_key),
        "--out", str(trusted), "--yes",
    ])
    signed_output = (signed.stdout or "") + (signed.stderr or "")
    if "ACTIVE (2)" not in signed_output or "PRESENT-BUT-INACTIVE (0)" not in signed_output:
        raise gp.DemoFailure("sign acknowledgement did not report exactly two active kernels")
    gp.initialize_replay_store(trusted, config_pub)
    check("token recipe review + signed policy", "ACTIVE {S,B}; cap=10; costArg=usage.tokens; zero placeholders")
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
            "clientInfo": {"name": "seal-c4", "version": "1"},
        }))
        json.loads(self.proc.line())
        self.proc.send(gp.request(101, "tools/list"))
        json.loads(self.proc.line())
        self.wait_stderr("SEAL_TOKEN_ADAPTER_READY")

    def wait_stderr(self, text: str, timeout: float = 5) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(text in line for line in self.proc.stderr_lines):
                return
            time.sleep(0.02)
        raise gp.DemoFailure(f"token session stderr marker missing: {text}")

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
                raise gp.DemoFailure(f"multiple receipts for one llm_call: {created}")
            time.sleep(0.02)
        raise gp.DemoFailure("receipt missing for llm_call")

    def marker_count(self) -> int:
        return sum("SEAL_LLM_CALL_RECEIVED" in line for line in self.proc.stderr_lines)

    def close(self) -> None:
        self.proc.close()


def signed_token(key: Path, refusal: dict, label: str) -> dict:
    return gp.approval_token(key, refusal, f"c4-{label}-{uuid.uuid4().hex}")


def receipt_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_receipt(seal: Path, receipt: Path, verdict: str) -> dict:
    record = receipt_json(receipt)
    rules = record.get("kernel_config", {}).get("safety", {}).get("tools", [])
    if not rules or rules[0].get("_seal_demo_tier") != C4_TIER:
        raise gp.DemoFailure(f"receipt tier mismatch: {receipt}")
    result = gp.run([str(seal), "verify", str(receipt)])
    if "PASS  VERIFIED (bundled self-check; not independent verification)" not in result.stdout or record.get("verdict") != verdict:
        raise gp.DemoFailure(f"receipt decision was not reproduced as {verdict}: {receipt}")
    return record


def assert_block(response: dict, text: str) -> None:
    if response.get("result", {}).get("isError") is not True or text.lower() not in gp.compact(response).lower():
        raise gp.DemoFailure(f"expected BLOCK containing {text!r}, got {response}")


def assert_allow(response: dict) -> None:
    if response.get("result", {}).get("isError") is not False:
        raise gp.DemoFailure(f"expected forwarded success, got {response}")


def require_cert(record: dict, kernel: str, verdict: str, reason: str | None = None) -> None:
    matches = [cert for cert in record.get("certs", []) if cert.get("kernel") == kernel]
    if len(matches) != 1 or matches[0].get("verdict") != verdict:
        raise gp.DemoFailure(f"missing {kernel}:{verdict} certificate: {record.get('certs')}")
    if reason is not None and matches[0].get("reason") != reason:
        raise gp.DemoFailure(f"unexpected {kernel} reason: {matches[0].get('reason')}")


def hero_pair(seal: Path, trusted: Path, config_pub: str, approval_key: Path,
              approval_pub: str, work: Path, adapter: Path, trace: DemoTrace) -> Path:
    prompt = "Summarize the ratified demo doctrine in one sentence."
    over_args = {"prompt": prompt, "usage": {"tokens": OVER_COST}}
    retry_args = {"prompt": prompt, "usage": {"tokens": RETRY_COST}}
    session = HostSession(trusted, config_pub, approval_pub, work, adapter)
    try:
        over_refusal, over_discovery = session.call(over_args)
        assert_block(over_refusal, "approval required")
        trace.record_receipt(
            over_discovery, role=gp.APPROVAL_SUBJECT_ROLE,
            theorem_ids=["BudgetCore.over_budget_denied", "Host.registry_deny_no_budget_spend"],
        )
        session.append(signed_token(approval_key, over_refusal, "over-cap"))
        denied, deny_receipt = session.call(over_args)
        assert_block(denied, "over budget token-usage (0+11>10)")
        deny_record = verify_receipt(seal, deny_receipt, "BLOCK")
        if deny_record.get("deny_kernel") != "budget":
            raise gp.DemoFailure(f"first call deny_kernel is not budget: {deny_record.get('deny_kernel')}")
        require_cert(deny_record, "safety", "allow", gp.target_from(over_refusal))
        require_cert(deny_record, "budget", "deny", "over budget token-usage (0+11>10): llm_call")
        if session.marker_count() != 0:
            raise gp.DemoFailure("over-budget llm_call reached the adapter")
        trace.record_receipt(
            deny_receipt, role="ATTACK-DENY",
            theorem_ids=["BudgetCore.over_budget_denied", "Host.registry_deny_no_budget_spend"],
            budget={
                "name": "token-usage", "cost_arg": "usage.tokens", "cap": CAP,
                "remaining_before": CAP, "remaining_after": CAP,
            },
        )

        retry_refusal, retry_discovery = session.call(retry_args)
        assert_block(retry_refusal, "approval required")
        trace.record_receipt(
            retry_discovery, role=gp.APPROVAL_SUBJECT_ROLE,
            theorem_ids=["BudgetCore.over_budget_denied", "Host.registry_deny_no_budget_spend"],
        )
        session.append(signed_token(approval_key, retry_refusal, "retry"))
        allowed, allow_receipt = session.call(retry_args)
        assert_allow(allowed)
        allow_record = verify_receipt(seal, allow_receipt, "ALLOW")
        require_cert(allow_record, "safety", "allow", gp.target_from(retry_refusal))
        require_cert(allow_record, "budget", "allow", "within budget: llm_call")
        if session.marker_count() != 1:
            raise gp.DemoFailure(f"in-budget retry downstream count != 1: {session.marker_count()}")
        response_text = allowed["result"]["content"][0]["text"]
        if f"tokens={RETRY_COST}" not in response_text:
            raise gp.DemoFailure(f"deterministic adapter response lacks token evidence: {response_text}")
        trace.record_receipt(
            allow_receipt, role="LEGIT",
            theorem_ids=["Host.composed_budget_cap", "Host.registry_closed_algebra"],
            budget={
                "name": "token-usage", "cost_arg": "usage.tokens", "cap": CAP,
                "remaining_before": CAP, "remaining_after": CAP - RETRY_COST,
            },
        )
        check(
            "deny-first token governor",
            "cost 11 denied by Budget at cap 10 with remaining 10; no downstream execution",
        )
        check(
            "exact in-budget retry",
            "same llm_call prompt; usage.tokens=4 ALLOW; remaining 10->6; exactly one downstream execution",
        )
        return session.receipts
    finally:
        session.close()


def verify_scan(seal: Path, manifest: Path, policy: Path) -> None:
    scanned = gp.run([str(seal), "scan", str(manifest), str(policy)])
    if "ACTIVE (2)" not in scanned.stdout or "PRESENT-BUT-INACTIVE (0)" not in scanned.stdout:
        raise gp.DemoFailure("scan did not report exactly ACTIVE {S,B}")
    if not re.search(r"^\s*PASS\s+0 uncovered, 0 ungated,", scanned.stdout, re.M):
        raise gp.DemoFailure("scan did not report clean finite manifest coverage")
    check("seal scan composition", "ACTIVE {S,B}; zero vacuous, uncovered, or ungated tools")


def boundary_card() -> None:
    print("""
===================== C4 TOKEN GOVERNOR BOUNDARY =====================
PROVEN REFERENCE ENFORCEMENT
  Safety approval binding and the closed registry algebra; Budget over-cap
  denial, composed cap, and deny-without-budget-spend.
RUNTIME EVIDENCE
  Deterministic llm_call adapter; real nested usage.tokens costArg; first
  approved cost 11 denied at cap 10; retry cost 4 executed exactly once.
NON-CLAIM
  This deterministic adapter does not contact a live model, and its declared
  token units are demonstration inputs. Receipt claim scope remains mediation
  under the signed policy, not full-system non-occurrence.
======================================================================
""", flush=True)
    check("boundary card", "proof/runtime/non-claim boundary printed")


def execute(artifact_dir: Path, color: str) -> int:
    preflight()
    gp.build_named_targets()
    with tempfile.TemporaryDirectory(prefix="seal-token-governor-") as td:
        work = Path(td)
        adapter = write_adapter(work)
        seal = gp.temporary_install(work)
        manifest = capture_manifest(adapter, work)
        policy, trusted, config_pub, approval_key, approval_pub = prepare_policy(seal, manifest, work)
        trace = DemoTrace(artifact_dir, "c4", seal, C4_THEOREMS, color)
        trace.configure(
            "token-governor", policy,
            active=["safety", "budget"], inactive=[], experimental=[],
        )
        receipts = hero_pair(
            seal, trusted, config_pub, approval_key, approval_pub, work, adapter, trace,
        )
        verify_scan(seal, manifest, policy)
        boundary_card()
        trace.finalize([receipts])
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deterministic", action="store_true")
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    args = parser.parse_args()
    if not args.deterministic:
        parser.error("C4 is a deterministic evidence demo; --deterministic is required")
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
