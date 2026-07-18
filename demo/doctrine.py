#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reusable doctrine spine for Seal demos.

Runtime receipts are copied byte-for-byte into a durable artifact directory
and described by one NDJSON trace. Standalone receipts verify independently;
history-dependent receipts bind to a byte-replayed trace transcript. TTY and
Markdown output are projections of that trace; neither is an independent demo
script.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
PROOF_REFERENCE = ROOT / "docs" / "PROOF-REFERENCE.md"
SCHEMA = "seal-demo-trace/v1"
MANIFEST_SCHEMA = "seal-demo-proof-manifest/v1"
CLAIM_SCOPE = (
    "Attests the mediation decision under policy P, not that no side effect "
    "occurred outside the gate."
)
NON_CLAIMS = [
    "Authorization is not intent.",
    "A mediated decision does not establish full-system non-occurrence outside this gate.",
    "This illustrative combination is not the H1 topology×config proof matrix.",
    "Illustrative combo; the H1 topology×config matrix is what PROVES.",
]


class DoctrineFailure(RuntimeError):
    pass


def compact(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def argument_at_path(arguments: dict, dotted_path: str) -> object:
    if not isinstance(dotted_path, str) or not dotted_path or any(not part for part in dotted_path.split(".")):
        raise DoctrineFailure(f"invalid dotted argument path: {dotted_path!r}")
    current: object = arguments
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise DoctrineFailure(f"argument path {dotted_path!r} is missing")
        current = current[part]
    return current


def validate_budget_evidence(budget: dict, arguments: dict, *, verdict: str,
                             deny_kernel: str | None, context: str) -> dict:
    required = {"name", "cost_arg", "cap", "remaining_before", "remaining_after"}
    missing = required - budget.keys()
    if missing:
        raise DoctrineFailure(f"Budget evidence lacks {sorted(missing)} in {context}")
    if not isinstance(budget["name"], str) or not budget["name"]:
        raise DoctrineFailure(f"Budget evidence has invalid name in {context}")
    cost_arg = budget["cost_arg"]
    if cost_arg in {"path", "sql"}:
        raise DoctrineFailure(f"Budget costArg is a path/content stand-in: {cost_arg}")
    cost = argument_at_path(arguments, cost_arg)
    naturals = {
        "cost": cost,
        "cap": budget["cap"],
        "remaining_before": budget["remaining_before"],
        "remaining_after": budget["remaining_after"],
    }
    for field, value in naturals.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise DoctrineFailure(f"Budget {field} is not a natural number in {context}")
    before = budget["remaining_before"]
    after = budget["remaining_after"]
    if before > budget["cap"] or after > budget["cap"]:
        raise DoctrineFailure(f"Budget remaining value exceeds cap in {context}")
    normalized = "DENY" if verdict == "BLOCK" else verdict
    if normalized == "ALLOW":
        if cost > before or after != before - cost:
            raise DoctrineFailure(f"Budget ALLOW arithmetic is inconsistent in {context}")
    elif deny_kernel == "budget":
        if cost <= before or after != before:
            raise DoctrineFailure(f"Budget DENY must be would-exceed with unchanged state in {context}")
    elif after != before:
        raise DoctrineFailure(f"non-Budget denial changed Budget state in {context}")
    result = dict(budget)
    result["cost"] = cost
    return result


def run(command: list[str], *, cwd: Path = ROOT, expect: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != expect:
        raise DoctrineFailure(
            f"expected exit {expect}, got {result.returncode}: {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _source_roots() -> list[Path]:
    roots = [ROOT]
    packages = ROOT / ".lake" / "packages"
    if packages.is_dir():
        roots.extend(path for path in sorted(packages.iterdir()) if path.is_dir())
    return roots


def _lean_sources(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.lean"):
        if root == ROOT and ".lake" in path.parts:
            continue
        yield path


def _pin_locations(theorem_id: str) -> list[tuple[Path, int]]:
    needle = f"#print axioms {theorem_id}"
    found: list[tuple[Path, int]] = []
    for root in _source_roots():
        for path in _lean_sources(root):
            for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if needle in line:
                    found.append((path, line_no))
    return found


def _definition_location(theorem_id: str) -> tuple[Path, int]:
    basename = theorem_id.rsplit(".", 1)[-1]
    pattern = re.compile(rf"^\s*(?:theorem|def)\s+{re.escape(basename)}(?:\s|$)")
    found: list[tuple[Path, int]] = []
    for root in _source_roots():
        for path in _lean_sources(root):
            for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if pattern.search(line):
                    found.append((path, line_no))
    if len(found) != 1:
        rendered = ", ".join(f"{path}:{line}" for path, line in found) or "none"
        raise DoctrineFailure(f"theorem source must be unique for {theorem_id}; found {rendered}")
    return found[0]


def _repo_for_source(path: Path) -> tuple[Path, str, str]:
    root = ROOT if ROOT in [path, *path.parents] and ".lake" not in path.parts else None
    if root is None:
        for package in (ROOT / ".lake" / "packages").iterdir():
            if package in [path, *path.parents]:
                root = package
                break
    if root is None:
        raise DoctrineFailure(f"cannot resolve source repository for {path}")
    commit = run(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip()
    remote = run(["git", "remote", "get-url", "origin"], cwd=root).stdout.strip()
    remote = re.sub(r"^git@github\.com:", "https://github.com/", remote)
    remote = remote.removesuffix(".git")
    return root, remote, commit


def _module_for_source(repo: Path, source: Path) -> str:
    return ".".join(source.relative_to(repo).with_suffix("").parts)


def _olean_for_module(repo: Path, module: str) -> Path:
    return repo / ".lake" / "build" / "lib" / "lean" / Path(*module.split(".")).with_suffix(".olean")


def _axiom_footprints(theorems: list[str], modules: list[str]) -> tuple[dict[str, list[str]], str]:
    source = "\n".join([*(f"import {module}" for module in sorted(set(modules))), "", *(f"#print axioms {theorem}" for theorem in theorems)]) + "\n"
    with tempfile.TemporaryDirectory(prefix="seal-demo-proof-probe-") as td:
        probe = Path(td) / "ProofManifestProbe.lean"
        probe.write_text(source, encoding="utf-8")
        result = run(["lake", "env", "lean", str(probe)])
    output = (result.stdout or "") + (result.stderr or "")
    footprints: dict[str, list[str]] = {}
    for theorem in theorems:
        escaped = re.escape(theorem)
        match = re.search(rf"'{escaped}' depends on axioms: \[(.*?)\]", output, re.S)
        if match:
            footprints[theorem] = [item.strip() for item in match.group(1).split(",") if item.strip()]
        elif re.search(rf"'{escaped}' does not depend on any axioms", output):
            footprints[theorem] = []
        else:
            raise DoctrineFailure(f"Lean proof probe did not print an axiom footprint for {theorem}\n{output}")
    return footprints, sha256_bytes(output.encode())


def generate_proof_manifest(output: Path, theorem_ids: Iterable[str]) -> dict:
    theorem_ids = sorted(set(theorem_ids))
    if not theorem_ids:
        raise DoctrineFailure("proof manifest requires at least one theorem")
    if not PROOF_REFERENCE.is_file():
        raise DoctrineFailure(f"proof reference missing: {PROOF_REFERENCE}")

    gate = run(["lake", "exe", "axiom_check"])
    gate_output = (gate.stdout or "") + (gate.stderr or "")
    if "sorryAx" in gate_output or "Lean.ofReduceBool" in gate_output:
        raise DoctrineFailure("axiom gate output contains a forbidden axiom")
    # C1's concrete shell theorems live in the frozen mcp-seal dependency and
    # are pinned by its Test/Axioms module. The host runtime build does not
    # otherwise need Seal.GoldenPath, so build that dependency gate explicitly
    # before requiring its .olean in the generated manifest.
    mcp_seal = ROOT / ".lake" / "packages" / "mcp-seal"
    if mcp_seal.is_dir() and any(theorem.startswith(("Seal.", "SealV2.", "SealCore.")) for theorem in theorem_ids):
        run(["lake", "build", "axiom_check"], cwd=mcp_seal)

    pending: dict[str, dict] = {}
    modules: list[str] = []
    pin_material = bytearray()
    for theorem_id in theorem_ids:
        pins = _pin_locations(theorem_id)
        if not pins:
            raise DoctrineFailure(
                f"invented or unpinned theorem ID rejected: {theorem_id}; "
                "not present in an existing #print axioms pin"
            )
        source, source_line = _definition_location(theorem_id)
        repo, remote, commit = _repo_for_source(source)
        module = _module_for_source(repo, source)
        olean = _olean_for_module(repo, module)
        if not olean.is_file():
            raise DoctrineFailure(f"Lean build artifact missing for {theorem_id}: {olean}")
        modules.append(module)
        for pin_path, _ in pins:
            pin_material.extend(pin_path.read_bytes())
        pending[theorem_id] = {
            "theorem_name": theorem_id,
            "module": module,
            "source_path": str(source.relative_to(repo)),
            "source_line": source_line,
            "repository": remote,
            "commit_pin": commit,
            "source_url": f"{remote}/blob/{commit}/{source.relative_to(repo)}#L{source_line}",
            "olean_sha256": sha256_file(olean),
            "pin_locations": [
                {"path": str(path.relative_to(ROOT)) if ROOT in [path, *path.parents] else str(path), "line": line}
                for path, line in pins
            ],
        }

    footprints, probe_sha = _axiom_footprints(theorem_ids, modules)
    for theorem_id in theorem_ids:
        pending[theorem_id]["axioms"] = footprints[theorem_id]

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "generated_from": {
            "seal_host_commit": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
            "lean_toolchain": (ROOT / "lean-toolchain").read_text(encoding="utf-8").strip(),
            "axiom_gate": "PASS",
            "axiom_probe_sha256": probe_sha,
            "proof_reference_sha256": sha256_file(PROOF_REFERENCE),
            "pin_sources_sha256": sha256_bytes(bytes(pin_material)),
        },
        "proofs": pending,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def _participation_label(name: str, active: list[str], inactive: list[str], experimental: list[str]) -> str:
    normal = name.lower()
    for label, values in (("ACTIVE", active), ("PRESENT-BUT-INACTIVE", inactive), ("EXPERIMENTAL", experimental)):
        if any(value.lower() == normal for value in values):
            return label
    return "ABSENT/OFF"


def _color(text: str, code: str, enabled: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if enabled else text


def render_tty_event(event: dict, *, color: bool) -> None:
    kind = event.get("event")
    if kind == "demo_metadata":
        print(f"policy_recipe={event['policy_recipe']} config_sha256={event['config_sha256']}")
        print(f"ACTIVE={{{','.join(event['active'])}}}")
        print(f"PRESENT-BUT-INACTIVE={{{','.join(event['present_but_inactive'])}}}")
        print(f"EXPERIMENTAL={{{','.join(event['experimental'])}}}")
    elif kind == "step":
        verdict = event["verdict"]
        decorated = _color(verdict, "31;1" if verdict == "DENY" else "32;1", color)
        print(f"{decorated} {event['role']}  {event['tool']}  args={event['args_digest'][:16]}…")
        fired = ", ".join(
            f"{item['kernel']}:{item['verdict']}[{item['participation']}]" for item in event["kernel_fired"]
        )
        print(f"  kernel_fired={fired}; deny_kernel={event['deny_kernel'] or '-'}")
        for proof in event["proof_refs"]:
            print(f"  theorem-id={proof['theorem_id']} commit-pin={proof['commit_pin']}")
        print(
            f"  receipt-path={event['receipt_path']} verification-lane={event.get('verification_lane', 'standalone')} "
            f"seal-verify={event['seal_verify']['status']}"
        )
        if event.get("requires_trace"):
            print(f"  requires-trace={event['requires_trace']}")
        if event.get("budget"):
            budget = event["budget"]
            if event["verdict"] == "DENY" and event.get("deny_kernel") == "budget":
                remaining = (
                    f"{budget['remaining_before']}→would-exceed "
                    f"(unchanged={budget['remaining_after']})"
                )
            else:
                remaining = f"{budget['remaining_before']}→{budget['remaining_after']}"
            print(
                f"  budget={budget['name']} costArg={budget['cost_arg']} cost={budget['cost']} "
                f"cap={budget['cap']} remaining={remaining}"
            )
        if event.get("temporal"):
            temporal = event["temporal"]
            print(
                f"  temporal={temporal['policy_name']} type={temporal['policy_type']} "
                f"trigger={{{','.join(temporal['trigger'])}}} "
                f"forbidden={{{','.join(temporal['forbidden'])}}}"
            )
            print(
                f"  temporal-trace={temporal['trace_events_before']}→"
                f"{temporal['trace_events_after']} evidence={temporal['trace_evidence']}"
            )
            if temporal.get("deny_state"):
                state = temporal["deny_state"]
                print(
                    "  deny-state="
                    f"trace-unchanged[{state['trace_theorem']}]; "
                    f"capability-consumed={str(state['capability_consumed']).lower()}"
                    f"[{state['capability_theorem']}]"
                )
            print(
                f"  freeze-scope={temporal['freeze_scope']} "
                f"wall-clock-claim={str(temporal['wall_clock_claim']).lower()}"
            )
        if event.get("consensus"):
            consensus = event["consensus"]
            print(
                f"  consensus=tool-name:{consensus['value']} votes={consensus['votes']}/"
                f"{len(consensus['roster'])} required={consensus['required']} "
                f"quorum={'met' if consensus['quorum_met'] else 'short'}"
            )
        if event.get("linear"):
            linear = event["linear"]
            print(
                f"  linear={linear['capability_id']} capArg={linear['cap_arg']} "
                f"committed={linear['remaining_before']}→{linear['remaining_after']} "
                f"consumed={str(linear['consumed']).lower()}"
            )
        print(f"  {CLAIM_SCOPE}")
    elif kind == "anti_forge":
        print(
            f"ANTI-FORGE rejected exit={event['tampered_verify_exit']} "
            f"restore-byte-exact={str(event['restored_sha256'] == event['original_sha256']).lower()}"
        )
    elif kind == "trace_replay":
        print(
            f"TRACE-REPLAY {event['status']} transcript={event['transcript_path']} "
            f"sha256={event['transcript_sha256']} steps={event['steps']}"
        )
    elif kind == "trace_negative_control":
        print(
            f"TRACE-CONTROL {event['name']} expected={event['expected']} "
            f"observed={event['observed']} status={event['status']}"
        )
    elif kind == "non_claims":
        print("NON-CLAIMS")
        for line in event["lines"]:
            print(f"  - {line}")


def render_markdown(trace_path: Path, output: Path) -> str:
    events = load_trace(trace_path)
    meta = next(event for event in events if event["event"] == "demo_metadata")
    lines = [
        f"## Seal demo receipt strip — {meta['demo_id']}",
        "",
        f"- `policy_recipe`: `{meta['policy_recipe']}`",
        f"- `config_sha256`: `{meta['config_sha256']}`",
        f"- `ACTIVE`: `{meta['active']}`",
        f"- `PRESENT-BUT-INACTIVE`: `{meta['present_but_inactive']}`",
        f"- `EXPERIMENTAL`: `{meta['experimental']}`",
        "",
    ]
    for event in events:
        if event["event"] != "step":
            continue
        lines.extend([
            f"### {event['sequence']}. {event['role']} — {event['verdict']}",
            "",
            f"- Tool: `{event['tool']}`; args digest: `{event['args_digest']}`",
            f"- Kernel fired: `{event['kernel_fired']}`; deny kernel: `{event['deny_kernel']}`",
            f"- Receipt: `{event['receipt_path']}` (`{event['receipt_sha256']}`)",
            f"- Verification lane: `{event.get('verification_lane', 'standalone')}`",
            f"- `seal verify`: **{event['seal_verify']['status']}** (exit `{event['seal_verify']['exit_code']}`)",
        ])
        if event.get("requires_trace"):
            lines.append(f"- Requires trace transcript: `{event['requires_trace']}`")
        for proof in event["proof_refs"]:
            lines.append(
                f"- Theorem: [`{proof['theorem_id']}`]({proof['source_url']}) at commit `{proof['commit_pin']}`"
            )
        if event.get("budget"):
            budget = event["budget"]
            if event["verdict"] == "DENY" and event.get("deny_kernel") == "budget":
                remaining = (
                    f"`{budget['remaining_before']} → would-exceed` "
                    f"(unchanged `{budget['remaining_after']}`)"
                )
            else:
                remaining = f"`{budget['remaining_before']} → {budget['remaining_after']}`"
            lines.append(
                f"- Budget `{budget['name']}`: `costArg={budget['cost_arg']}`, cost `{budget['cost']}`, "
                f"cap `{budget['cap']}`, remaining {remaining}"
            )
        if event.get("temporal"):
            temporal = event["temporal"]
            lines.extend([
                f"- Temporal `{temporal['policy_name']}` (`{temporal['policy_type']}`): "
                f"trigger `{temporal['trigger']}`; forbidden `{temporal['forbidden']}`",
                f"- Temporal executed trace: `{temporal['trace_events_before']} → "
                f"{temporal['trace_events_after']}`; evidence: `{temporal['trace_evidence']}`",
            ])
            if temporal.get("deny_state"):
                state = temporal["deny_state"]
                lines.append(
                    f"- Deny state (theorem-backed): trace unchanged "
                    f"(`{state['trace_theorem']}`); capability consumed `false` "
                    f"(`{state['capability_theorem']}`)"
                )
            lines.append(
                f"- Freeze scope: {temporal['freeze_scope']} "
                f"Wall-clock claim: `{str(temporal['wall_clock_claim']).lower()}`"
            )
        if event.get("consensus"):
            consensus = event["consensus"]
            lines.append(
                f"- Consensus tool-name value `{consensus['value']}`: votes "
                f"`{consensus['votes']}/{len(consensus['roster'])}`; strict-majority required "
                f"`{consensus['required']}`; quorum met `{str(consensus['quorum_met']).lower()}`"
            )
        if event.get("linear"):
            linear = event["linear"]
            lines.append(
                f"- Linear `{linear['capability_id']}` via `{linear['cap_arg']}`: committed holding "
                f"`{linear['remaining_before']} → {linear['remaining_after']}`; consumed "
                f"`{str(linear['consumed']).lower()}`"
            )
        lines.extend([f"- Claim scope: {CLAIM_SCOPE}", ""])
    replays = [event for event in events if event.get("event") == "trace_replay"]
    controls = [event for event in events if event.get("event") == "trace_negative_control"]
    if replays:
        replay = replays[0]
        lines.extend([
            "### Trace transcript replay",
            "",
            f"Full ordered replay: **{replay['status']}**; transcript "
            f"`{replay['transcript_path']}` (`{replay['transcript_sha256']}`), "
            f"steps `{replay['steps']}`, pinned WASM `{replay['wasm_sha256']}`.",
            "",
        ])
        for control in controls:
            lines.append(
                f"- `{control['name']}`: expected `{control['expected']}`, "
                f"observed `{control['observed']}` — **{control['status']}**"
            )
        lines.append("")
    anti = next(event for event in events if event["event"] == "anti_forge")
    anti_subject = anti.get("subject", "receipt")
    lines.extend([
        "### Anti-forge negative control",
        "",
        f"Corrupted {anti_subject} rejected with exit `{anti['tampered_verify_exit']}`; restored SHA-256 "
        f"`{anti['restored_sha256']}` matches the original byte-for-byte.",
        "",
        "### Non-claims",
        "",
    ])
    non_claims = next(event for event in events if event["event"] == "non_claims")
    lines.extend(f"- {line}" for line in non_claims["lines"])
    text = "\n".join(lines) + "\n"
    output.write_text(text, encoding="utf-8")
    return text


def load_trace(path: Path) -> list[dict]:
    events: list[dict] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise DoctrineFailure(f"invalid NDJSON at {path}:{line_no}: {error}") from error
    return events


class DemoTrace:
    def __init__(self, artifact_dir: Path, demo_id: str, seal: Path, theorem_ids: Iterable[str], color_mode: str = "auto"):
        self.artifact_dir = artifact_dir.resolve()
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.receipt_dir = self.artifact_dir / "receipts"
        self.receipt_dir.mkdir(exist_ok=True)
        self.trace_path = self.artifact_dir / "events.ndjson"
        self.trace_path.write_text("", encoding="utf-8")
        self.manifest_path = self.artifact_dir / "proof-manifest.json"
        self.manifest = generate_proof_manifest(self.manifest_path, theorem_ids)
        self.demo_id = demo_id
        self.seal = seal
        self.color = color_mode == "always" or (color_mode == "auto" and os.isatty(1))
        self.sequence = 0
        self.recorded_sources: set[Path] = set()
        self.copied_receipts: list[Path] = []
        self.standalone_receipts: list[Path] = []
        self.trace_scoped_receipts: list[Path] = []
        self.metadata: dict | None = None

    def emit(self, event: dict, *, render: bool = True) -> None:
        with self.trace_path.open("a", encoding="utf-8") as handle:
            handle.write(compact(event) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if render:
            render_tty_event(event, color=self.color)

    def configure(self, policy_recipe: str, policy: Path, *, active: list[str], inactive: list[str],
                  experimental: list[str], trace_transcript: dict | None = None) -> None:
        value = json.loads(policy.read_text(encoding="utf-8"))
        config_hash = sha256_bytes(compact(value).encode())
        self.metadata = {
            "schema": SCHEMA,
            "event": "demo_metadata",
            "demo_id": self.demo_id,
            "policy_recipe": policy_recipe,
            "config_sha256": config_hash,
            "active": active,
            "present_but_inactive": inactive,
            "experimental": experimental,
            "proof_manifest": self.manifest_path.name,
            "proof_manifest_sha256": sha256_file(self.manifest_path),
        }
        if trace_transcript is not None:
            self.metadata["trace_transcript"] = trace_transcript
        self.emit(self.metadata)

    def record_receipt(self, source: Path, *, role: str, theorem_ids: list[str],
                       budget: dict | None = None, temporal: dict | None = None,
                       consensus: dict | None = None, linear: dict | None = None,
                       verification_lane: str = "standalone", requires_trace: str | None = None,
                       standalone_failure: dict | None = None) -> Path:
        if self.metadata is None:
            raise DoctrineFailure("demo metadata must be emitted before any receipt")
        source = source.resolve()
        if source in self.recorded_sources:
            raise DoctrineFailure(f"receipt recorded twice: {source}")
        record = json.loads(source.read_text(encoding="utf-8"))
        self.sequence += 1
        dest = self.receipt_dir / f"step-{self.sequence:02d}-{source.name}"
        shutil.copyfile(source, dest)
        if source.read_bytes() != dest.read_bytes():
            raise DoctrineFailure(f"receipt copy changed bytes: {source}")
        if verification_lane == "standalone":
            if requires_trace is not None or standalone_failure is not None:
                raise DoctrineFailure("standalone receipt cannot carry trace-only verification metadata")
            verified = run([str(self.seal), "verify", str(dest)])
            if "PASS  VERIFIED" not in verified.stdout:
                raise DoctrineFailure(f"seal verify did not report PASS VERIFIED: {dest}")
            seal_verify = {"command": "seal verify", "status": "PASS", "exit_code": verified.returncode}
        elif verification_lane == "trace":
            if not isinstance(requires_trace, str) or not re.fullmatch(r"[0-9a-f]{64}", requires_trace):
                raise DoctrineFailure("trace-scoped receipt requires a transcript SHA-256")
            if not isinstance(standalone_failure, dict) or standalone_failure.get("exit_code") == 0:
                raise DoctrineFailure("trace-scoped receipt must record its non-green standalone replay")
            seal_verify = dict(standalone_failure)
            if seal_verify.get("command") != "seal verify" or seal_verify.get("status") != "TRACE-SCOPED":
                raise DoctrineFailure("trace-scoped receipt standalone label drift")
        else:
            raise DoctrineFailure(f"unknown verification lane: {verification_lane}")

        arguments = record.get("arguments")
        if not isinstance(arguments, dict):
            raise DoctrineFailure(f"receipt lacks structured arguments: {dest}")
        args_digest = sha256_bytes(compact(arguments).encode())
        if record.get("args_hash") != args_digest:
            raise DoctrineFailure(f"receipt args_hash mismatch: {dest}")
        if sha256_bytes(compact(record.get("kernel_config")).encode()) != self.metadata["config_sha256"]:
            raise DoctrineFailure(f"receipt config differs from demo metadata: {dest}")

        proof_refs = []
        for theorem_id in theorem_ids:
            proof = self.manifest["proofs"].get(theorem_id)
            if proof is None:
                raise DoctrineFailure(f"receipt step cites theorem absent from manifest: {theorem_id}")
            proof_refs.append({
                "theorem_id": theorem_id,
                "commit_pin": proof["commit_pin"],
                "module": proof["module"],
                "source_url": proof["source_url"],
            })

        active = self.metadata["active"]
        inactive = self.metadata["present_but_inactive"]
        experimental = self.metadata["experimental"]
        certs = record.get("certs")
        if not isinstance(certs, list) or not certs:
            raise DoctrineFailure(f"receipt lacks kernel certificates: {dest}")
        kernel_fired = [
            {
                "kernel": cert["kernel"],
                "verdict": cert["verdict"].upper(),
                "reason": cert["reason"],
                "participation": _participation_label(cert["kernel"], active, inactive, experimental),
            }
            for cert in certs
        ]
        receipt_verdict = record.get("verdict")
        if receipt_verdict not in {"BLOCK", "ALLOW"}:
            raise DoctrineFailure(f"unexpected receipt verdict: {receipt_verdict}")
        if budget is not None:
            budget = validate_budget_evidence(
                budget, arguments, verdict=receipt_verdict,
                deny_kernel=record.get("deny_kernel"), context=str(dest),
            )

        relative = dest.relative_to(self.artifact_dir)
        event = {
            "schema": SCHEMA,
            "event": "step",
            "demo_id": self.demo_id,
            "sequence": self.sequence,
            "role": role,
            "tool": record["tool"],
            "args_digest": args_digest,
            "verdict": "DENY" if receipt_verdict == "BLOCK" else "ALLOW",
            "receipt_verdict": receipt_verdict,
            "kernel_fired": kernel_fired,
            "deny_kernel": record.get("deny_kernel"),
            "proof_refs": proof_refs,
            "receipt_path": str(relative),
            "receipt_sha256": sha256_file(dest),
            "verification_lane": verification_lane,
            "seal_verify": seal_verify,
            "claim_scope": CLAIM_SCOPE,
        }
        if budget is not None:
            event["budget"] = budget
        if temporal is not None:
            event["temporal"] = temporal
        if consensus is not None:
            event["consensus"] = consensus
        if linear is not None:
            event["linear"] = linear
        if requires_trace is not None:
            event["requires_trace"] = requires_trace
        self.recorded_sources.add(source)
        self.copied_receipts.append(dest)
        if verification_lane == "standalone":
            self.standalone_receipts.append(dest)
        else:
            self.trace_scoped_receipts.append(dest)
        self.emit(event)
        return dest

    def _verify_all(self) -> None:
        for receipt in self.standalone_receipts:
            result = run([str(self.seal), "verify", str(receipt)])
            if "PASS  VERIFIED" not in result.stdout:
                raise DoctrineFailure(f"final seal verify did not report PASS: {receipt}")

    def _anti_forge(self) -> None:
        if not self.standalone_receipts:
            controls = [event for event in load_trace(self.trace_path) if event.get("event") == "anti_forge"]
            if len(controls) != 1:
                raise DoctrineFailure("trace-only demo requires one pre-recorded anti-forge control")
            control = controls[0]
            if (control.get("subject") != "trace-transcript" or
                    control.get("tampered_verify_exit") == 0 or
                    control.get("original_sha256") != control.get("restored_sha256") or
                    control.get("restored_verify") != "PASS"):
                raise DoctrineFailure("trace-only anti-forge control is malformed")
            return
        receipt = self.standalone_receipts[0]
        original = receipt.read_bytes()
        original_hash = sha256_bytes(original)
        marker = b'"args_hash": "'
        start = original.find(marker)
        if start < 0:
            raise DoctrineFailure(f"cannot find args_hash byte for anti-forge control: {receipt}")
        offset = start + len(marker)
        tampered = bytearray(original)
        tampered[offset] = ord("0") if tampered[offset] != ord("0") else ord("1")
        receipt.write_bytes(tampered)
        result = subprocess.run([str(self.seal), "verify", str(receipt)], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            receipt.write_bytes(original)
            raise DoctrineFailure("anti-forge negative control: seal verify accepted a one-byte-corrupted receipt")
        receipt.write_bytes(original)
        restored_hash = sha256_file(receipt)
        if restored_hash != original_hash or receipt.read_bytes() != original:
            raise DoctrineFailure("anti-forge negative control did not restore the receipt byte-exact")
        rerun = run([str(self.seal), "verify", str(receipt)])
        if "PASS  VERIFIED" not in rerun.stdout:
            raise DoctrineFailure("restored receipt did not verify")
        self.emit({
            "schema": SCHEMA,
            "event": "anti_forge",
            "receipt_path": str(receipt.relative_to(self.artifact_dir)),
            "mutation": "one byte flipped in args_hash",
            "tampered_verify_exit": result.returncode,
            "original_sha256": original_hash,
            "restored_sha256": restored_hash,
            "restored_verify": "PASS",
        })

    def finalize(self, receipt_roots: Iterable[Path]) -> None:
        produced = {
            path.resolve()
            for root in receipt_roots
            if root.exists()
            for path in root.rglob("receipt-*.json")
        }
        missing = produced - self.recorded_sources
        extra = self.recorded_sources - produced
        if missing or extra:
            raise DoctrineFailure(
                "receipt accounting mismatch; "
                f"untraced={sorted(map(str, missing))}, missing-at-source={sorted(map(str, extra))}"
            )
        self._verify_all()
        self._anti_forge()
        self._verify_all()
        summary = {"schema": SCHEMA, "event": "verification_summary", "receipts": len(self.copied_receipts), "status": "PASS"}
        if self.trace_scoped_receipts:
            summary.update({
                "standalone_receipts": len(self.standalone_receipts),
                "trace_scoped_receipts": len(self.trace_scoped_receipts),
            })
        self.emit(summary, render=False)
        self.emit({"schema": SCHEMA, "event": "non_claims", "lines": NON_CLAIMS})
        markdown = render_markdown(self.trace_path, self.artifact_dir / "receipt-strip.md")
        validate_trace(self.artifact_dir)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with Path(summary).open("a", encoding="utf-8") as handle:
                handle.write(markdown)


def validate_step_order(metadata: dict, steps: list[dict]) -> None:
    """Enforce each demo's ratified narrative without weakening siblings."""
    if metadata.get("demo_id") == "c3":
        if len(steps) != 3:
            raise DoctrineFailure("C3 ordered narrative must contain exactly three steps")
        if [step.get("role") for step in steps] != ["QUORUM-SHORT", "DEPLOY-OK", "REPLAY-DENY"]:
            raise DoctrineFailure("C3 order must be QUORUM-SHORT, DEPLOY-OK, REPLAY-DENY")
        if [step.get("verdict") for step in steps] != ["DENY", "ALLOW", "DENY"]:
            raise DoctrineFailure("C3 verdict order must be DENY, ALLOW, DENY")
        return
    if metadata.get("demo_id") == "c6":
        if len(steps) != 2:
            raise DoctrineFailure("C6 ordered narrative must contain exactly two steps")
        if [step.get("role") for step in steps] != ["LEGIT-TRIGGER", "ATTACK-DENY"]:
            raise DoctrineFailure("C6 ordered narrative must be LEGIT-TRIGGER then ATTACK-DENY")
        if [step.get("verdict") for step in steps] != ["ALLOW", "DENY"]:
            raise DoctrineFailure("C6 ordered narrative must be ALLOW trigger then DENY forbidden call")
        return
    if not steps or steps[0].get("verdict") != "DENY":
        raise DoctrineFailure("first persuasive step must be DENY")
    if len(steps) < 2 or steps[0].get("role") != "ATTACK-DENY" or steps[1].get("role") != "LEGIT":
        raise DoctrineFailure("ordered narrative must begin ATTACK-DENY then LEGIT")
    if steps[1].get("verdict") != "ALLOW":
        raise DoctrineFailure("the LEGIT step immediately after ATTACK-DENY must ALLOW")
    if any(step.get("role") != "CONTROL" for step in steps[2:]):
        raise DoctrineFailure("only CONTROL steps may follow the DENY→ALLOW hero pair")


def validate_lane_scope(demo_id: str, lane: str) -> None:
    """Keep the ratified C1/C2/C4 standalone contract closed."""
    if demo_id in {"c1", "c2", "c4"} and lane != "standalone":
        raise DoctrineFailure(f"{demo_id.upper()} receipts must remain on the standalone verification lane")


def validate_trace(artifact_dir: Path) -> None:
    artifact_dir = artifact_dir.resolve()
    trace = artifact_dir / "events.ndjson"
    manifest_path = artifact_dir / "proof-manifest.json"
    events = load_trace(trace)
    if not events or events[0].get("event") != "demo_metadata":
        raise DoctrineFailure("trace must begin with demo_metadata")
    metadata = events[0]
    if metadata.get("proof_manifest_sha256") != sha256_file(manifest_path):
        raise DoctrineFailure("trace proof-manifest digest mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    steps = [event for event in events if event.get("event") == "step"]
    validate_step_order(metadata, steps)
    required = {
        "tool", "args_digest", "verdict", "kernel_fired", "proof_refs", "receipt_path",
        "receipt_sha256", "seal_verify", "claim_scope",
    }
    receipt_paths: set[Path] = set()
    receipt_records: list[dict] = []
    for index, step in enumerate(steps, 1):
        missing = required - step.keys()
        if missing:
            raise DoctrineFailure(f"step {index} lacks doctrine fields: {sorted(missing)}")
        if step["claim_scope"] != CLAIM_SCOPE:
            raise DoctrineFailure(f"step {index} claim scope drift")
        lane = step.get("verification_lane", "standalone")
        validate_lane_scope(metadata.get("demo_id", ""), lane)
        if lane == "standalone":
            if step["seal_verify"] != {"command": "seal verify", "status": "PASS", "exit_code": 0}:
                raise DoctrineFailure(f"step {index} lacks green standalone seal verify")
            if step.get("requires_trace") is not None:
                raise DoctrineFailure(f"step {index} standalone receipt unexpectedly requires a trace")
        elif lane == "trace":
            transcript_sha = metadata.get("trace_transcript", {}).get("sha256")
            if step.get("requires_trace") != transcript_sha:
                raise DoctrineFailure(f"step {index} trace dependency differs from demo metadata")
            verification = step.get("seal_verify", {})
            if verification.get("command") != "seal verify" or verification.get("status") != "TRACE-SCOPED" or verification.get("exit_code") == 0:
                raise DoctrineFailure(f"step {index} trace-scoped receipt has a dishonest standalone label")
        else:
            raise DoctrineFailure(f"step {index} has unknown verification lane")
        receipt = (artifact_dir / step["receipt_path"]).resolve()
        if artifact_dir not in receipt.parents or not receipt.is_file():
            raise DoctrineFailure(f"step {index} receipt path invalid: {receipt}")
        if sha256_file(receipt) != step["receipt_sha256"]:
            raise DoctrineFailure(f"step {index} receipt digest mismatch")
        record = json.loads(receipt.read_text(encoding="utf-8"))
        receipt_records.append(record)
        if ("DENY" if record["verdict"] == "BLOCK" else record["verdict"]) != step["verdict"]:
            raise DoctrineFailure(f"step {index} receipt verdict mismatch")
        if step.get("budget"):
            resolved = validate_budget_evidence(
                step["budget"], record.get("arguments", {}), verdict=step["verdict"],
                deny_kernel=step.get("deny_kernel"), context=f"step {index}",
            )
            if resolved != step["budget"]:
                raise DoctrineFailure(f"step {index} Budget cost differs from receipt arguments")
        for proof in step["proof_refs"]:
            source = manifest["proofs"].get(proof["theorem_id"])
            if source is None or source["commit_pin"] != proof["commit_pin"]:
                raise DoctrineFailure(f"step {index} proof reference is unresolved or unpinned")
        receipt_paths.add(receipt)
    on_disk = {path.resolve() for path in (artifact_dir / "receipts").glob("*.json")}
    if receipt_paths != on_disk:
        raise DoctrineFailure("trace does not account for exactly every artifact receipt")
    anti = [event for event in events if event.get("event") == "anti_forge"]
    if len(anti) != 1 or anti[0]["tampered_verify_exit"] == 0 or anti[0]["original_sha256"] != anti[0]["restored_sha256"]:
        raise DoctrineFailure("anti-forge rejection/restoration evidence missing")
    summaries = [event for event in events if event.get("event") == "verification_summary"]
    expected_summary = {"schema": SCHEMA, "event": "verification_summary", "receipts": len(steps), "status": "PASS"}
    if metadata.get("demo_id") == "c3":
        expected_summary.update({"standalone_receipts": 0, "trace_scoped_receipts": 3})
    elif metadata.get("demo_id") == "c6":
        expected_summary.update({"standalone_receipts": 1, "trace_scoped_receipts": 1})
    if summaries != [expected_summary]:
        raise DoctrineFailure("receipt verification summary mismatch")
    non_claims = [event for event in events if event.get("event") == "non_claims"]
    if len(non_claims) != 1 or non_claims[0].get("lines") != NON_CLAIMS:
        raise DoctrineFailure("fixed non-claims block missing or changed")
    if metadata.get("demo_id") == "c3":
        _validate_c3(metadata, steps, receipt_records, manifest, events, artifact_dir)
    if metadata.get("demo_id") == "c4":
        _validate_c4(metadata, steps, receipt_records, manifest)
    if metadata.get("demo_id") == "c6":
        _validate_c6(metadata, steps, receipt_records, manifest, events, artifact_dir)
    expected_md = render_markdown(trace, artifact_dir / ".receipt-strip.check.md")
    check_path = artifact_dir / ".receipt-strip.check.md"
    try:
        if (artifact_dir / "receipt-strip.md").read_text(encoding="utf-8") != expected_md:
            raise DoctrineFailure("Markdown strip is not reproducible from NDJSON")
    finally:
        check_path.unlink(missing_ok=True)


def _validate_c3(metadata: dict, steps: list[dict], records: list[dict], manifest: dict,
                 events: list[dict] | None = None, artifact_dir: Path | None = None) -> None:
    if metadata.get("policy_recipe") != "deploy":
        raise DoctrineFailure("C3 must use the shipped deploy recipe")
    if metadata.get("active") != ["safety", "consensus", "linear"]:
        raise DoctrineFailure("C3 ACTIVE set must be exactly Safety+Consensus+Linear")
    if metadata.get("present_but_inactive") != [] or metadata.get("experimental") != []:
        raise DoctrineFailure("C3 must have no inactive or experimental kernel sections")
    expected_theorems = {
        "Host.composed_non_bypass",
        "Host.composed_no_conflicting_agreement",
        "Host.composed_linear_conservation",
        "Host.registry_closed_algebra",
        "Host.pureCommit_deny_of_member",
        "Host.registry_deny_no_capability_consumed",
        "Host.linear_committed_trace_no_double_spend",
    }
    if set(manifest.get("proofs", {})) != expected_theorems:
        raise DoctrineFailure("C3 proof manifest theorem set drift")
    if len(steps) != 3 or len(records) != 3 or any(step.get("tool") != "deploy" for step in steps):
        raise DoctrineFailure("C3 must contain exactly three deploy receipts")
    if records[1].get("arguments") != records[2].get("arguments"):
        raise DoctrineFailure("C3 DEPLOY-OK and REPLAY-DENY must be byte-identical calls")
    if records[0].get("arguments") == records[1].get("arguments"):
        raise DoctrineFailure("C3 quorum-short probe must have its own Safety target")
    if [step.get("receipt_verdict") for step in steps] != ["BLOCK", "ALLOW", "BLOCK"]:
        raise DoctrineFailure("C3 must retain BLOCK/ALLOW/BLOCK receipt vocabulary")
    if any(step.get("verification_lane") != "trace" for step in steps):
        raise DoctrineFailure("every combined C3 receipt must be trace-scoped")
    if [step.get("deny_kernel") for step in steps] != ["consensus", None, "linear"]:
        raise DoctrineFailure("C3 denying kernels must be Consensus, none, Linear")
    if [record.get("deny_kernel") for record in records] != ["consensus", None, "linear"]:
        raise DoctrineFailure("C3 runtime denying-kernel evidence drift")

    proof_sets = [
        {"Host.pureCommit_deny_of_member", "Host.registry_deny_no_capability_consumed"},
        {"Host.registry_closed_algebra", "Host.composed_non_bypass",
         "Host.composed_no_conflicting_agreement", "Host.composed_linear_conservation"},
        {"Host.linear_committed_trace_no_double_spend", "Host.pureCommit_deny_of_member",
         "Host.registry_deny_no_capability_consumed"},
    ]
    verdicts = [
        ["allow", "allow", "deny", "allow"],
        ["allow", "allow", "allow", "allow"],
        ["allow", "allow", "allow", "deny"],
    ]
    for index, (step, record, proof_set, expected_verdicts) in enumerate(
            zip(steps, records, proof_sets, verdicts), 1):
        if {proof["theorem_id"] for proof in step.get("proof_refs", [])} != proof_set:
            raise DoctrineFailure(f"C3 step {index} theorem set drift")
        certs = record.get("certs", [])
        expected_runtime = ["safety", "temporal", "consensus", "linear"]
        if [cert.get("kernel") for cert in certs] != expected_runtime:
            raise DoctrineFailure(f"C3 step {index} certificate set/order drift")
        if [cert.get("verdict") for cert in certs] != expected_verdicts:
            raise DoctrineFailure(f"C3 step {index} certificate verdict drift")
        fired = step.get("kernel_fired", [])
        if [cert.get("kernel") for cert in fired] != expected_runtime:
            raise DoctrineFailure(f"C3 step {index} trace participation order drift")
        participation = {cert.get("kernel"): cert.get("participation") for cert in fired}
        if participation != {"safety": "ACTIVE", "temporal": "ABSENT/OFF", "consensus": "ACTIVE", "linear": "ACTIVE"}:
            raise DoctrineFailure(f"C3 step {index} participation labels drift")
        if certs[0].get("verdict") != "allow" or not re.fullmatch(r"[0-9a-f]{64}", certs[0].get("reason", "")):
            raise DoctrineFailure(f"C3 step {index} lacks a live matching Safety approval")
        verification = step.get("seal_verify", {})
        if (verification.get("command") != "seal verify" or verification.get("status") != "TRACE-SCOPED" or
                verification.get("exit_code") == 0 or verification.get("rederived_verdict") != "BLOCK" or
                verification.get("artifact_lane_reason") != "combined receipt omits votes/grants; verifier replays both empty"):
            raise DoctrineFailure(f"C3 step {index} standalone boundary evidence drift")
        expected_live = ["BLOCK", "ALLOW", "BLOCK"][index - 1]
        if verification.get("live_session_verdict") != expected_live:
            raise DoctrineFailure(f"C3 step {index} live verdict label drift")

    expected_consensus = [
        {"roster": [101, 202, 303], "value": "deploy", "votes": 1, "required": 2, "quorum_met": False},
        {"roster": [101, 202, 303], "value": "deploy", "votes": 2, "required": 2, "quorum_met": True},
        {"roster": [101, 202, 303], "value": "deploy", "votes": 2, "required": 2, "quorum_met": True},
    ]
    expected_linear = [
        {"cap_arg": "capability.id", "capability_id": "deploy-cap-c3-001", "grant_events": 1,
         "remaining_before": 1, "remaining_after": 1, "consumed": False},
        {"cap_arg": "capability.id", "capability_id": "deploy-cap-c3-001", "grant_events": 0,
         "remaining_before": 1, "remaining_after": 0, "consumed": True},
        {"cap_arg": "capability.id", "capability_id": "deploy-cap-c3-001", "grant_events": 0,
         "remaining_before": 0, "remaining_after": 0, "consumed": False},
    ]
    if [step.get("consensus") for step in steps] != expected_consensus:
        raise DoctrineFailure("C3 quorum evidence drift")
    if [step.get("linear") for step in steps] != expected_linear:
        raise DoctrineFailure("C3 committed Linear evidence drift")

    configs = [record.get("kernel_config") for record in records]
    if any(config != configs[0] for config in configs[1:]):
        raise DoctrineFailure("C3 receipts must share one identical signed policy")
    cfg = configs[0]
    if cfg.get("consensus", {}).get("roster") != [101, 202, 303] or cfg.get("consensus", {}).get("high_stakes") != ["deploy"]:
        raise DoctrineFailure("C3 receipt roster/high-stakes policy drift")
    if cfg.get("linear", {}).get("tools") != [{"tool": "deploy", "cap_arg": "capability.id"}]:
        raise DoctrineFailure("C3 receipt Linear capability path drift")
    if any(section in cfg for section in ["convergence", "calibration", "budget"]):
        raise DoctrineFailure("C3 receipt carries an out-of-scope kernel section")
    if events is None or artifact_dir is None:
        return

    transcript_meta = metadata.get("trace_transcript")
    if not isinstance(transcript_meta, dict):
        raise DoctrineFailure("C3 demo metadata lacks its trace transcript")
    transcript_sha = transcript_meta.get("sha256")
    if not isinstance(transcript_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", transcript_sha):
        raise DoctrineFailure("C3 trace transcript SHA-256 malformed")
    if any(step.get("requires_trace") != transcript_sha for step in steps):
        raise DoctrineFailure("C3 receipt-to-trace dependency drift")
    if transcript_meta.get("path") != "trace-transcript.json" or transcript_meta.get("harness") != "demo/trace_replay.cjs" or transcript_meta.get("status") != "PASS":
        raise DoctrineFailure("C3 transcript metadata drift")
    transcript_path = artifact_dir / "trace-transcript.json"
    if not transcript_path.is_file() or sha256_file(transcript_path) != transcript_sha:
        raise DoctrineFailure("C3 transcript missing or digest mismatch")
    transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
    if transcript.get("schema") != "seal-demo-trace-transcript/v1" or transcript.get("demo_id") != "c3" or len(transcript.get("steps", [])) != 3:
        raise DoctrineFailure("C3 transcript shape drift")
    if transcript_meta.get("wasm_sha256") != transcript.get("wasm_sha256"):
        raise DoctrineFailure("C3 transcript WASM pin drift")
    if transcript.get("signed_config") != records[0].get("signed_config"):
        raise DoctrineFailure("C3 transcript signed config differs from receipts")

    for index, (step, record, transcript_step) in enumerate(zip(steps, records, transcript["steps"]), 1):
        if transcript_step.get("sequence") != index or transcript_step.get("role") != step.get("role"):
            raise DoctrineFailure(f"C3 transcript step {index} order/role drift")
        if transcript_step.get("canonical_request") != record.get("canonical_request") or transcript_step.get("raw_kernel_output") != record.get("emitted_bytes"):
            raise DoctrineFailure(f"C3 transcript step {index} request/output drift")
        try:
            embedded = base64.b64decode(transcript_step["receipt_bytes_base64"], validate=True)
        except Exception as error:
            raise DoctrineFailure(f"C3 transcript step {index} receipt bytes malformed") from error
        artifact_receipt = (artifact_dir / step["receipt_path"]).read_bytes()
        if embedded != artifact_receipt or sha256_bytes(embedded) != transcript_step.get("receipt_sha256"):
            raise DoctrineFailure(f"C3 transcript step {index} receipt is not byte-identical")
        replay_input = transcript_step.get("step_input", {})
        expected_approvals = [{"target": grant["target"]} for grant in record.get("granted_capabilities", [])]
        if replay_input.get("line") != record.get("canonical_request") or replay_input.get("now") != record.get("now") or replay_input.get("approvals") != expected_approvals:
            raise DoctrineFailure(f"C3 transcript step {index} replay input binding drift")
        vote_lines = [line for line in replay_input.get("votes", "").splitlines() if line.strip()]
        grant_lines = [line for line in replay_input.get("grants", "").splitlines() if line.strip()]
        if len(vote_lines) != [1, 2, 2][index - 1] or len(grant_lines) != [1, 0, 0][index - 1]:
            raise DoctrineFailure(f"C3 transcript step {index} votes/grants evidence drift")
        if replay_input.get("forecasts") != "":
            raise DoctrineFailure(f"C3 transcript step {index} unexpectedly carries forecasts")
    variants = transcript["steps"][0].get("input_variants", {})
    if set(variants) != {"quorum-met"} or variants["quorum-met"].get("votes") != transcript["steps"][1]["step_input"]["votes"]:
        raise DoctrineFailure("C3 quorum-met input variant drift")
    if any(step.get("input_variants") for step in transcript["steps"][1:]):
        raise DoctrineFailure("C3 input variant must exist only on QUORUM-SHORT")

    replay = [event for event in events if event.get("event") == "trace_replay"]
    if replay != [{
        "schema": SCHEMA, "event": "trace_replay", "status": "PASS",
        "transcript_path": "trace-transcript.json", "transcript_sha256": transcript_sha,
        "wasm_sha256": transcript["wasm_sha256"], "steps": 3, "harness": "demo/trace_replay.cjs",
    }]:
        raise DoctrineFailure("C3 full trace replay evidence drift")
    controls = [event for event in events if event.get("event") == "trace_negative_control"]
    expected_controls = [
        {"schema": SCHEMA, "event": "trace_negative_control", "name": "quorum-met",
         "expected": "FAIL", "observed": "FAIL", "status": "PASS",
         "evidence": "1-of-3 Consensus BLOCK changed to 2-of-3 forward/ALLOW and mismatched receipt bytes"},
        {"schema": SCHEMA, "event": "trace_negative_control", "name": "drop-deploy-ok",
         "expected": "FAIL", "observed": "FAIL", "status": "PASS",
         "evidence": "without DEPLOY-OK the one-use capability remained held and REPLAY-DENY re-derived forward/ALLOW"},
        {"schema": SCHEMA, "event": "trace_negative_control", "name": "byte-flip",
         "expected": "FAIL", "observed": "FAIL", "status": "PASS",
         "evidence": "one byte flipped in the REPLAY-DENY raw kernel output"},
        {"schema": SCHEMA, "event": "trace_negative_control", "name": "restore",
         "expected": "SHA-MATCH+PASS", "observed": "SHA-MATCH+PASS", "status": "PASS",
         "evidence": f"restored transcript sha256={transcript_sha}; full ordered replay PASS"},
    ]
    if controls != expected_controls:
        raise DoctrineFailure("C3 trace negative-control evidence drift")


def _validate_c4(metadata: dict, steps: list[dict], records: list[dict], manifest: dict) -> None:
    if metadata.get("policy_recipe") != "token-governor":
        raise DoctrineFailure("C4 must use the token-governor recipe")
    if metadata.get("active") != ["safety", "budget"]:
        raise DoctrineFailure("C4 ACTIVE set must be exactly Safety+Budget")
    if metadata.get("present_but_inactive") != [] or metadata.get("experimental") != []:
        raise DoctrineFailure("C4 must have no inactive or experimental kernel sections")
    expected_theorems = {
        "BudgetCore.over_budget_denied",
        "Host.composed_budget_cap",
        "Host.registry_closed_algebra",
        "Host.registry_deny_no_budget_spend",
    }
    if set(manifest.get("proofs", {})) != expected_theorems:
        raise DoctrineFailure("C4 proof manifest must contain exactly the four ratified Budget+Safety theorems")
    if len(steps) != 2 or len(records) != 2:
        raise DoctrineFailure("C4 must contain exactly the DENY→ALLOW hero pair")
    deny, allow = steps
    deny_record, allow_record = records
    if any(step.get("tool") != "llm_call" for step in steps):
        raise DoctrineFailure("C4 hero pair must use the real llm_call tool")
    deny_proofs = {proof["theorem_id"] for proof in deny["proof_refs"]}
    allow_proofs = {proof["theorem_id"] for proof in allow["proof_refs"]}
    if deny_proofs != {"BudgetCore.over_budget_denied", "Host.registry_deny_no_budget_spend"}:
        raise DoctrineFailure("C4 Budget denial theorem set drift")
    if allow_proofs != {"Host.composed_budget_cap", "Host.registry_closed_algebra"}:
        raise DoctrineFailure("C4 composed allow theorem set drift")
    deny_args = deny_record.get("arguments", {})
    allow_args = allow_record.get("arguments", {})
    if deny_args.get("prompt") != allow_args.get("prompt") or not isinstance(deny_args.get("prompt"), str):
        raise DoctrineFailure("C4 retry must preserve the exact prompt")
    if argument_at_path(deny_args, "usage.tokens") != 11:
        raise DoctrineFailure("C4 first call must charge 11 token units")
    if argument_at_path(allow_args, "usage.tokens") != 4:
        raise DoctrineFailure("C4 retry must charge 4 token units")
    expected_deny_budget = {
        "name": "token-usage", "cost_arg": "usage.tokens", "cost": 11,
        "cap": 10, "remaining_before": 10, "remaining_after": 10,
    }
    expected_allow_budget = {
        "name": "token-usage", "cost_arg": "usage.tokens", "cost": 4,
        "cap": 10, "remaining_before": 10, "remaining_after": 6,
    }
    if deny.get("budget") != expected_deny_budget or allow.get("budget") != expected_allow_budget:
        raise DoctrineFailure("C4 token counter evidence drift")
    if deny.get("deny_kernel") != "budget" or deny_record.get("deny_kernel") != "budget":
        raise DoctrineFailure("C4 first call must be denied by Budget")
    deny_certs = {cert.get("kernel"): cert for cert in deny_record.get("certs", [])}
    allow_certs = {cert.get("kernel"): cert for cert in allow_record.get("certs", [])}
    if deny_certs.get("safety", {}).get("verdict") != "allow":
        raise DoctrineFailure("C4 over-cap call must carry a live Safety approval")
    if deny_certs.get("budget", {}).get("reason") != "over budget token-usage (0+11>10): llm_call":
        raise DoctrineFailure("C4 Budget deny certificate drift")
    if allow_certs.get("safety", {}).get("verdict") != "allow" or allow_certs.get("budget", {}).get("verdict") != "allow":
        raise DoctrineFailure("C4 retry must be allowed by both Safety and Budget")


def _validate_c6(metadata: dict, steps: list[dict], records: list[dict], manifest: dict,
                 events: list[dict] | None = None, artifact_dir: Path | None = None) -> None:
    if metadata.get("policy_recipe") != "init+add-kernel-T":
        raise DoctrineFailure("C6 must use the shipped init + add-kernel T authoring path")
    if metadata.get("active") != ["safety", "temporal"]:
        raise DoctrineFailure("C6 ACTIVE set must be exactly Safety+Temporal")
    if metadata.get("present_but_inactive") != [] or metadata.get("experimental") != []:
        raise DoctrineFailure("C6 must have no inactive or experimental kernel sections")
    expected_theorems = {
        "Host.composed_temporal_safety",
        "Host.registry_closed_algebra",
        "Host.registry_deny_no_capability_consumed",
        "Host.registry_deny_temporal_frozen",
    }
    if set(manifest.get("proofs", {})) != expected_theorems:
        raise DoctrineFailure("C6 proof manifest must contain exactly the four ratified Temporal+Safety theorems")
    if len(steps) != 2 or len(records) != 2:
        raise DoctrineFailure("C6 must contain exactly the trigger-ALLOW then frozen-DENY pair")
    trigger, denied = steps
    trigger_record, denied_record = records
    if [step.get("tool") for step in steps] != ["session.revoke", "audit.destroy"]:
        raise DoctrineFailure("C6 tools must be session.revoke then audit.destroy")
    if trigger.get("receipt_verdict") != "ALLOW" or denied.get("receipt_verdict") != "BLOCK":
        raise DoctrineFailure("C6 must retain ALLOW/BLOCK receipt vocabulary")
    if trigger.get("verification_lane") != "standalone" or denied.get("verification_lane") != "trace":
        raise DoctrineFailure("C6 must place only the trigger on the standalone lane and the frozen deny on the trace lane")
    if trigger.get("seal_verify") != {"command": "seal verify", "status": "PASS", "exit_code": 0}:
        raise DoctrineFailure("C6 trigger receipt must independently verify")
    denied_verify = denied.get("seal_verify", {})
    if denied_verify.get("command") != "seal verify" or denied_verify.get("status") != "TRACE-SCOPED" or denied_verify.get("exit_code") == 0:
        raise DoctrineFailure("C6 frozen receipt must be honestly labelled trace-scoped")
    if denied_verify.get("fresh_state_verdict") != "ALLOW" or denied_verify.get("live_session_verdict") != "BLOCK":
        raise DoctrineFailure("C6 standalone failure must exhibit fresh-state ALLOW versus live-session BLOCK")
    if trigger.get("deny_kernel") is not None or denied.get("deny_kernel") != "temporal":
        raise DoctrineFailure("C6 denying kernel must be Temporal on only the second step")
    if trigger_record.get("deny_kernel") is not None or denied_record.get("deny_kernel") != "temporal":
        raise DoctrineFailure("C6 runtime receipt deny-kernel evidence drift")
    trigger_proofs = {proof["theorem_id"] for proof in trigger["proof_refs"]}
    denied_proofs = {proof["theorem_id"] for proof in denied["proof_refs"]}
    if trigger_proofs != {"Host.composed_temporal_safety", "Host.registry_closed_algebra"}:
        raise DoctrineFailure("C6 trigger theorem set drift")
    if denied_proofs != {
        "Host.registry_deny_temporal_frozen", "Host.registry_deny_no_capability_consumed",
    }:
        raise DoctrineFailure("C6 frozen-deny theorem set drift")

    expected_kernels = ["safety", "temporal"]
    for label, step, record in (
        ("trigger", trigger, trigger_record), ("denied", denied, denied_record),
    ):
        certs = record.get("certs", [])
        if [cert.get("kernel") for cert in certs] != expected_kernels:
            raise DoctrineFailure(f"C6 {label} receipt certificate set/order drift")
        fired = step.get("kernel_fired", [])
        if [cert.get("kernel") for cert in fired] != expected_kernels:
            raise DoctrineFailure(f"C6 {label} trace certificate set/order drift")
        if any(cert.get("participation") != "ACTIVE" for cert in fired):
            raise DoctrineFailure(f"C6 {label} must show every fired kernel ACTIVE")
        if certs[0].get("verdict") != "allow" or not re.fullmatch(r"[0-9a-f]{64}", certs[0].get("reason", "")):
            raise DoctrineFailure(f"C6 {label} must carry a live matching Safety approval")
    if trigger_record["certs"][1].get("verdict") != "allow" or trigger_record["certs"][1].get("reason") != "trace ok (1 events)":
        raise DoctrineFailure("C6 trigger must allow and arm a one-event Temporal trace")
    if denied_record["certs"][1].get("verdict") != "deny" or denied_record["certs"][1].get("reason") != "temporal policy violated: freeze-destructive-after-trigger":
        raise DoctrineFailure("C6 forbidden call must carry the exact Temporal frozen deny certificate")

    policy = {
        "policy_name": "freeze-destructive-after-trigger",
        "policy_type": "no_after",
        "trigger": ["session.revoke", "audit.destroy"],
        "forbidden": ["session.revoke", "audit.destroy"],
    }
    expected_trigger_temporal = {
        **policy,
        "trace_events_before": 0,
        "trace_events_after": 1,
        "trace_evidence": "runtime-certificate:trace ok (1 events)",
        "freeze_scope": "session.revoke armed the trigger-driven freeze",
        "wall_clock_claim": False,
    }
    expected_denied_temporal = {
        **policy,
        "trace_events_before": 1,
        "trace_events_after": 1,
        "trace_evidence": "theorem:Host.registry_deny_temporal_frozen",
        "deny_state": {
            "trace_theorem": "Host.registry_deny_temporal_frozen",
            "capability_consumed": False,
            "capability_theorem": "Host.registry_deny_no_capability_consumed",
        },
        "freeze_scope": "this specific audit.destroy call was mediated to DENY under the armed policy",
        "wall_clock_claim": False,
    }
    if trigger.get("temporal") != expected_trigger_temporal:
        raise DoctrineFailure("C6 trigger Temporal evidence drift")
    if denied.get("temporal") != expected_denied_temporal:
        raise DoctrineFailure("C6 frozen-deny Temporal evidence drift")

    temporal_cfg = trigger_record.get("kernel_config", {}).get("temporal", {})
    policies = temporal_cfg.get("policies")
    expected_policy = [{
        "name": policy["policy_name"], "type": policy["policy_type"],
        "trigger": policy["trigger"], "forbidden": policy["forbidden"],
    }]
    if policies != expected_policy or denied_record.get("kernel_config", {}).get("temporal", {}).get("policies") != expected_policy:
        raise DoctrineFailure("C6 receipt policy must retain the exact shipped freeze policy")
    if trigger_record.get("kernel_config") != denied_record.get("kernel_config"):
        raise DoctrineFailure("C6 trigger and denied call must use one identical signed policy")
    if events is None or artifact_dir is None:
        return

    transcript_meta = metadata.get("trace_transcript")
    if not isinstance(transcript_meta, dict):
        raise DoctrineFailure("C6 demo metadata lacks its trace transcript")
    transcript_sha = transcript_meta.get("sha256")
    if not isinstance(transcript_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", transcript_sha):
        raise DoctrineFailure("C6 trace transcript SHA-256 is malformed")
    if denied.get("requires_trace") != transcript_sha or trigger.get("requires_trace") is not None:
        raise DoctrineFailure("C6 receipt-to-trace dependency drift")
    expected_lanes = {
        "standalone": "fresh-state receipt; plain seal verify required",
        "trace": "one init plus exact ordered requests; raw outputs byte-compared",
    }
    if transcript_meta.get("path") != "trace-transcript.json" or transcript_meta.get("harness") != "demo/trace_replay.cjs":
        raise DoctrineFailure("C6 transcript path or reusable harness identity drift")
    if transcript_meta.get("status") != "PASS" or transcript_meta.get("lanes") != expected_lanes:
        raise DoctrineFailure("C6 transcript verification status or lane contract drift")
    transcript_path = artifact_dir / transcript_meta["path"]
    if not transcript_path.is_file() or sha256_file(transcript_path) != transcript_sha:
        raise DoctrineFailure("C6 trace transcript missing or digest mismatch")
    transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
    if transcript.get("schema") != "seal-demo-trace-transcript/v1" or transcript.get("demo_id") != "c6" or len(transcript.get("steps", [])) != 2:
        raise DoctrineFailure("C6 trace transcript shape drift")
    if transcript.get("wasm_sha256") != trigger_record.get("kernel_identity", {}).get("wasm_sha256"):
        raise DoctrineFailure("C6 transcript WASM pin differs from runtime receipt")
    if transcript_meta.get("wasm_sha256") != transcript.get("wasm_sha256"):
        raise DoctrineFailure("C6 trace metadata WASM pin differs from transcript")
    if transcript.get("signed_config") != trigger_record.get("signed_config") or transcript.get("signed_config") != denied_record.get("signed_config"):
        raise DoctrineFailure("C6 transcript signed config differs from runtime receipts")
    for index, (step, transcript_step) in enumerate(zip(steps, transcript["steps"]), 1):
        record = records[index - 1]
        if transcript_step.get("sequence") != index or transcript_step.get("role") != step.get("role"):
            raise DoctrineFailure(f"C6 transcript step {index} sequence/role drift")
        if transcript_step.get("canonical_request") != record.get("canonical_request"):
            raise DoctrineFailure(f"C6 transcript step {index} request/order drift")
        if transcript_step.get("canonical_request_sha256") != record.get("canonical_request_sha256"):
            raise DoctrineFailure(f"C6 transcript step {index} request digest drift")
        if transcript_step.get("raw_kernel_output") != record.get("emitted_bytes"):
            raise DoctrineFailure(f"C6 transcript step {index} raw output drift")
        try:
            transcript_receipt = base64.b64decode(transcript_step["receipt_bytes_base64"], validate=True)
        except Exception as error:
            raise DoctrineFailure(f"C6 transcript step {index} receipt bytes malformed") from error
        artifact_receipt = (artifact_dir / step["receipt_path"]).read_bytes()
        if transcript_receipt != artifact_receipt or sha256_bytes(transcript_receipt) != transcript_step.get("receipt_sha256"):
            raise DoctrineFailure(f"C6 transcript step {index} receipt is not byte-identical to the artifact")
        if transcript_step.get("receipt_path") != step["receipt_path"]:
            raise DoctrineFailure(f"C6 transcript step {index} receipt path drift")

    replay = [event for event in events if event.get("event") == "trace_replay"]
    if replay != [{
        "schema": SCHEMA, "event": "trace_replay", "status": "PASS",
        "transcript_path": "trace-transcript.json", "transcript_sha256": transcript_sha,
        "wasm_sha256": transcript["wasm_sha256"], "steps": 2,
        "harness": "demo/trace_replay.cjs",
    }]:
        raise DoctrineFailure("C6 full trace replay evidence missing or drifted")
    controls = [event for event in events if event.get("event") == "trace_negative_control"]
    expected_controls = [
        {
            "schema": SCHEMA, "event": "trace_negative_control", "name": "drop-trigger",
            "expected": "FAIL", "observed": "FAIL", "status": "PASS",
            "evidence": "fresh-state audit.destroy re-derived forward/ALLOW, mismatching live-session BLOCK bytes",
        },
        {
            "schema": SCHEMA, "event": "trace_negative_control", "name": "byte-flip",
            "expected": "FAIL", "observed": "FAIL", "status": "PASS",
            "evidence": "one byte flipped in the post-trigger raw kernel output",
        },
        {
            "schema": SCHEMA, "event": "trace_negative_control", "name": "restore",
            "expected": "SHA-MATCH+PASS", "observed": "SHA-MATCH+PASS", "status": "PASS",
            "evidence": f"restored transcript sha256={transcript_sha}; full ordered replay PASS",
        },
    ]
    if controls != expected_controls:
        raise DoctrineFailure("C6 trace negative-control evidence missing or drifted")
