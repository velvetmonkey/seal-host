#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reusable doctrine spine for Seal demos.

Runtime receipts are copied byte-for-byte into a durable artifact directory,
verified there, and described by one NDJSON trace.  TTY and Markdown output
are projections of that trace; neither is an independent demo script.
"""

from __future__ import annotations

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
        print(f"  receipt-path={event['receipt_path']} seal-verify={event['seal_verify']['status']}")
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
        print(f"  {CLAIM_SCOPE}")
    elif kind == "anti_forge":
        print(
            f"ANTI-FORGE rejected exit={event['tampered_verify_exit']} "
            f"restore-byte-exact={str(event['restored_sha256'] == event['original_sha256']).lower()}"
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
            f"- `seal verify`: **{event['seal_verify']['status']}** (exit `{event['seal_verify']['exit_code']}`)",
        ])
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
        lines.extend([f"- Claim scope: {CLAIM_SCOPE}", ""])
    anti = next(event for event in events if event["event"] == "anti_forge")
    lines.extend([
        "### Anti-forge negative control",
        "",
        f"Corrupted receipt rejected with exit `{anti['tampered_verify_exit']}`; restored SHA-256 "
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
        self.metadata: dict | None = None

    def emit(self, event: dict, *, render: bool = True) -> None:
        with self.trace_path.open("a", encoding="utf-8") as handle:
            handle.write(compact(event) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if render:
            render_tty_event(event, color=self.color)

    def configure(self, policy_recipe: str, policy: Path, *, active: list[str], inactive: list[str], experimental: list[str]) -> None:
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
        self.emit(self.metadata)

    def record_receipt(self, source: Path, *, role: str, theorem_ids: list[str], budget: dict | None = None) -> Path:
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
        verified = run([str(self.seal), "verify", str(dest)])
        if "PASS  VERIFIED" not in verified.stdout:
            raise DoctrineFailure(f"seal verify did not report PASS VERIFIED: {dest}")

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
            "seal_verify": {"command": "seal verify", "status": "PASS", "exit_code": verified.returncode},
            "claim_scope": CLAIM_SCOPE,
        }
        if budget is not None:
            event["budget"] = budget
        self.recorded_sources.add(source)
        self.copied_receipts.append(dest)
        self.emit(event)
        return dest

    def _verify_all(self) -> None:
        for receipt in self.copied_receipts:
            result = run([str(self.seal), "verify", str(receipt)])
            if "PASS  VERIFIED" not in result.stdout:
                raise DoctrineFailure(f"final seal verify did not report PASS: {receipt}")

    def _anti_forge(self) -> None:
        if not self.copied_receipts:
            raise DoctrineFailure("anti-forge control requires an emitted receipt")
        receipt = self.copied_receipts[0]
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
        self.emit({"schema": SCHEMA, "event": "verification_summary", "receipts": len(self.copied_receipts), "status": "PASS"}, render=False)
        self.emit({"schema": SCHEMA, "event": "non_claims", "lines": NON_CLAIMS})
        markdown = render_markdown(self.trace_path, self.artifact_dir / "receipt-strip.md")
        validate_trace(self.artifact_dir)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with Path(summary).open("a", encoding="utf-8") as handle:
                handle.write(markdown)


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
    if not steps or steps[0].get("verdict") != "DENY":
        raise DoctrineFailure("first persuasive step must be DENY")
    if len(steps) < 2 or steps[0].get("role") != "ATTACK-DENY" or steps[1].get("role") != "LEGIT":
        raise DoctrineFailure("ordered narrative must begin ATTACK-DENY then LEGIT")
    if steps[1].get("verdict") != "ALLOW":
        raise DoctrineFailure("the LEGIT step immediately after ATTACK-DENY must ALLOW")
    if any(step.get("role") != "CONTROL" for step in steps[2:]):
        raise DoctrineFailure("only CONTROL steps may follow the DENY→ALLOW hero pair")
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
        if step["seal_verify"] != {"command": "seal verify", "status": "PASS", "exit_code": 0}:
            raise DoctrineFailure(f"step {index} lacks green seal verify")
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
    if summaries != [{"schema": SCHEMA, "event": "verification_summary", "receipts": len(steps), "status": "PASS"}]:
        raise DoctrineFailure("receipt verification summary mismatch")
    non_claims = [event for event in events if event.get("event") == "non_claims"]
    if len(non_claims) != 1 or non_claims[0].get("lines") != NON_CLAIMS:
        raise DoctrineFailure("fixed non-claims block missing or changed")
    if metadata.get("demo_id") == "c4":
        _validate_c4(metadata, steps, receipt_records, manifest)
    expected_md = render_markdown(trace, artifact_dir / ".receipt-strip.check.md")
    check_path = artifact_dir / ".receipt-strip.check.md"
    try:
        if (artifact_dir / "receipt-strip.md").read_text(encoding="utf-8") != expected_md:
            raise DoctrineFailure("Markdown strip is not reproducible from NDJSON")
    finally:
        check_path.unlink(missing_ok=True)


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
