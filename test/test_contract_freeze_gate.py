#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the V2.3 contract freeze gate's fail-closed boundary."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "contract_freeze_gate.py"
MANIFEST = "docs/effect-envelope-v23.freeze.json"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
FROZEN_FILES = (
    "docs/EFFECT-ENVELOPE-V23.md",
    "rust/src/envelope_v23.rs",
    "rust/tests/envelope_v23.rs",
    "rust/tests/envelope_v23_twin.rs",
    "rust/tests/vectors/envelope_v23_twin_corpus.json",
    "rust/tests/vectors/envelope_v23_twin_expected.hex",
    "scripts/envelope_v23_twin_lane.lean",
)


class ContractFreezeGateTests(unittest.TestCase):
    def make_repo_copy(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="freeze-gate-test-"))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for relative in FROZEN_FILES + (MANIFEST, "scripts/contract_freeze_gate.py"):
            source = ROOT / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        return root

    def run_gate(
        self, root: Path, *extra: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        process_env = os.environ.copy()
        process_env.pop("CI", None)
        process_env.pop("GITHUB_ACTIONS", None)
        process_env.pop("CONTRACT_FREEZE_CI", None)
        if env:
            process_env.update(env)
        return subprocess.run(
            [sys.executable, str(root / "scripts" / "contract_freeze_gate.py"), *extra],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=30,
            env=process_env,
        )

    def test_clean_tree_passes(self) -> None:
        root = self.make_repo_copy()
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rust_comment_edit_is_not_contract_drift(self) -> None:
        root = self.make_repo_copy()
        source = root / "rust" / "src" / "envelope_v23.rs"
        text = source.read_text(encoding="utf-8")
        before = "Rust byte twin and host-side gates"
        after = "Rust byte twin plus host-side gates"
        self.assertEqual(text.count(before), 1)
        source.write_text(text.replace(before, after), encoding="utf-8")
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rust_comment_line_addition_is_not_contract_drift(self) -> None:
        root = self.make_repo_copy()
        source = root / "rust" / "src" / "envelope_v23.rs"
        text = source.read_text(encoding="utf-8")
        marker = "use crate::ed25519::{self, VerificationError};"
        self.assertEqual(text.count(marker), 1)
        source.write_text(
            text.replace(marker, "// Non-contract rationale.\n" + marker),
            encoding="utf-8",
        )
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rust_wire_byte_edit_is_contract_drift(self) -> None:
        root = self.make_repo_copy()
        source = root / "rust" / "src" / "envelope_v23.rs"
        text = source.read_text(encoding="utf-8")
        before = 'b"seal.effect/v2\\0"'
        after = 'b"seal.effect/v3\\0"'
        self.assertEqual(text.count(before), 1)
        source.write_text(text.replace(before, after), encoding="utf-8")
        result = self.run_gate(root)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("rust/src/envelope_v23.rs", result.stderr)
        self.assertIn("--refreeze cannot approve", result.stderr)

    def test_rust_test_function_name_is_not_contract_drift(self) -> None:
        root = self.make_repo_copy()
        source = root / "rust" / "tests" / "envelope_v23.rs"
        text = source.read_text(encoding="utf-8")
        before = "fn byte_twin_matches_fable_golden_vector()"
        after = "fn byte_twin_matches_fable_golden_bytes()"
        self.assertEqual(text.count(before), 1)
        source.write_text(text.replace(before, after), encoding="utf-8")
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lean_comment_edit_is_not_contract_drift(self) -> None:
        root = self.make_repo_copy()
        source = root / "scripts" / "envelope_v23_twin_lane.lean"
        text = source.read_text(encoding="utf-8")
        before = "Any divergence from the Rust encoder"
        after = "Every divergence from the Rust encoder"
        self.assertEqual(text.count(before), 1)
        source.write_text(text.replace(before, after), encoding="utf-8")
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_doc_edit_without_refreeze_fails(self) -> None:
        root = self.make_repo_copy()
        doc = root / "docs" / "EFFECT-ENVELOPE-V23.md"
        doc.write_text(doc.read_text(encoding="utf-8") + "\nan extra clause\n", encoding="utf-8")
        result = self.run_gate(root)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--refreeze cannot approve", result.stderr)
        self.assertIn("EFFECT-ENVELOPE-V23.md", result.stderr)

    def test_corpus_edit_without_refreeze_fails(self) -> None:
        root = self.make_repo_copy()
        corpus = root / "rust" / "tests" / "vectors" / "envelope_v23_twin_corpus.json"
        doc = json.loads(corpus.read_text(encoding="utf-8"))
        doc["vectors"][0]["envelope"]["issued_at"] += 1
        corpus.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        result = self.run_gate(root)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--refreeze cannot approve", result.stderr)

    def test_refreeze_cannot_approve_doc_edit(self) -> None:
        root = self.make_repo_copy()
        doc = root / "docs" / "EFFECT-ENVELOPE-V23.md"
        manifest = root / MANIFEST
        before_manifest = manifest.read_bytes()
        doc.write_text(doc.read_text(encoding="utf-8") + "\nan extra clause\n", encoding="utf-8")
        refreeze = self.run_gate(root, "--refreeze")
        self.assertNotEqual(refreeze.returncode, 0, refreeze.stdout + refreeze.stderr)
        self.assertIn("--refreeze cannot approve", refreeze.stderr)
        self.assertEqual(manifest.read_bytes(), before_manifest)
        result = self.run_gate(root)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_manual_review_baseline_update_allows_legible_refreeze(self) -> None:
        root = self.make_repo_copy()
        doc = root / "docs" / "EFFECT-ENVELOPE-V23.md"
        script = root / "scripts" / "contract_freeze_gate.py"
        old_hash = hashlib.sha256(doc.read_bytes()).hexdigest()
        doc.write_text(doc.read_text(encoding="utf-8") + "\na reviewed clause\n", encoding="utf-8")
        new_hash = hashlib.sha256(doc.read_bytes()).hexdigest()
        source = script.read_text(encoding="utf-8")
        self.assertEqual(source.count(old_hash), 1)
        script.write_text(source.replace(old_hash, new_hash), encoding="utf-8")

        refreeze = self.run_gate(root, "--refreeze")
        self.assertEqual(refreeze.returncode, 0, refreeze.stdout + refreeze.stderr)
        self.assertIn("REFREEZE UPDATE docs/EFFECT-ENVELOPE-V23.md", refreeze.stdout)
        self.assertIn(f"old={old_hash}", refreeze.stdout)
        self.assertIn(f"new={new_hash}", refreeze.stdout)
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_refreeze_is_forbidden_in_ci(self) -> None:
        root = self.make_repo_copy()
        result = self.run_gate(root, "--refreeze", env={"CONTRACT_FREEZE_CI": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("forbidden on a CI runner", result.stderr)

    def test_tracked_file_added_to_frozen_directory_fails(self) -> None:
        root = self.make_repo_copy()
        added = root / "rust" / "tests" / "vectors" / "effect_envelope_v23_added.txt"
        added.write_text("adversarial extra vector\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", str(added)], check=True)
        result = self.run_gate(root)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("effect_envelope_v23_added.txt", result.stderr)
        self.assertIn("independent review baseline", result.stderr)

    def test_untracked_file_in_frozen_directory_is_ignored(self) -> None:
        root = self.make_repo_copy()
        added = root / "rust" / "tests" / "vectors" / "editor-scratch.tmp"
        added.write_text("untracked junk\n", encoding="utf-8")
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_expectation_golden_line_tamper_fails_even_after_refreeze(self) -> None:
        root = self.make_repo_copy()
        expected = root / "rust" / "tests" / "vectors" / "envelope_v23_twin_expected.hex"
        lines = expected.read_text(encoding="utf-8").splitlines()
        corpus = json.loads(
            (root / "rust" / "tests" / "vectors" / "envelope_v23_twin_corpus.json").read_text(
                encoding="utf-8"
            )
        )
        golden = next(
            i for i, v in enumerate(corpus["vectors"]) if v["name"] == "golden-fable"
        )
        lines[golden] = lines[golden][:-2] + ("00" if lines[golden][-2:] != "00" else "01")
        expected.write_text("\n".join(lines) + "\n", encoding="utf-8")
        refreeze = self.run_gate(root, "--refreeze")
        self.assertNotEqual(refreeze.returncode, 0, refreeze.stdout + refreeze.stderr)
        self.assertIn("guard_msgs", refreeze.stdout + refreeze.stderr)

    def test_vector_count_mismatch_fails(self) -> None:
        root = self.make_repo_copy()
        expected = root / "rust" / "tests" / "vectors" / "envelope_v23_twin_expected.hex"
        lines = expected.read_text(encoding="utf-8").splitlines()
        expected.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        refreeze = self.run_gate(root, "--refreeze")
        self.assertNotEqual(refreeze.returncode, 0, refreeze.stdout + refreeze.stderr)

    def test_unknown_manifest_key_fails(self) -> None:
        root = self.make_repo_copy()
        manifest = root / MANIFEST
        doc = json.loads(manifest.read_text(encoding="utf-8"))
        doc["unknown"] = True
        manifest.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        result = self.run_gate(root)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("manifest rejected", result.stderr)

    def test_missing_manifest_fails(self) -> None:
        root = self.make_repo_copy()
        (root / MANIFEST).unlink()
        result = self.run_gate(root)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("manifest rejected", result.stderr)

    def test_ci_runs_gate_unconditionally(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("python3 scripts/contract_freeze_gate.py", workflow)
        match = re.search(
            r"^  contract-freeze:\n(?:^(?:    .*)?\n)+", workflow, flags=re.MULTILINE
        )
        self.assertIsNotNone(match, "ci.yml must define a contract-freeze job")
        job = match.group(0)
        self.assertIn("python3 scripts/contract_freeze_gate.py", job)
        self.assertNotIn(
            "SEAL_CI_READ_TOKEN",
            job,
            "the freeze gate must run without the private dependency token",
        )
        gate_position = job.index("python3 scripts/contract_freeze_gate.py")
        gate_start = job.rfind("\n      - ", 0, gate_position)
        gate_end = job.find("\n      - ", gate_position)
        gate_step = job[gate_start:gate_end]
        self.assertNotIn("if:", gate_step, "the freeze gate step must be unconditional")
        self.assertIn(
            "continue-on-error: true",
            gate_step,
            "the freeze gate must report without masking later controls",
        )
        self.assertIn(
            "name: Require every isolated CI step to pass",
            job,
            "isolated failures need a final fail-closed aggregate",
        )
        self.assertIn(
            "SEAL_CONTROL_STEPS: ${{ toJSON(steps) }}",
            job,
            "the final gate must inspect every isolated outcome",
        )
        self.assertIn(
            'CONTRACT_FREEZE_CI: "1"',
            job,
            "the CI job must explicitly disable the refreeze path",
        )

        workflow_header = workflow.split("\njobs:", maxsplit=1)[0]
        self.assertRegex(workflow_header, r"(?m)^on:\s*$")
        self.assertRegex(workflow_header, r"(?m)^  push:\s*$")
        self.assertRegex(workflow_header, r"(?m)^  pull_request:\s*$")


if __name__ == "__main__":
    unittest.main()
