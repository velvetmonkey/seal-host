#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the V2.3 contract freeze gate's fail-closed boundary."""

from __future__ import annotations

import json
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
        return root

    def run_gate(self, root: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(root / "scripts" / "contract_freeze_gate.py"), *extra],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def test_clean_tree_passes(self) -> None:
        root = self.make_repo_copy()
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_doc_edit_without_refreeze_fails(self) -> None:
        root = self.make_repo_copy()
        doc = root / "docs" / "EFFECT-ENVELOPE-V23.md"
        doc.write_text(doc.read_text(encoding="utf-8") + "\nan extra clause\n", encoding="utf-8")
        result = self.run_gate(root)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("re-freeze", result.stderr)
        self.assertIn("EFFECT-ENVELOPE-V23.md", result.stderr)

    def test_corpus_edit_without_refreeze_fails(self) -> None:
        root = self.make_repo_copy()
        corpus = root / "rust" / "tests" / "vectors" / "envelope_v23_twin_corpus.json"
        doc = json.loads(corpus.read_text(encoding="utf-8"))
        doc["vectors"][0]["envelope"]["issued_at"] += 1
        corpus.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        result = self.run_gate(root)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("re-freeze", result.stderr)

    def test_refreeze_after_doc_edit_then_passes(self) -> None:
        root = self.make_repo_copy()
        doc = root / "docs" / "EFFECT-ENVELOPE-V23.md"
        doc.write_text(doc.read_text(encoding="utf-8") + "\nan extra clause\n", encoding="utf-8")
        refreeze = self.run_gate(root, "--refreeze")
        self.assertEqual(refreeze.returncode, 0, refreeze.stdout + refreeze.stderr)
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
        self.assertNotIn("if:", job, "the freeze gate step must be unconditional")


if __name__ == "__main__":
    unittest.main()
