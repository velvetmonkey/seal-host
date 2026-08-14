#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed physical tests for repository-local claim surface drift."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "claims-surface-drift.mjs"
INPUTS = (
    Path("README.md"),
    Path("docs/LIMITATIONS.md"),
    Path("docs/THREAT-MODEL.md"),
    Path("docs/TRUTH-BOX.md"),
    Path("docs/SEAL-SYSTEM-TCB.md"),
    Path("demo/DOCTRINE.md"),
    Path("demo/C5-README.md"),
    Path("demo/C6-README.md"),
    Path("demo/C7-README.md"),
    Path("demo/RUN-STATE.md"),
    Path("demo/doctrine.py"),
    Path("demo/golden_path.py"),
    Path("demo/golden_path_convergence.py"),
    Path("demo/golden_path_filesystem.py"),
    Path("demo/golden_path_postgres.py"),
    Path("demo/golden_path_temporal.py"),
    Path("demo/golden_path_token.py"),
)


class ClaimsSurfaceDriftGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="claims-surface-drift-guard-")
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / "demo").mkdir()
        (self.root / "docs").mkdir()
        shutil.copy2(SCRIPT, self.root / "scripts" / SCRIPT.name)
        for relative in INPUTS:
            shutil.copy2(ROOT / relative, self.root / relative)

    def tearDown(self) -> None:
        for relative in INPUTS:
            path = self.root / relative
            if path.exists():
                path.chmod(0o600)
        self.temporary.cleanup()

    def run_guard(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["node", str(self.root / "scripts" / SCRIPT.name)],
            cwd=self.root,
            text=True,
            capture_output=True,
            timeout=10,
        )

    def assert_refused(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_in_sync_repository_local_surfaces_pass(self) -> None:
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("in sync across repository-local surfaces", result.stdout)

    def test_repository_local_surface_drift_fails(self) -> None:
        readme = self.root / "README.md"
        text = readme.read_text(encoding="utf-8")
        marker = "<!-- truthbox:end -->"
        self.assertIn(marker, text)
        readme.write_text(
            text.replace(marker, "tampered local claim\n" + marker, 1),
            encoding="utf-8",
        )
        result = self.run_guard()
        self.assert_refused(result)
        self.assertIn("CLAIMS DRIFT", result.stderr)

    def test_manifest_entry_absent_fails_with_named_error(self) -> None:
        (self.root / "docs/SEAL-SYSTEM-TCB.md").unlink()
        result = self.run_guard()
        self.assert_refused(result)
        self.assertIn("ERROR  claim manifest entry docs/SEAL-SYSTEM-TCB.md", result.stderr)

    def test_product_independent_receipt_claim_is_refused(self) -> None:
        readme = self.root / "README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8")
            + "\nThe product independently verifies receipts.\n",
            encoding="utf-8",
        )
        result = self.run_guard()
        self.assert_refused(result)
        self.assertIn("forbidden product-independent receipt claim", result.stderr)

    def test_drift_and_unreadable_manifest_entry_are_both_reported(self) -> None:
        readme = self.root / "README.md"
        text = readme.read_text(encoding="utf-8")
        marker = "<!-- truthbox:end -->"
        readme.write_text(
            text.replace(marker, "tampered local claim\n" + marker, 1),
            encoding="utf-8",
        )
        tcb = self.root / "docs/SEAL-SYSTEM-TCB.md"
        backup = self.root / "docs/SEAL-SYSTEM-TCB.md.backup"
        shutil.move(tcb, backup)
        tcb.mkdir()
        try:
            result = self.run_guard()
        finally:
            tcb.rmdir()
            shutil.move(backup, tcb)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("ERROR  claim manifest entry docs/SEAL-SYSTEM-TCB.md", result.stderr)
        self.assertIn("CLAIMS DRIFT", result.stderr)

    def test_absent_input_fails(self) -> None:
        (self.root / "docs/TRUTH-BOX.md").unlink()
        result = self.run_guard()
        self.assert_refused(result)
        self.assertIn("ERROR  docs/TRUTH-BOX.md", result.stderr)

    def test_empty_input_fails(self) -> None:
        (self.root / "docs/TRUTH-BOX.md").write_text("", encoding="utf-8")
        result = self.run_guard()
        self.assert_refused(result)
        self.assertIn("markers missing or malformed", result.stderr)

    def test_unreadable_input_fails(self) -> None:
        (self.root / "docs/TRUTH-BOX.md").chmod(0)
        result = self.run_guard()
        self.assert_refused(result)
        self.assertIn("ERROR  docs/TRUTH-BOX.md", result.stderr)


if __name__ == "__main__":
    unittest.main()
