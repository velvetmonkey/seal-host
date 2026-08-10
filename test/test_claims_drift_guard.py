#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed physical tests for the claims-drift executable."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "claims-drift.mjs"
INPUTS = (
    Path("README.md"),
    Path("docs/LIMITATIONS.md"),
    Path("docs/THREAT-MODEL.md"),
    Path("docs/TRUTH-BOX.md"),
)


class ClaimsDriftGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="claims-drift-guard-")
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / "docs").mkdir()
        shutil.copy2(SCRIPT, self.root / "scripts" / SCRIPT.name)
        for relative in INPUTS:
            shutil.copy2(ROOT / relative, self.root / relative)

    def tearDown(self) -> None:
        # An unreadable-file test must not make TemporaryDirectory cleanup
        # platform-dependent.
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

    def test_in_sync_inputs_pass(self) -> None:
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("all claim blocks in sync", result.stdout)

    def test_physical_drift_fails(self) -> None:
        readme = self.root / "README.md"
        text = readme.read_text(encoding="utf-8")
        marker = "<!-- truthbox:end -->"
        self.assertIn(marker, text)
        readme.write_text(
            text.replace(marker, "tampered claim\n" + marker, 1),
            encoding="utf-8",
        )
        result = self.run_guard()
        self.assert_refused(result)
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
