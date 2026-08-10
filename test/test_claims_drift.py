#!/usr/bin/env python3
"""Regression tests for local and cross-repository claims drift."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "claims-drift.mjs"
REPOSITORIES = (
    "seal",
    "seal-host",
    "seal-check",
    "seal-live-demo",
    "seal-verify-action",
    "seal-assurance-kit",
    "mcp-seal-dev",
)
BLOCK = (
    "<!-- truthbox:begin -->\n"
    "> **Runtime profile: `compatible`.**\n"
    "> **Claim:** the family check must agree.\n"
    "> **Non-claim:** a hash match is not a deployment proof.\n"
    "<!-- truthbox:end -->\n"
)


class ClaimsDriftTests(unittest.TestCase):
    def family_root(self) -> Path:
        temporary = Path(tempfile.mkdtemp(prefix="claims-drift-family-"))
        for repo in REPOSITORIES:
            docs = temporary / repo / "docs"
            docs.mkdir(parents=True)
            (docs / "TRUTH-BOX.md").write_text(BLOCK, encoding="utf-8")
        return temporary

    def run_family(self, family_root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["node", str(SCRIPT), "--family-root", str(family_root)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=10,
        )

    def test_matching_family_is_green(self) -> None:
        family = self.family_root()
        result = self.run_family(family)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("family truth-box hashes match across all seven repos", result.stdout)

    def test_tamper_red_restore_green(self) -> None:
        family = self.family_root()
        target = family / "seal-check" / "docs" / "TRUTH-BOX.md"
        original = target.read_text(encoding="utf-8")
        target.write_text(original.replace("family check must agree", "tampered family claim"), encoding="utf-8")
        red = self.run_family(family)
        self.assertEqual(red.returncode, 1, red.stdout + red.stderr)
        self.assertIn("FAMILY CLAIMS DRIFT", red.stderr)

        target.write_text(original, encoding="utf-8")
        green = self.run_family(family)
        self.assertEqual(green.returncode, 0, green.stdout + green.stderr)

    def test_absent_input_fails(self) -> None:
        family = self.family_root()
        (family / "seal-check" / "docs" / "TRUTH-BOX.md").unlink()
        result = self.run_family(family)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_empty_input_fails(self) -> None:
        family = self.family_root()
        (family / "seal-check" / "docs" / "TRUTH-BOX.md").write_text("", encoding="utf-8")
        result = self.run_family(family)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_unreadable_input_fails(self) -> None:
        family = self.family_root()
        target = family / "seal-check" / "docs" / "TRUTH-BOX.md"
        target.chmod(0o000)
        try:
            result = self.run_family(family)
        finally:
            target.chmod(0o644)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
