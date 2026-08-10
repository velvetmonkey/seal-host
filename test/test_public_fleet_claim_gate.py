#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Physical negative cases for the public fleet claim gate."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "public_fleet_claim_gate.py"


def run_gate(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


def copy_reader_tree(target: Path) -> None:
    for name in ("README.md", "NOTICE.md", "EVIDENCE.md", "SECURITY.md"):
        shutil.copy2(ROOT / name, target / name)
    docs = target / "docs"
    docs.mkdir()
    for source in (ROOT / "docs").glob("*.md"):
        shutil.copy2(source, docs / source.name)


class PublicFleetClaimGateTests(unittest.TestCase):
    def test_current_reader_surfaces_pass(self) -> None:
        result = run_gate(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS public fleet claim gate", result.stdout)

    def test_tampered_private_family_claim_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-claim-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            readme = root / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8")
                + "\n_All Seal-family repositories are currently private; "
                + "these links resolve only for authorised evaluators._\n",
                encoding="utf-8",
            )

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("README.md", result.stderr)
        self.assertIn("stale private-era fleet claim", result.stderr)

    def test_absent_required_surface_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-absent-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            (root / "NOTICE.md").unlink()

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NOTICE.md: absent required reader surface", result.stderr)

    def test_empty_required_surface_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-empty-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            (root / "EVIDENCE.md").write_text("", encoding="utf-8")

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("EVIDENCE.md: empty reader surface", result.stderr)

    def test_unreadable_required_surface_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-unreadable-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            (root / "SECURITY.md").unlink()
            (root / "SECURITY.md").mkdir()

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SECURITY.md: not a readable file", result.stderr)


if __name__ == "__main__":
    unittest.main()
