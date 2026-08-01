#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "proof_inventory.py"
SPEC = importlib.util.spec_from_file_location("proof_inventory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


class ProofInventoryTests(unittest.TestCase):
    def make_root(self, directory: str) -> Path:
        root = Path(directory)
        (root / "Host").mkdir()
        (root / "Test").mkdir()
        (root / ".lake/build/lib/lean/Host").mkdir(parents=True)
        (root / "Test/Axioms.lean").write_text("import Host.Wired\n", encoding="utf-8")
        (root / "Host/Wired.lean").write_text(
            "theorem wired : True := by trivial\n"
            "/-- info: 'wired' does not depend on any axioms -/\n"
            "#guard_msgs in #print axioms wired\n",
            encoding="utf-8",
        )
        (root / ".lake/build/lib/lean/Host/Wired.olean").touch()
        return root

    def test_wired_compiled_and_classified_module_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = inventory.evaluate(self.make_root(directory))
            self.assertTrue(report.passed, report)
            self.assertEqual(len(report.rows), 1)
            self.assertEqual(report.rows[0].assigned, "axiom_check")
            self.assertTrue(report.rows[0].compiled)
            self.assertTrue(report.rows[0].axiom_classified)

    def test_stale_olean_does_not_launder_unimported_theorem_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/Throwaway.lean").write_text(
                "theorem proof_inventory_negative_control : True := by trivial\n",
                encoding="utf-8",
            )
            (root / ".lake/build/lib/lean/Host/Throwaway.olean").touch()
            report = inventory.evaluate(root)
            row = next(row for row in report.rows if row.module == "Host.Throwaway")
            self.assertFalse(row.compiled)
            self.assertEqual(row.assigned, "UNASSIGNED")
            self.assertTrue(row.orphaned)
            self.assertFalse(report.passed)

    def test_assigned_module_without_build_artifact_is_orphaned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / ".lake/build/lib/lean/Host/Wired.olean").unlink()
            report = inventory.evaluate(root)
            self.assertTrue(report.rows[0].orphaned)
            self.assertFalse(report.passed)

    def test_comments_do_not_create_theorem_or_import_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/CommentOnly.lean").write_text(
                "/- theorem fake : False := by trivial -/\n"
                "-- theorem alsoFake : False := by trivial\n",
                encoding="utf-8",
            )
            report = inventory.evaluate(root)
            self.assertNotIn("Host.CommentOnly", {row.module for row in report.rows})


if __name__ == "__main__":
    unittest.main()
