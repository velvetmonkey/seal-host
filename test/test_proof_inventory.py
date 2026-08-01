#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
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

    def assert_orphan_detected(self, source: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/Evasion.lean").write_text(source, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--root", str(root)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("Host.Evasion\tyes\tUNASSIGNED", result.stdout)
            self.assertIn("ORPHAN PROOF MODULE: Host.Evasion", result.stderr)

    def test_protected_theorem_is_detected(self) -> None:
        self.assert_orphan_detected("protected theorem t : True := by trivial\n")

    def test_private_theorem_is_detected(self) -> None:
        self.assert_orphan_detected("private theorem t : True := by trivial\n")

    def test_same_line_attribute_theorem_is_detected(self) -> None:
        self.assert_orphan_detected("@[simp] theorem t : True := by trivial\n")

    def test_nonrec_theorem_is_detected(self) -> None:
        self.assert_orphan_detected("nonrec theorem t : True := by trivial\n")

    def test_indented_theorem_is_detected(self) -> None:
        self.assert_orphan_detected("  theorem t : True := by trivial\n")

    def test_comment_markers_in_strings_do_not_hide_theorem(self) -> None:
        self.assert_orphan_detected(
            'def openMarker : String := "/-"\n'
            "theorem frisk_hidden_by_string : True := by trivial\n"
            'def closeMarker : String := "-/"\n'
        )

    def test_comment_markers_in_raw_strings_do_not_hide_theorem(self) -> None:
        self.assert_orphan_detected(
            'def markers : String := r#"/- an embedded " quote -/"#\n'
            "theorem visible_after_raw_string : True := by trivial\n"
        )

    def test_reserved_module_set_is_pinned(self) -> None:
        self.assertEqual(set(inventory.RESERVED), {"Host.CanonicalL0Liveness"})

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

    def test_theorem_text_in_string_does_not_create_row(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/StringOnly.lean").write_text(
                'def prose : String := "theorem fake : False"\n', encoding="utf-8"
            )
            report = inventory.evaluate(root)
            self.assertNotIn("Host.StringOnly", {row.module for row in report.rows})


if __name__ == "__main__":
    unittest.main()
