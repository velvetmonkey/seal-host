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
        (root / ".github/workflows").mkdir(parents=True)
        (root / "lakefile.toml").write_text(
            'name = "fixture"\n'
            'testDriver = "lean_tests"\n'
            'defaultTargets = ["ci_root"]\n\n'
            '[[lean_lib]]\nname = "HostLib"\nglobs = ["Host.+"]\n\n'
            '[[lean_exe]]\nname = "ci_root"\nroot = "Test.CiRoot"\n\n'
            '[[lean_exe]]\nname = "lean_tests"\nroot = "Test.CiRoot"\n',
            encoding="utf-8",
        )
        (root / ".github/workflows/ci.yml").write_text(
            "name: CI\non: [push, pull_request]\njobs:\n  build:\n    steps:\n"
            "      - run: lake build\n"
            "      - run: lake test\n",
            encoding="utf-8",
        )
        (root / "Test/CiRoot.lean").write_text(
            "import Host.Wired\n", encoding="utf-8"
        )
        (root / "Host/Wired.lean").write_text(
            "theorem wired : True := by trivial\n", encoding="utf-8"
        )
        return root

    def run_gate(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def assert_orphan_source(self, source: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/Evasion.lean").write_text(source, encoding="utf-8")
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ORPHANED\tHost.Evasion", result.stdout)

    def test_workflow_build_closure_is_reached(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_gate(self.make_root(directory))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("REACHED=1", result.stdout)
            self.assertIn("REACHED\tHost.Wired", result.stdout)

    def test_orphan_control_is_red_and_names_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/Planted.lean").write_text(
                "theorem planted_orphan : True := by trivial\n", encoding="utf-8"
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ORPHANED\tHost.Planted", result.stdout)
            self.assertIn("ORPHAN PROOF MODULE: Host.Planted", result.stderr)

    def test_protected_theorem_is_detected(self) -> None:
        self.assert_orphan_source("protected theorem t : True := by trivial\n")

    def test_private_theorem_is_detected(self) -> None:
        self.assert_orphan_source("private theorem t : True := by trivial\n")

    def test_same_line_attribute_theorem_is_detected(self) -> None:
        self.assert_orphan_source("@[simp] theorem t : True := by trivial\n")

    def test_nonrec_theorem_is_detected(self) -> None:
        self.assert_orphan_source("nonrec theorem t : True := by trivial\n")

    def test_indented_theorem_is_detected(self) -> None:
        self.assert_orphan_source("  theorem t : True := by trivial\n")

    def test_comment_markers_in_strings_do_not_hide_theorem(self) -> None:
        self.assert_orphan_source(
            'def openMarker : String := "/-"\n'
            "theorem visible_after_string : True := by trivial\n"
            'def closeMarker : String := "-/"\n'
        )

    def test_comment_markers_in_raw_strings_do_not_hide_theorem(self) -> None:
        self.assert_orphan_source(
            'def markers : String := r#"/- an embedded " quote -/"#\n'
            "theorem visible_after_raw_string : True := by trivial\n"
        )

    def test_severance_control_is_red_and_names_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Test/CiRoot.lean").write_text("", encoding="utf-8")
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ORPHANED\tHost.Wired", result.stdout)
            self.assertIn("ORPHAN PROOF MODULE: Host.Wired", result.stderr)

    def test_one_character_local_root_typo_is_unclassified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/Typo.lean").write_text(
                "import Hosts.Wired\n"
                "theorem typo_probe : True := by trivial\n",
                encoding="utf-8",
            )
            (root / "Test/CiRoot.lean").write_text(
                "import Host.Wired\nimport Host.Typo\n", encoding="utf-8"
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("UNCLASSIFIED\tHost.Typo", result.stdout)
            self.assertIn("cannot resolve import Hosts.Wired", result.stderr)

    def test_nonexistent_upstream_import_is_unclassified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/Upstream.lean").write_text(
                "import Mathlib.CompletelyFakeInventoryControl\n"
                "theorem upstream_probe : True := by trivial\n",
                encoding="utf-8",
            )
            (root / "Test/CiRoot.lean").write_text(
                "import Host.Wired\nimport Host.Upstream\n", encoding="utf-8"
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("UNCLASSIFIED\tHost.Upstream", result.stdout)
            self.assertIn(
                "cannot resolve import Mathlib.CompletelyFakeInventoryControl",
                result.stderr,
            )

    def test_circular_import_is_unclassified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/CycleA.lean").write_text(
                "import Host.CycleB\n"
                "theorem cycle_probe : True := by trivial\n",
                encoding="utf-8",
            )
            (root / "Host/CycleB.lean").write_text(
                "import Host.CycleA\n", encoding="utf-8"
            )
            (root / "Test/CiRoot.lean").write_text(
                "import Host.Wired\nimport Host.CycleA\n", encoding="utf-8"
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("UNCLASSIFIED\tHost.CycleA", result.stdout)
            self.assertIn("circular local import", result.stderr)

    def test_comments_strings_and_modifiers_do_not_evade_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Test/CiRoot.lean").write_text(
                "import Host.Wired\nimport Host.Prefixes\n", encoding="utf-8"
            )
            (root / "Host/Prefixes.lean").write_text(
                '/- theorem fake : False := by trivial -/\n'
                'def prose : String := "theorem alsoFake : False"\n'
                "@[simp] protected theorem real : True := by trivial\n",
                encoding="utf-8",
            )
            report = inventory.evaluate(root)
            row = next(row for row in report.rows if row.module == "Host.Prefixes")
            self.assertEqual(row.declarations, 1)
            self.assertEqual(row.status, "REACHED")

    def test_workflow_comments_and_echoes_are_not_builds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            workflow = root / ".github/workflows/ci.yml"
            workflow.write_text(
                "name: CI\non: push\njobs:\n  build:\n    steps:\n"
                "      - run: |\n"
                "          # lake build Host.NotACommand\n"
                '          echo "lake build Host.NotACommand"\n'
                "          lake build\n",
                encoding="utf-8",
            )
            invocations = inventory.extract_invocations(root)
            self.assertEqual(len(invocations), 1)
            self.assertEqual(invocations[0].kind, "build")
            self.assertEqual(invocations[0].target, "")

    def test_exception_is_named_and_not_laundered_as_reached(self) -> None:
        self.assertEqual(
            set(inventory.EXCEPTIONS), {"Host.CanonicalL0Liveness"}
        )
        self.assertIn(
            "Ben, 2026-08-01", inventory.EXCEPTIONS["Host.CanonicalL0Liveness"]
        )


if __name__ == "__main__":
    unittest.main()
