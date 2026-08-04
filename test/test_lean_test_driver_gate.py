#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Behavioral tests for the Lean aggregate-driver wiring gate."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "lean_test_driver_gate.py"


class LeanTestDriverGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "Test").mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_fixture(
        self,
        *,
        source_children: tuple[str, ...] = ("first_test", "second_test"),
        needs_field: str = "needs",
        needed_children: tuple[str, ...] = ("first_test", "second_test"),
    ) -> None:
        source_entries = "\n".join(f'  "{name}",' for name in source_children)
        (self.root / "Test" / "LeanTests.lean").write_text(
            textwrap.dedent(
                f"""
                namespace Test.LeanTests
                private def testBinaries : Array String := #[
                {source_entries}
                ]
                end Test.LeanTests
                """
            ),
            encoding="utf-8",
        )
        needs = ", ".join(f'"{name}"' for name in needed_children)
        child_tables = "\n".join(
            f'[[lean_exe]]\nname = "{name}"\nroot = "Test.Child"'
            for name in source_children
        )
        (self.root / "lakefile.toml").write_text(
            textwrap.dedent(
                f"""
                name = "fixture"
                testDriver = "lean_tests"
                {child_tables}
                [[lean_exe]]
                name = "lean_tests"
                root = "Test.LeanTests"
                {needs_field} = [{needs}]
                """
            ),
            encoding="utf-8",
        )

    def run_gate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(GATE), "--root", str(self.root)],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_matching_source_derived_roster_passes(self) -> None:
        self.write_fixture()
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("exactly matches all 2 children derived", result.stdout)

    def test_unknown_needs_spelling_fails(self) -> None:
        self.write_fixture(needs_field="needs_TYPO")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("needs_TYPO", result.stderr)

    def test_child_removed_only_from_needs_fails(self) -> None:
        self.write_fixture(needed_children=("first_test",))
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("missing=['second_test']", result.stderr)

    def test_source_change_is_the_single_roster_authority(self) -> None:
        self.write_fixture(
            source_children=("replacement_test",),
            needed_children=("replacement_test",),
        )
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("exactly matches all 1 children derived", result.stdout)

    def test_every_lean_action_has_a_preceding_gate_call(self) -> None:
        action_marker = "leanprover/lean-action"
        gate_marker = "python3 scripts/lean_test_driver_gate.py"
        action_count = 0
        for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            actions = [match.start() for match in re.finditer(action_marker, text)]
            gates = [match.start() for match in re.finditer(gate_marker, text)]
            if not actions:
                continue
            action_count += len(actions)
            self.assertEqual(len(gates), len(actions), workflow)
            for gate, action in zip(gates, actions, strict=True):
                self.assertLess(gate, action, workflow)
        self.assertGreater(action_count, 0, "no lean-action invocation found")

    def test_every_aggregate_test_has_a_native_prerequisite(self) -> None:
        action_marker = "leanprover/lean-action"
        native_build = re.compile(
            r"^\s+(?:run: )?bash \.lake/packages/mcp-seal/c/build\.sh$",
            re.MULTILINE,
        )
        explicit_test = re.compile(
            r"^\s+(?:run: )?(?:python3 scripts/ci_disk_telemetry\.py \S+ -- )?lake test$",
            re.MULTILINE,
        )
        action_count = 0
        test_count = 0

        for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            actions = [match.start() for match in re.finditer(action_marker, text)]
            if not actions:
                continue

            builds = [match.start() for match in native_build.finditer(text)]
            tests = [match.start() for match in explicit_test.finditer(text)]
            action_count += len(actions)
            test_count += len(tests)
            self.assertLessEqual(len(tests), len(builds), workflow)

            for test in tests:
                action = max((item for item in actions if item < test), default=-1)
                build = max((item for item in builds if item < test), default=-1)
                self.assertGreater(action, -1, workflow)
                self.assertGreater(build, -1, workflow)
                next_step = text.find("\n      - ", action)
                action_block = text[action : next_step if next_step != -1 else None]
                self.assertIn("test: false", action_block, workflow)
                self.assertLess(action, build, workflow)
                self.assertLess(build, test, workflow)

        self.assertEqual(action_count, 7, "review every lean-action call site")
        self.assertEqual(test_count, 6, "review every aggregate lake test call site")

    def test_split_aggregate_jobs_are_required_predecessors(self) -> None:
        expected = (
            ("golden-path.yml", "lean-aggregate", "deterministic-shell"),
            ("security.yml", "fuzz-hostile-ingress-lean", "fuzz-hostile-ingress"),
        )
        for filename, lean_job, downstream_job in expected:
            workflow = (ROOT / ".github" / "workflows" / filename).read_text(
                encoding="utf-8"
            )
            with self.subTest(workflow=filename):
                self.assertRegex(
                    workflow,
                    rf"(?m)^  {downstream_job}:\n    needs: {lean_job}$",
                )
                lean_start = workflow.index(f"  {lean_job}:\n")
                downstream_start = workflow.index(f"  {downstream_job}:\n")
                lean_block = workflow[lean_start:downstream_start]
                self.assertIn("bash .lake/packages/mcp-seal/c/build.sh", lean_block)
                self.assertRegex(lean_block, r"(?m)-- lake test$")
                self.assertIn("SEAL_CONTROL_STEPS: ${{ toJSON(steps) }}", lean_block)
                self.assertIn("run: python3 scripts/ci_control_aggregate.py", lean_block)


if __name__ == "__main__":
    unittest.main()
