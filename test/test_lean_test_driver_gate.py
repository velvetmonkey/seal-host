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

    def write_runtime_fixture(self, *, tamper: str | None = None) -> None:
        source = (ROOT / "Test" / "LeanTests.lean").read_text(encoding="utf-8")
        children = tuple(
            re.findall(r'^\s*"([A-Za-z0-9_-]+)",?\s*$', source, re.MULTILINE)
        )
        self.write_fixture(source_children=children, needed_children=children)
        if tamper is not None:
            source = source.replace("for name in testBinaries do", tamper)
        (self.root / "Test" / "LeanTests.lean").write_text(
            source, encoding="utf-8"
        )

    def test_matching_source_derived_roster_passes(self) -> None:
        self.write_fixture()
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("exactly matches all 2 children derived", result.stdout)

    def test_missing_driver_source_fails_closed(self) -> None:
        self.write_fixture()
        (self.root / "Test" / "LeanTests.lean").unlink()
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cannot read", result.stderr)

    def test_empty_driver_source_fails_closed(self) -> None:
        self.write_fixture()
        (self.root / "Test" / "LeanTests.lean").write_text("", encoding="utf-8")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cannot find the testBinaries array", result.stderr)

    def test_unreadable_driver_source_fails_closed(self) -> None:
        self.write_fixture()
        source = self.root / "Test" / "LeanTests.lean"
        source.unlink()
        source.mkdir()
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cannot read", result.stderr)

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

    def test_partial_runtime_loop_fails_closed(self) -> None:
        self.write_runtime_fixture(tamper="for name in testBinaries.take 3 do")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("partial iteration", result.stderr)

    def test_runtime_count_guard_is_required(self) -> None:
        self.write_runtime_fixture()
        source_path = self.root / "Test" / "LeanTests.lean"
        source = source_path.read_text(encoding="utf-8")
        source = source.replace(
            "  if passed.size != expectedTestCount then\n"
            "    IO.eprintln s!\"[lean_tests] COUNT MISMATCH: expected {expectedTestCount} test binaries but only {passed.size} ran; refusing to pass\"\n"
            "    return 1\n",
            "",
        )
        source_path.write_text(source, encoding="utf-8")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("passed.size differs", result.stderr)

    def test_source_change_is_the_single_roster_authority(self) -> None:
        self.write_fixture(
            source_children=("replacement_test",),
            needed_children=("replacement_test",),
        )
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("exactly matches all 1 children derived", result.stdout)

    def test_every_aggregate_lean_action_has_a_preceding_gate_call(self) -> None:
        action_marker = "leanprover/lean-action"
        gate_marker = "python3 scripts/lean_test_driver_gate.py"
        action_count = 0
        for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            job_starts = [
                match.start()
                for match in re.finditer(r"(?m)^  [A-Za-z0-9_-]+:\s*$", text)
            ]
            for index, start in enumerate(job_starts):
                end = job_starts[index + 1] if index + 1 < len(job_starts) else len(text)
                block = text[start:end]
                if not re.search(r"(?m)lake test(?:\s|$)", block):
                    continue
                action = block.find(action_marker)
                gate = block.find(gate_marker)
                test = block.find("lake test")
                self.assertNotEqual(action, -1, workflow)
                self.assertNotEqual(gate, -1, workflow)
                self.assertLess(gate, action, workflow)
                self.assertLess(action, test, workflow)
                action_count += 1
        self.assertEqual(action_count, 5, "review every aggregate Lean action")

    def test_every_lean_action_defers_tests_and_disables_lint(self) -> None:
        action_marker = "leanprover/lean-action"
        action_count = 0

        for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            actions = [match.start() for match in re.finditer(action_marker, text)]
            if not actions:
                continue

            action_count += len(actions)
            for action in actions:
                next_step = text.find("\n      - ", action)
                action_block = text[action : next_step if next_step != -1 else None]
                self.assertIn("test: false", action_block, workflow)
                self.assertIn("lint: false", action_block, workflow)

        # This count is a tripwire, not a fact to be kept in sync: it goes red
        # whenever a call site is added or removed, and the only way to clear
        # it is to review every site and restate the roster below. Bumping the
        # number without doing that review defeats the whole control.
        #
        # Raised 9 -> 11 by the pyyamlpop lane, 2026-08-08, after reviewing all
        # eleven sites individually. Two were new since the roster was last
        # restated, and one of the two was itself a defect:
        #   1  ci.yml:build:control_04
        #   2  ci.yml:rust-conformance-lean:control_06
        #   3  ci.yml:rust-conformance:control_06
        #   4  g2-mutation-ablation.yml:g2-mutation-ablation:control_06  NEW
        #      -- landed at df50f48 with no preceding gate call; the gate call
        #      was added, it did not already exist.
        #   5  golden-path.yml:lean-aggregate:control_05
        #   6  golden-path.yml:deterministic-shell:control_05
        #   7  public-export.yml:export:control_04
        #   8  public-export.yml:clean-source-build:control_02  NEW to this
        #      roster -- the previous comment counted public-export.yml once
        #      when it already had two sites, and this one had no preceding
        #      gate call either. Also fixed, not accommodated.
        #   9  release.yml:build:control_04
        #  10  security.yml:fuzz-hostile-ingress-lean:control_04
        #  11  security.yml:fuzz-hostile-ingress:control_04
        # All eleven pass test: false and lint: false, and all eleven now have
        # a preceding scripts/lean_test_driver_gate.py call.
        #
        # Lowered 11 -> 10 by this lane, 2026-08-08. Exactly one site leaves:
        # entry 2, ci.yml:rust-conformance-lean:control_06, because roadmap 8y
        # item 6 deletes that whole job as a same-commit duplicate of the
        # aggregate already run by ci.yml:build. Nothing is added, and the
        # remaining ten are unchanged, still gate-preceded, still test: false
        # and lint: false:
        #   1  ci.yml:build:control_04
        #   2  ci.yml:rust-conformance:control_06
        #   3  g2-mutation-ablation.yml:g2-mutation-ablation:control_06
        #   4  golden-path.yml:lean-aggregate:control_05
        #   5  golden-path.yml:deterministic-shell:control_05
        #   6  public-export.yml:export:control_04
        #   7  public-export.yml:clean-source-build:control_02
        #   8  release.yml:build:control_04
        #   9  security.yml:fuzz-hostile-ingress-lean:control_04
        #  10  security.yml:fuzz-hostile-ingress:control_04
        self.assertEqual(action_count, 10, "review every lean-action call site")

    def test_every_aggregate_test_has_a_native_prerequisite(self) -> None:
        """Each lake test must follow a native build in the same job.

        Downstream capacity-split jobs may reinstall lean-action without an
        aggregate lake test; those sites do not need a native build here.
        """
        native_build = re.compile(
            r"bash \.lake/packages/mcp-seal/c/build\.sh",
        )
        explicit_test = re.compile(
            r"(?:python3 scripts/ci_disk_telemetry\.py \S+ -- )?lake test(?:\s+2>&1\s+\|\s+tee\s+\S+)?\s*$",
            re.MULTILINE,
        )
        test_count = 0

        for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            # Split into job blocks: lines starting with exactly two spaces + name + colon
            job_starts = [
                match.start()
                for match in re.finditer(r"(?m)^  [A-Za-z0-9_-]+:\s*$", text)
            ]
            for index, start in enumerate(job_starts):
                end = job_starts[index + 1] if index + 1 < len(job_starts) else len(text)
                block = text[start:end]
                builds = [match.start() for match in native_build.finditer(block)]
                for test in explicit_test.finditer(block):
                    test_count += 1
                    self.assertTrue(
                        any(build < test.start() for build in builds),
                        f"{workflow}: lake test without preceding native build in job",
                    )

        self.assertEqual(test_count, 5, "review every aggregate lake test call site")

    def test_split_aggregate_jobs_are_required_predecessors(self) -> None:
        expected = (
            ("golden-path.yml", "lean-aggregate", "deterministic-shell"),
            ("security.yml", "fuzz-hostile-ingress-lean", "fuzz-hostile-ingress"),
        )
        for filename, lean_job, downstream_job in expected:
            path = ROOT / ".github" / "workflows" / filename
            text = path.read_text(encoding="utf-8")
            self.assertRegex(
                text,
                rf"(?m)^  {re.escape(downstream_job)}:\n"
                rf"    needs: {re.escape(lean_job)}\n",
            )
            lean_start = text.index(f"  {lean_job}:\n")
            downstream_start = text.index(f"  {downstream_job}:\n")
            lean_block = text[lean_start:downstream_start]
            self.assertIn("bash .lake/packages/mcp-seal/c/build.sh", lean_block)
            self.assertRegex(lean_block, r"(?m)-- lake test$")
            self.assertIn("SEAL_CONTROL_STEPS: ${{ toJSON(steps) }}", lean_block)
            self.assertIn(
                "run: python3 scripts/ci_control_aggregate.py", lean_block
            )


if __name__ == "__main__":
    unittest.main()
