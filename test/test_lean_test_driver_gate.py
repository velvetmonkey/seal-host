#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Behavioral tests for the Lean aggregate-driver wiring gate."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
from typing import Any
import unittest

try:
    import yaml
except ModuleNotFoundError:
    yaml = None


SOURCE_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("LEAN_WORKFLOW_ROOT", SOURCE_ROOT)).resolve()
GATE = SOURCE_ROOT / "scripts" / "lean_test_driver_gate.py"


@dataclass(frozen=True)
class Workflow:
    path: Path
    text: str
    document: dict[str, Any]


def load_workflows(root: Path = ROOT) -> list[Workflow]:
    workflow_dir = root / ".github" / "workflows"
    paths = sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))
    if not paths:
        raise RuntimeError(f"no workflow files found in {workflow_dir}")

    workflows = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if yaml is not None:
            try:
                document = yaml.safe_load(text)
            except yaml.YAMLError as error:
                raise RuntimeError(f"cannot parse workflow {path}: {error}") from error
        else:
            try:
                parsed = subprocess.run(
                    ["yq", "-o=json", ".", str(path)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
            except OSError as error:
                raise RuntimeError(
                    f"cannot parse workflow {path}: no YAML parser is available"
                ) from error
            if parsed.returncode != 0:
                raise RuntimeError(
                    f"cannot parse workflow {path}: {parsed.stderr.strip()}"
                )
            try:
                document = json.loads(parsed.stdout)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    f"cannot parse workflow {path}: yq returned invalid JSON"
                ) from error
        if not isinstance(document, dict) or not isinstance(document.get("jobs"), dict):
            raise RuntimeError(f"workflow {path} has no jobs mapping")
        workflows.append(Workflow(path=path, text=text, document=document))
    return workflows


def lean_action_sites(
    workflows: list[Workflow],
) -> list[tuple[Workflow, str, int, dict[str, Any]]]:
    sites = []
    for workflow in workflows:
        for job_name, job in workflow.document["jobs"].items():
            if not isinstance(job, dict):
                raise RuntimeError(
                    f"workflow {workflow.path} job {job_name} is not a mapping"
                )
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                raise RuntimeError(
                    f"workflow {workflow.path} job {job_name} steps is not a sequence"
                )
            for step_index, step in enumerate(steps):
                if not isinstance(step, dict):
                    raise RuntimeError(
                        f"workflow {workflow.path} job {job_name} has a non-mapping step"
                    )
                uses = step.get("uses")
                if (
                    isinstance(uses, str)
                    and uses.split("@", maxsplit=1)[0] == "leanprover/lean-action"
                ):
                    sites.append((workflow, str(job_name), step_index, step))
    if not sites:
        raise RuntimeError("zero lean-action call sites found in workflow sources")
    return sites


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

    def test_workflow_discovery_and_parsing_fail_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "no workflow files found"):
            load_workflows(self.root)

        workflow_dir = self.root / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)
        (workflow_dir / "broken.yml").write_text(
            "jobs: [unterminated\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "cannot parse workflow"):
            load_workflows(self.root)

    def test_zero_lean_action_sites_fails_closed(self) -> None:
        workflow_dir = self.root / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)
        (workflow_dir / "empty.yml").write_text(
            "jobs:\n  ordinary:\n    steps:\n      - run: true\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "zero lean-action call sites"):
            lean_action_sites(load_workflows(self.root))

    def test_every_lean_action_disables_implicit_tests(self) -> None:
        sites = lean_action_sites(load_workflows())
        self.assertEqual(len(sites), 8, "review every lean-action call site")
        for workflow, job_name, step_index, step in sites:
            with self.subTest(
                workflow=workflow.path.name,
                job=job_name,
                step=step_index,
            ):
                inputs = step.get("with")
                self.assertIsInstance(inputs, dict)
                self.assertIs(
                    inputs.get("test") if isinstance(inputs, dict) else None,
                    False,
                    "every lean-action call site must set test: false",
                )

    def test_every_aggregate_test_has_a_native_prerequisite(self) -> None:
        native_build = re.compile(
            r"^\s*bash \.lake/packages/mcp-seal/c/build\.sh\s*$",
            re.MULTILINE,
        )
        explicit_test = re.compile(
            r"^\s*(?:python3 scripts/ci_disk_telemetry\.py \S+ -- )?lake test\s*$",
            re.MULTILINE,
        )
        test_count = 0

        for workflow in load_workflows():
            for job_name, job in workflow.document["jobs"].items():
                if not isinstance(job, dict):
                    raise RuntimeError(
                        f"workflow {workflow.path} job {job_name} is not a mapping"
                    )
                steps = job.get("steps", [])
                if not isinstance(steps, list):
                    raise RuntimeError(
                        f"workflow {workflow.path} job {job_name} steps is not a sequence"
                    )
                build_steps = []
                for step_index, step in enumerate(steps):
                    if not isinstance(step, dict):
                        raise RuntimeError(
                            f"workflow {workflow.path} job {job_name} has a non-mapping step"
                        )
                    command = step.get("run")
                    if not isinstance(command, str):
                        continue
                    if native_build.search(command):
                        build_steps.append(step_index)
                    if not explicit_test.search(command):
                        continue
                    test_count += 1
                    with self.subTest(workflow=workflow.path.name, job=job_name):
                        self.assertTrue(
                            any(build < step_index for build in build_steps),
                            "every aggregate lake test must follow its native build "
                            "in the same job",
                        )

        self.assertEqual(test_count, 6, "review every aggregate lake test call site")

    def test_split_aggregate_jobs_are_required_predecessors(self) -> None:
        expected = (
            ("golden-path.yml", "lean-aggregate", "deterministic-shell"),
            ("security.yml", "fuzz-hostile-ingress-lean", "fuzz-hostile-ingress"),
        )
        for filename, lean_job, downstream_job in expected:
            path = ROOT / ".github" / "workflows" / filename
            loaded = next(item for item in load_workflows() if item.path == path)
            workflow = loaded.text
            document = loaded.document
            downstream = document["jobs"][downstream_job]
            with self.subTest(workflow=filename):
                self.assertEqual(downstream.get("needs"), lean_job)
                self.assertNotIn(
                    "if", downstream, "downstream job must not be conditional"
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
