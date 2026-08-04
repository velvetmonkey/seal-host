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

JOB_NAME = r"[A-Za-z0-9_][A-Za-z0-9_.\-]*"

# `success()` is exactly GitHub's implicit status check, and `&& <anything>` can
# only narrow it, so both forms provably keep a failed or skipped predecessor
# from starting the dependent. Every other expression -- `always()`,
# `success() || failure()`, `!cancelled()`, `github.event_name != 'x'`, and any
# spelling nobody has thought of yet -- is undecidable here and fails the gate.
# Widen this only by proving the new form blocks on a non-success predecessor.
PROVABLY_GATED_IF = re.compile(r"success\(\)(\s*&&\s*\S.*)?", re.DOTALL)

# Edges that already let a failed predecessor start their dependent, both older
# than the aggregate split and owned elsewhere. They are named so that a NEW
# ungated edge anywhere in the repository is a failure instead of an unnoticed
# entry in this table. Shrink it; do not grow it without a reason on the line.
DECLARED_UNGATED_EDGES = {
    ("ci.yml", "release-evidence"): "if: ${{ always() }} — reports on reds",
    ("release.yml", "build"): "if: ${{ !cancelled() }} — builds past a failed gate",
}


class WorkflowParseError(Exception):
    """The workflow is outside the strict subset whose gating this gate decides."""


class UndecidableGate(Exception):
    """A job-level `if:` whose gating effect this gate cannot prove."""


class Job:
    """The job-level keys that decide whether a dependent starts."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.needs: list[str] = []
        self.if_expression: str | None = None
        self.continue_on_error = False


def _is_structural(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_needs(inline: str | None, block: list[str], where: str) -> list[str]:
    if inline is not None:
        value = inline.strip()
        if value.startswith("["):
            if not value.endswith("]"):
                raise WorkflowParseError(f"{where}: unterminated needs sequence")
            body = value[1:-1].strip()
            raw = [part for part in body.split(",")] if body else []
        else:
            raw = [value]
    else:
        raw = []
        for line in block:
            match = re.fullmatch(rf"      - ({JOB_NAME})\s*", line)
            if match is None:
                raise WorkflowParseError(f"{where}: unparseable needs entry {line!r}")
            raw.append(match.group(1))
    names = []
    for item in raw:
        name = item.strip().strip('"').strip("'")
        if not re.fullmatch(JOB_NAME, name):
            raise WorkflowParseError(f"{where}: unparseable needs entry {item!r}")
        names.append(name)
    if not names:
        raise WorkflowParseError(f"{where}: empty needs")
    return names


def _apply_job_key(
    job: Job, key: str, inline: str | None, block: list[str], where: str
) -> None:
    if key == "needs":
        job.needs = _parse_needs(inline, block, where)
    elif key == "if":
        if inline is None or inline.strip() in ("|", ">", "|-", ">-", "|+", ">+"):
            raise WorkflowParseError(f"{where}: `if:` is not a single-line scalar")
        job.if_expression = inline.strip()
    elif key == "continue-on-error":
        value = "" if inline is None else inline.strip()
        if value not in ("true", "false"):
            raise WorkflowParseError(
                f"{where}: continue-on-error must be literal true/false, got {value!r}"
            )
        job.continue_on_error = value == "true"


def parse_workflow_jobs(text: str) -> dict[str, Job]:
    """Read the job-level gating keys, refusing anything it cannot read exactly.

    Anything outside `jobs:` -> two-space job headers -> four-space job keys
    raises rather than being silently ignored, so an unreadable reshuffle of the
    workflow fails the gate instead of passing it vacuously.
    """
    if "\t" in text:
        raise WorkflowParseError("tab characters make indentation undecidable")
    lines = text.split("\n")
    index = 0
    while index < len(lines) and lines[index].rstrip() != "jobs:":
        index += 1
    if index == len(lines):
        raise WorkflowParseError("no top-level `jobs:` mapping")
    index += 1

    jobs: dict[str, Job] = {}
    current: Job | None = None
    while index < len(lines):
        line = lines[index]
        if not _is_structural(line):
            index += 1
            continue
        indent = _indent(line)
        where = f"line {index + 1}"
        if indent == 0:
            break
        if indent == 2:
            match = re.fullmatch(rf"  ({JOB_NAME}):\s*", line)
            if match is None:
                raise WorkflowParseError(f"{where}: unreadable job header {line!r}")
            name = match.group(1)
            if name in jobs:
                raise WorkflowParseError(f"{where}: duplicate job {name!r}")
            current = Job(name)
            jobs[name] = current
            index += 1
            continue
        if indent == 4 and current is not None:
            match = re.fullmatch(r"    ([A-Za-z0-9_\-]+):(?:[ ]+(.*?))?\s*", line)
            if match is None:
                raise WorkflowParseError(f"{where}: unreadable job key {line!r}")
            key, inline = match.group(1), match.group(2)
            index += 1
            block: list[str] = []
            while index < len(lines):
                following = lines[index]
                if not _is_structural(following):
                    index += 1
                    continue
                if _indent(following) <= 4:
                    break
                block.append(following)
                index += 1
            _apply_job_key(current, key, inline, block, where)
            continue
        raise WorkflowParseError(f"{where}: unreadable indentation {line!r}")
    if not jobs:
        raise WorkflowParseError("no jobs parsed")
    return jobs


def reported_predecessor_result(job: Job, actual: str) -> str:
    """What a predecessor's real outcome looks like to its dependents.

    A job-level `continue-on-error` hands a failed job to its dependents as a
    success. Modelling it that way can only make this gate stricter.
    """
    if job.continue_on_error and actual == "failure":
        return "success"
    return actual


def dependent_starts(job: Job, predecessor_results: dict[str, str]) -> bool:
    """Whether `job` starts, given what its predecessors reported.

    Raises UndecidableGate when the job carries an `if:` outside the provably
    gated subset, so an unrecognised expression is a failure and never a pass.
    """
    implicit_gate = all(result == "success" for result in predecessor_results.values())
    if job.if_expression is None:
        return implicit_gate
    expression = job.if_expression.strip()
    if expression.startswith("${{"):
        if not expression.endswith("}}"):
            raise UndecidableGate(job.if_expression)
        expression = expression[3:-2].strip()
    if PROVABLY_GATED_IF.fullmatch(expression) is None:
        raise UndecidableGate(job.if_expression)
    # Sound in the blocking direction, which is the only one asserted on: a
    # false implicit gate makes `success() && ...` false whatever `...` is.
    return implicit_gate


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

        self.assertEqual(action_count, 8, "review every lean-action call site")
        self.assertEqual(test_count, 6, "review every aggregate lake test call site")

    def test_every_needs_edge_is_gated_or_declared_ungated(self) -> None:
        for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            try:
                jobs = parse_workflow_jobs(path.read_text(encoding="utf-8"))
            except WorkflowParseError as error:
                self.fail(f"{path.name}: {error}")
            for name, job in jobs.items():
                if not job.needs:
                    continue
                with self.subTest(workflow=path.name, job=name):
                    results = {}
                    for predecessor in job.needs:
                        self.assertIn(predecessor, jobs, f"{path.name}: {name} needs it")
                        results[predecessor] = reported_predecessor_result(
                            jobs[predecessor], "failure"
                        )
                    try:
                        gated = not dependent_starts(job, results)
                    except UndecidableGate:
                        gated = False
                    declared = DECLARED_UNGATED_EDGES.get((path.name, name))
                    if declared is None:
                        self.assertTrue(
                            gated,
                            f"{path.name}: {name} can start on a failed predecessor "
                            f"{job.needs}; gate it or declare it",
                        )
                    else:
                        self.assertFalse(
                            gated,
                            f"{path.name}: {name} is gated now ({declared}); drop it "
                            f"from DECLARED_UNGATED_EDGES",
                        )

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
                try:
                    jobs = parse_workflow_jobs(workflow)
                except WorkflowParseError as error:
                    self.fail(f"{filename}: {error}")
                self.assertIn(lean_job, jobs, filename)
                self.assertIn(downstream_job, jobs, filename)
                upstream, dependent = jobs[lean_job], jobs[downstream_job]

                self.assertIn(
                    lean_job,
                    dependent.needs,
                    f"{filename}: {downstream_job} does not depend on {lean_job}",
                )
                self.assertIsNone(
                    upstream.if_expression,
                    f"{filename}: {lean_job} must be unconditional; a conditional "
                    f"predecessor can skip and take the whole edge with it",
                )
                self.assertFalse(
                    upstream.continue_on_error,
                    f"{filename}: {lean_job} must not carry job-level "
                    f"continue-on-error; it would report failures as success",
                )
                self.assertFalse(
                    dependent.continue_on_error,
                    f"{filename}: {downstream_job} must not carry job-level "
                    f"continue-on-error",
                )

                # The property, evaluated rather than pattern-matched: whatever
                # the predecessor does short of succeeding, the dependent does
                # not start, so it cannot report success.
                for outcome in ("failure", "skipped", "cancelled"):
                    with self.subTest(predecessor=outcome):
                        reported = reported_predecessor_result(upstream, outcome)
                        results = {
                            name: reported if name == lean_job else "success"
                            for name in dependent.needs
                        }
                        try:
                            starts = dependent_starts(dependent, results)
                        except UndecidableGate as error:
                            self.fail(
                                f"{filename}: {downstream_job} carries "
                                f"`if: {error}`, whose gating effect is not "
                                f"provable; {lean_job} {outcome} may not stop it"
                            )
                        self.assertFalse(
                            starts,
                            f"{filename}: {downstream_job} still starts when "
                            f"{lean_job} is {outcome}",
                        )

                lean_start = workflow.index(f"  {lean_job}:\n")
                downstream_start = workflow.index(f"  {downstream_job}:\n")
                lean_block = workflow[lean_start:downstream_start]
                self.assertIn("bash .lake/packages/mcp-seal/c/build.sh", lean_block)
                self.assertRegex(lean_block, r"(?m)-- lake test$")
                self.assertIn("SEAL_CONTROL_STEPS: ${{ toJSON(steps) }}", lean_block)
                self.assertIn("run: python3 scripts/ci_control_aggregate.py", lean_block)


class DependentGatingModelTests(unittest.TestCase):
    """The gating model itself must fail closed on anything it cannot decide."""

    def workflow(self, *, upstream: str = "", dependent: str) -> dict[str, Job]:
        return parse_workflow_jobs(
            "on:\n"
            "  push:\n"
            "jobs:\n"
            "  lean-aggregate:\n"
            "    runs-on: ubuntu-latest\n"
            f"{upstream}"
            "    steps:\n"
            "      - id: control_01\n"
            "        run: echo one\n"
            "  deterministic-shell:\n"
            f"{dependent}"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - id: control_01\n"
            "        run: echo two\n"
        )

    def blocked_on_every_bad_outcome(self, jobs: dict[str, Job]) -> None:
        upstream, dependent = jobs["lean-aggregate"], jobs["deterministic-shell"]
        for outcome in ("failure", "skipped", "cancelled"):
            reported = reported_predecessor_result(upstream, outcome)
            results = {name: reported for name in dependent.needs}
            self.assertFalse(dependent_starts(dependent, results), outcome)

    def test_plain_needs_blocks_every_bad_outcome(self) -> None:
        jobs = self.workflow(dependent="    needs: lean-aggregate\n")
        self.blocked_on_every_bad_outcome(jobs)

    def test_sequence_and_flow_needs_are_read_the_same(self) -> None:
        flow = self.workflow(dependent="    needs: [lean-aggregate]\n")
        block = self.workflow(
            dependent="    needs:\n      - lean-aggregate\n"
        )
        self.assertEqual(flow["deterministic-shell"].needs, ["lean-aggregate"])
        self.assertEqual(block["deterministic-shell"].needs, ["lean-aggregate"])
        self.blocked_on_every_bad_outcome(flow)
        self.blocked_on_every_bad_outcome(block)

    def test_success_conjunction_still_blocks(self) -> None:
        jobs = self.workflow(
            dependent="    needs: lean-aggregate\n"
            "    if: ${{ success() && github.event_name == 'push' }}\n"
        )
        self.blocked_on_every_bad_outcome(jobs)

    def test_neutralising_conditions_are_undecidable(self) -> None:
        for expression in (
            "${{ always() }}",
            "always()",
            "${{ success() || failure() }}",
            "${{ !cancelled() }}",
            "${{ github.event_name != 'nonexistent' }}",
            "${{ failure() || success() || cancelled() }}",
            "${{ some.future.spelling.nobody.enumerated }}",
        ):
            with self.subTest(expression=expression):
                jobs = self.workflow(
                    dependent=f"    needs: lean-aggregate\n    if: {expression}\n"
                )
                with self.assertRaises(UndecidableGate):
                    dependent_starts(
                        jobs["deterministic-shell"], {"lean-aggregate": "failure"}
                    )

    def test_upstream_continue_on_error_reports_failure_as_success(self) -> None:
        jobs = self.workflow(
            upstream="    continue-on-error: true\n",
            dependent="    needs: lean-aggregate\n",
        )
        upstream, dependent = jobs["lean-aggregate"], jobs["deterministic-shell"]
        self.assertTrue(upstream.continue_on_error)
        self.assertTrue(
            dependent_starts(
                dependent,
                {"lean-aggregate": reported_predecessor_result(upstream, "failure")},
            )
        )

    def test_unreadable_workflow_shapes_are_refused(self) -> None:
        for text in (
            "jobs:\n  deterministic-shell: {needs: lean-aggregate}\n",
            "jobs:\n  deterministic-shell:\n    needs: [lean-aggregate\n",
            "jobs:\n  deterministic-shell:\n\tneeds: lean-aggregate\n",
            "jobs:\n  deterministic-shell:\n    continue-on-error: ${{ inputs.soft }}\n",
            "jobs:\n  deterministic-shell:\n    if: >-\n      always()\n",
            "on:\n  push:\n",
        ):
            with self.subTest(text=text):
                with self.assertRaises(WorkflowParseError):
                    parse_workflow_jobs(text)


if __name__ == "__main__":
    unittest.main()
