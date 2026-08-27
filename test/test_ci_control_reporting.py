#!/usr/bin/env python3
"""Structural guards for exhaustive CI step reporting."""

from __future__ import annotations

from pathlib import Path
import re
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github/workflows"
AGGREGATE_NAME = "Require every isolated CI step to pass"
# GitHub runs both spellings. Discovering only *.yml lets a real workflow
# sit outside this control by naming itself .yaml.
WORKFLOW_SUFFIXES = (".yml", ".yaml")

# This is deliberately a mapping over every workflow discovered on disk, not a
# hand-picked set of the files that happened to need private access when this
# test was first written.  An unknown workflow is a finding: someone must
# decide whether it needs a fail-closed private-access route, rather than it
# quietly sitting outside this control.
PRIVATE_ACCESS_EXPECTATIONS = {
    "acceptance.yml": (
        'run: test -n "$SEAL_CI_READ_TOKEN"',
        'name: Configure private fleet read access',
    ),
    "ci.yml": (
        'run: test -n "$SEAL_CI_READ_TOKEN"',
    ),
    "g2-mutation-ablation.yml": (
        "SEAL_CI_READ_TOKEN is not configured",
        'name: Configure private dependency auth',
    ),
    "kernel-reproduce.yml": (
        'run: test -n "$SEAL_CI_READ_TOKEN"',
    ),
    "golden-path.yml": (
        'test -n "$SEAL_CI_READ_TOKEN" || {',
        "exit 1",
    ),
    "public-export.yml": (),
    "release-docs.yml": (),
    "release.yml": (
        'test -n "$SEAL_CI_READ_TOKEN"',
    ),
    "security.yml": (
        'run: test -n "$SEAL_CI_READ_TOKEN"',
    ),
    "claims-family-drift.yml": (),
}

# Every discovered workflow is deliberately classified by the way a failed
# step reaches a failed workflow.  The two fail-fast workflows do not use the
# isolated-control aggregate: `acceptance.yml` is reusable, so GitHub reports
# the caller's step identity there, and `release-docs.yml` has no tolerated
# step failures to aggregate.  A new file has no mode until it is reviewed.
WORKFLOW_CONTROL_MODES = {
    "acceptance.yml": "fail-fast",
    "claims-family-drift.yml": "fail-fast",
    "ci.yml": "aggregate",
    "g2-mutation-ablation.yml": "aggregate",
    "golden-path.yml": "aggregate",
    "kernel-reproduce.yml": "fail-fast",
    "public-export.yml": "aggregate",
    "release-docs.yml": "fail-fast",
    "release.yml": "aggregate",
    "security.yml": "aggregate",
}


def workflow_paths(workflow_dir: Path = WORKFLOW_DIR) -> tuple[Path, ...]:
    """Discover the workflow population; additions require explicit review."""
    return tuple(
        sorted(
            path
            for suffix in WORKFLOW_SUFFIXES
            for path in workflow_dir.glob(f"*{suffix}")
        )
    )


def private_access_failures(workflows: tuple[Path, ...]) -> list[str]:
    """Return every unclassified workflow or missing private-access fact."""
    failures: list[str] = []
    for workflow in workflows:
        required = PRIVATE_ACCESS_EXPECTATIONS.get(workflow.name)
        if required is None:
            failures.append(
                f"workflow has no private-access classification: {workflow.name}"
            )
            continue
        text = workflow.read_text(encoding="utf-8")
        for needle in required:
            if needle not in text:
                failures.append(
                    f"{workflow.name} missing private-access requirement: {needle}"
                )
    return failures


def job_step_blocks(path: Path) -> dict[str, list[list[str]]]:
    """Return the six-space YAML list items in each job's steps block."""
    jobs: dict[str, list[list[str]]] = {}
    current_job: str | None = None
    in_steps = False
    current_step: list[str] | None = None

    for line in path.read_text(encoding="utf-8").splitlines():
        job = re.fullmatch(r"  ([a-z0-9-]+):", line)
        if job:
            if current_step is not None and current_job is not None:
                jobs[current_job].append(current_step)
                current_step = None
            current_job = job.group(1)
            jobs[current_job] = []
            in_steps = False
            continue
        if current_job is not None and line == "    steps:":
            in_steps = True
            continue
        if not in_steps:
            continue
        if line.startswith("      - "):
            if current_step is not None:
                jobs[current_job].append(current_step)
            current_step = [line]
        elif current_step is not None:
            current_step.append(line)

    if current_step is not None and current_job is not None:
        jobs[current_job].append(current_step)
    return {job: steps for job, steps in jobs.items() if steps}


class CiControlReportingTests(unittest.TestCase):
    def test_every_job_isolates_all_steps_then_aggregates(self) -> None:
        workflows = workflow_paths()
        self.assertEqual(
            {workflow.name for workflow in workflows},
            set(WORKFLOW_CONTROL_MODES),
            "control modes must name the discovered workflow population",
        )
        for workflow in workflows:
            with self.subTest(workflow=workflow.name):
                jobs = job_step_blocks(workflow)
                self.assertTrue(jobs, f"no jobs parsed from {workflow}")
                mode = WORKFLOW_CONTROL_MODES[workflow.name]
                for job, steps in jobs.items():
                    with self.subTest(workflow=workflow.name, job=job):
                        if mode == "fail-fast":
                            step_text = "\n".join("\n".join(step) for step in steps)
                            self.assertNotIn("continue-on-error", step_text)
                            continue

                        if workflow.name == "release.yml" and job == "ci-acceptance":
                            gate = "\n".join("\n".join(step) for step in steps)
                            self.assertIn("run: python3 scripts/tag_release_gate.py", gate)
                            self.assertNotIn("continue-on-error", gate)
                            continue

                        reporting_steps = steps
                        if workflow.name == "release.yml" and job == "publish":
                            publication = "\n".join(steps[-1])
                            self.assertIn("name: Publish immutable release assets", publication)
                            self.assertNotIn("continue-on-error", publication)
                            reporting_steps = steps[:-1]

                        aggregate = "\n".join(reporting_steps[-1])
                        self.assertIn(f"name: {AGGREGATE_NAME}", aggregate)
                        self.assertIn("if: ${{ always() }}", aggregate)
                        self.assertIn("SEAL_CONTROL_STEPS: ${{ toJSON(steps) }}", aggregate)
                        self.assertIn("run: python3 scripts/ci_control_aggregate.py", aggregate)
                        self.assertNotIn("continue-on-error", aggregate)

                        ids: list[str] = []
                        for step in reporting_steps[:-1]:
                            text = "\n".join(step)
                            match = re.search(
                                r"^\s*- id: (control_[0-9]+|attest)$", text, re.MULTILINE
                            )
                            self.assertIsNotNone(match, text)
                            ids.append(match.group(1))
                            self.assertIn("continue-on-error: true", text)
                        self.assertEqual(len(ids), len(set(ids)), ids)

    def test_private_access_gates_still_fail_closed(self) -> None:
        workflows = workflow_paths()
        self.assertEqual(
            {workflow.name for workflow in workflows},
            set(PRIVATE_ACCESS_EXPECTATIONS),
            "private-access classifications must name the discovered workflow population",
        )
        self.assertEqual(private_access_failures(workflows), [])

    def test_unclassified_workflow_fails_closed(self) -> None:
        """Negative control: a new workflow cannot evade private-access review."""
        with tempfile.TemporaryDirectory() as temporary:
            workflow = Path(temporary) / "new-unclassified.yml"
            workflow.write_text("name: new control\non: workflow_dispatch\n", encoding="utf-8")
            failures = private_access_failures((workflow,))
        self.assertEqual(
            failures,
            ["workflow has no private-access classification: new-unclassified.yml"],
        )

    def test_yaml_extension_is_discovered_and_fails_closed(self) -> None:
        """GitHub accepts .yaml; that spelling must enter the population."""
        with tempfile.TemporaryDirectory() as temporary:
            workflow_dir = Path(temporary)
            workflow = workflow_dir / "new-unclassified.yaml"
            workflow.write_text(
                "name: new control\non: workflow_dispatch\n", encoding="utf-8"
            )
            discovered = workflow_paths(workflow_dir)
            self.assertEqual(
                [path.name for path in discovered],
                ["new-unclassified.yaml"],
                "discovery must include GitHub's .yaml spelling",
            )
            self.assertEqual(
                private_access_failures(discovered),
                [
                    "workflow has no private-access classification: "
                    "new-unclassified.yaml"
                ],
            )

    def test_release_build_reports_after_fleet_failure_but_publish_stays_gated(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertRegex(
            workflow,
            r"(?m)^  build:\n    if: \$\{\{ !cancelled\(\) \}\}\n"
            r"    needs:\n      - ci-acceptance\n      - fleet-gate$",
        )
        self.assertRegex(
            workflow,
            r"(?m)^  publish:\n    needs:\n      - ci-acceptance\n"
            r"      - fleet-gate\n      - build$",
        )


if __name__ == "__main__":
    unittest.main()
