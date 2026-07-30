#!/usr/bin/env python3
"""Structural guards for exhaustive CI step reporting."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ROOT / ".github/workflows/ci.yml",
    ROOT / ".github/workflows/security.yml",
    ROOT / ".github/workflows/golden-path.yml",
    ROOT / ".github/workflows/public-export.yml",
    ROOT / ".github/workflows/release.yml",
)
AGGREGATE_NAME = "Require every isolated CI step to pass"


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
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.name):
                jobs = job_step_blocks(workflow)
                self.assertTrue(jobs, f"no jobs parsed from {workflow}")
                for job, steps in jobs.items():
                    with self.subTest(workflow=workflow.name, job=job):
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
        expected = {
            "ci.yml": (
                'run: test -n "$SEAL_CI_READ_TOKEN"',
            ),
            "security.yml": (
                'run: test -n "$SEAL_CI_READ_TOKEN"',
            ),
            "golden-path.yml": (
                'test -n "$SEAL_CI_READ_TOKEN" || {',
                "exit 1",
            ),
            "public-export.yml": (
                'run: test -n "$SEAL_CI_READ_TOKEN"',
            ),
            "release.yml": (
                'test -n "$SEAL_CI_READ_TOKEN"',
            ),
        }
        for workflow in WORKFLOWS:
            text = workflow.read_text(encoding="utf-8")
            for required in expected[workflow.name]:
                with self.subTest(workflow=workflow.name, required=required):
                    self.assertIn(required, text)

    def test_release_build_reports_after_fleet_failure_but_publish_stays_gated(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertRegex(
            workflow,
            r"(?m)^  build:\n    if: \$\{\{ !cancelled\(\) \}\}\n    needs: fleet-gate$",
        )
        self.assertRegex(
            workflow,
            r"(?m)^  publish:\n    needs:\n      - fleet-gate\n      - build$",
        )


if __name__ == "__main__":
    unittest.main()
