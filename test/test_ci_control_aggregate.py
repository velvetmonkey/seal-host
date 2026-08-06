#!/usr/bin/env python3
"""Regression tests for fail-closed CI control aggregation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
AGGREGATE = ROOT / "scripts" / "ci_control_aggregate.py"
sys.path.insert(0, str(ROOT / "scripts"))
from ci_control_aggregate import Control, workflow_controls  # noqa: E402


def declared_ids(workflow: str = "ci.yml", job: str = "build") -> list[str]:
    return sorted(
        control.control_id
        for control in workflow_controls()
        if control.workflow == workflow and control.job == job
    )


def full_success_steps(
    workflow: str = "ci.yml", job: str = "build"
) -> dict[str, dict[str, str]]:
    return {
        control_id: {"outcome": "success", "conclusion": "success"}
        for control_id in declared_ids(workflow, job)
    }


class CiControlAggregateTests(unittest.TestCase):
    def run_aggregate(
        self,
        steps: object | None,
        *,
        allowlist: Path | None = None,
        workflow: str = "ci.yml",
        job: str = "build",
        clear_identity: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if clear_identity:
            env.pop("GITHUB_WORKFLOW_REF", None)
            env.pop("GITHUB_JOB", None)
        else:
            env["GITHUB_WORKFLOW_REF"] = (
                f"velvetmonkey/seal-host/.github/workflows/{workflow}@refs/heads/test"
            )
            env["GITHUB_JOB"] = job
        if steps is None:
            env.pop("SEAL_CONTROL_STEPS", None)
        else:
            env["SEAL_CONTROL_STEPS"] = json.dumps(steps)
        command = ["python3", str(AGGREGATE)]
        if allowlist is not None:
            command.extend(["--allowlist", str(allowlist)])
        return subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_build_job_declares_control_33(self) -> None:
        """Pin control_33 by name so deleting it from ci.yml breaks a test."""
        self.assertIn(
            Control("ci.yml", "build", "control_33"),
            workflow_controls(),
        )
        self.assertIn("control_33", declared_ids("ci.yml", "build"))

    def test_honest_full_payload_is_green(self) -> None:
        steps = full_success_steps()
        self.assertIn("control_33", steps)
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        count = len(steps)
        self.assertIn(f"{count} passed", result.stdout)
        self.assertIn(f"{count} reported", result.stdout)
        self.assertIn(f"{count} declared", result.stdout)

    def test_omitting_control_33_fails_completeness(self) -> None:
        steps = full_success_steps()
        del steps["control_33"]
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "declared CI control missing from measurement: ci.yml:build:control_33",
            result.stdout,
        )
        self.assertIn("1 missing", result.stdout)

    def test_single_control_payload_fails_completeness(self) -> None:
        result = self.run_aggregate(
            {"control_01": {"outcome": "success", "conclusion": "success"}}
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("declared CI control missing from measurement", result.stdout)
        self.assertIn("control_33", result.stdout)
        self.assertIn("missing", result.stdout)

    def test_attest_only_payload_fails_completeness(self) -> None:
        result = self.run_aggregate(
            {"attest": {"outcome": "success", "conclusion": "success"}}
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("declared CI control missing from measurement", result.stdout)
        self.assertIn("control_33", result.stdout)

    def test_partial_census_without_control_33_fails(self) -> None:
        """User repro shape: many successes, control_33 absent entirely."""
        steps = {
            name: {"outcome": "success", "conclusion": "success"}
            for name in declared_ids()
            if name != "control_33"
        }
        # Pad with synthetic extras so the reported count is large while the
        # declared control is still missing — the defect the probe hit.
        for index in range(100, 112):
            steps[f"control_{index}"] = {
                "outcome": "success",
                "conclusion": "success",
            }
        self.assertNotIn("control_33", steps)
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "declared CI control missing from measurement: ci.yml:build:control_33",
            result.stdout,
        )

    def test_missing_identity_fails_closed(self) -> None:
        result = self.run_aggregate(full_success_steps(), clear_identity=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "cannot identify workflow and job for control completeness",
            result.stdout,
        )

    def test_unknown_job_fails_closed(self) -> None:
        result = self.run_aggregate(
            {"control_01": {"outcome": "success", "conclusion": "success"}},
            job="does-not-exist",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "no controls declared for ci.yml:does-not-exist",
            result.stdout,
        )

    def test_failure_remains_red_after_continue_on_error(self) -> None:
        steps = full_success_steps()
        steps["control_01"] = {"outcome": "failure", "conclusion": "success"}
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("control_01", result.stdout)
        self.assertIn("1 failed", result.stdout)

    def test_semantic_attestation_id_is_aggregated(self) -> None:
        # attest is not declared on the build job; inject it as an extra
        # reported step so a failed attestation still reddens the aggregate.
        steps = full_success_steps()
        steps["attest"] = {"outcome": "failure", "conclusion": "success"}
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("attest", result.stdout)

    def test_missing_or_vacuous_results_fail_closed(self) -> None:
        for steps in (None, {}, {"setup": {"outcome": "success"}}):
            with self.subTest(steps=steps):
                result = self.run_aggregate(steps)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_skipped_control_off_allowlist_fails(self) -> None:
        steps = full_success_steps()
        steps["control_01"] = {"outcome": "skipped", "conclusion": "skipped"}
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("ci.yml:build:control_01", result.stdout)

    def test_skipped_control_on_allowlist_passes_with_successes(self) -> None:
        steps = full_success_steps()
        steps["control_03"] = {"outcome": "skipped", "conclusion": "skipped"}
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("allowed to skip: ci.yml:build:control_03", result.stdout)
        self.assertIn("1 skipped", result.stdout)
        self.assertIn(f"{len(steps) - 1} passed", result.stdout)

    def test_all_allowlisted_skips_with_zero_successes_fails(self) -> None:
        """Floor: zero successful observations is not a pass, even if skips are allowed."""
        job = "export-surface"
        ids = declared_ids("ci.yml", job)
        self.assertGreaterEqual(len(ids), 1)
        steps = {
            control_id: {"outcome": "skipped", "conclusion": "skipped"}
            for control_id in ids
        }
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            allowlist = Path(directory) / "allowlist.json"
            allowlist.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "controls": [
                            {
                                "workflow": "ci.yml",
                                "job": job,
                                "id": control_id,
                                "reason": "Test allowlist entry for all-skip floor.",
                            }
                            for control_id in ids
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_aggregate(steps, allowlist=allowlist, job=job)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("no successful control observations", result.stdout)
        self.assertIn("0 passed", result.stdout)

    def test_missing_allowlist_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            missing = Path(directory) / "missing.json"
            result = self.run_aggregate(full_success_steps(), allowlist=missing)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("skip allowlist is missing", result.stdout)

    def test_unparseable_allowlist_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            invalid = Path(directory) / "invalid.json"
            invalid.write_text("{not JSON\n", encoding="utf-8")
            result = self.run_aggregate(full_success_steps(), allowlist=invalid)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("skip allowlist is not valid JSON", result.stdout)

    def test_unknown_control_in_allowlist_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            unknown = Path(directory) / "unknown.json"
            unknown.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "controls": [
                            {
                                "workflow": "ci.yml",
                                "job": "build",
                                "id": "control_99",
                                "reason": "Deliberately unknown test control.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_aggregate(full_success_steps(), allowlist=unknown)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "allowlisted control does not exist in any workflow: "
            "ci.yml:build:control_99",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
