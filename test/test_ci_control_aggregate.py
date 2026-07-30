#!/usr/bin/env python3
"""Regression tests for fail-closed CI control aggregation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
AGGREGATE = ROOT / "scripts" / "ci_control_aggregate.py"


class CiControlAggregateTests(unittest.TestCase):
    def run_aggregate(
        self,
        steps: object | None,
        *,
        allowlist: Path | None = None,
        workflow: str = "ci.yml",
        job: str = "build",
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
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

    def test_all_success_is_green(self) -> None:
        result = self.run_aggregate(
            {
                "control_01": {"outcome": "success", "conclusion": "success"},
                "control_02": {"outcome": "success", "conclusion": "success"},
            }
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("2 passed", result.stdout)

    def test_failure_remains_red_after_continue_on_error(self) -> None:
        result = self.run_aggregate(
            {
                "control_01": {"outcome": "failure", "conclusion": "success"},
                "control_02": {"outcome": "success", "conclusion": "success"},
            }
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("control_01", result.stdout)
        self.assertIn("1 failed", result.stdout)

    def test_semantic_attestation_id_is_aggregated(self) -> None:
        result = self.run_aggregate(
            {
                "control_15": {"outcome": "success", "conclusion": "success"},
                "attest": {"outcome": "failure", "conclusion": "success"},
                "control_17": {"outcome": "success", "conclusion": "success"},
            }
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("attest", result.stdout)

    def test_missing_or_vacuous_results_fail_closed(self) -> None:
        for steps in (None, {}, {"setup": {"outcome": "success"}}):
            with self.subTest(steps=steps):
                result = self.run_aggregate(steps)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_skipped_control_off_allowlist_fails(self) -> None:
        result = self.run_aggregate(
            {
                "control_01": {"outcome": "skipped", "conclusion": "skipped"},
            }
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("ci.yml:build:control_01", result.stdout)

    def test_skipped_control_on_allowlist_passes(self) -> None:
        result = self.run_aggregate(
            {
                "control_03": {"outcome": "skipped", "conclusion": "skipped"},
            }
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("allowed to skip: ci.yml:build:control_03", result.stdout)
        self.assertIn("1 skipped", result.stdout)

    def test_missing_allowlist_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            missing = Path(directory) / "missing.json"
            result = self.run_aggregate(
                {"control_01": {"outcome": "success"}}, allowlist=missing
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("skip allowlist is missing", result.stdout)

    def test_unparseable_allowlist_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            invalid = Path(directory) / "invalid.json"
            invalid.write_text("{not JSON\n", encoding="utf-8")
            result = self.run_aggregate(
                {"control_01": {"outcome": "success"}}, allowlist=invalid
            )
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
            result = self.run_aggregate(
                {"control_01": {"outcome": "success"}}, allowlist=unknown
            )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "allowlisted control does not exist in any workflow: "
            "ci.yml:build:control_99",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
