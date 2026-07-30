#!/usr/bin/env python3
"""Regression tests for fail-closed CI control aggregation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
AGGREGATE = ROOT / "scripts" / "ci_control_aggregate.py"


class CiControlAggregateTests(unittest.TestCase):
    def run_aggregate(self, steps: object | None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if steps is None:
            env.pop("SEAL_CONTROL_STEPS", None)
        else:
            env["SEAL_CONTROL_STEPS"] = json.dumps(steps)
        return subprocess.run(
            ["python3", str(AGGREGATE)],
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

    def test_skipped_conditional_is_reported_but_not_invented_as_failure(self) -> None:
        result = self.run_aggregate(
            {
                "control_01": {"outcome": "success", "conclusion": "success"},
                "control_02": {"outcome": "skipped", "conclusion": "skipped"},
            }
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("1 skipped", result.stdout)


if __name__ == "__main__":
    unittest.main()
