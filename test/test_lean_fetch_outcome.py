#!/usr/bin/env python3
"""Regression coverage for Lake package-fetch infrastructure reporting."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts" / "lean_fetch_outcome.py"


class LeanFetchOutcomeTest(unittest.TestCase):
    def run_adapter(self, command: str) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.NamedTemporaryFile() as output:
            environment = os.environ | {"GITHUB_OUTPUT": output.name}
            result = subprocess.run(
                ["python3", str(ADAPTER), "--", "bash", "-c", command],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
            )
            output.seek(0)
            return result, output.read().decode("utf-8")

    def test_clone_outage_is_unrunnable_with_its_named_source(self) -> None:
        result, outputs = self.run_adapter(
            "echo 'info: aesop: cloning https://example.invalid/aesop.git'; "
            "echo 'error: external command git exited with code 128'; exit 128"
        )
        self.assertEqual(result.returncode, 128, result.stdout + result.stderr)
        self.assertIn("Lean dependency fetch could not run from https://example.invalid/aesop.git", result.stdout)
        self.assertIn("unrunnable=true", outputs)
        self.assertIn("unrunnable-reason=Lean dependency fetch could not run from https://example.invalid/aesop.git", outputs)

    def test_real_build_failure_stays_a_plain_failure(self) -> None:
        result, outputs = self.run_adapter("echo 'error: axiom_check found sorry'; exit 1")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("Lean dependency fetch could not run", result.stdout)
        self.assertEqual(outputs, "unrunnable=false\n")

    def test_golden_path_exports_c1_fetch_outcome_to_the_aggregator(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "golden-path.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "python3 scripts/lean_fetch_outcome.py -- " + chr(92) + "\n                ./demo/run c1",
            workflow,
        )
        self.assertIn('"control_12":["control_13","control_14","control_15","control_16","control_17","control_18","control_19"]', workflow)


if __name__ == "__main__":
    unittest.main()
