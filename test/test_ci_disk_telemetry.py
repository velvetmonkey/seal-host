#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Behavioral checks for CI disk telemetry and exit-code propagation."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
TELEMETRY = ROOT / "scripts" / "ci_disk_telemetry.py"


class CiDiskTelemetryTests(unittest.TestCase):
    def run_telemetry(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(TELEMETRY),
                "--interval-seconds",
                "0.01",
                "unit-test",
                "--",
                *command,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_reports_initial_peak_and_final_measurements(self) -> None:
        result = self.run_telemetry([sys.executable, "-c", "pass"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for event in ("initial", "peak", "final"):
            self.assertIn(f"phase=unit-test event={event}", result.stdout)
        self.assertIn("command_rc=0", result.stdout)

    def test_propagates_the_measured_command_failure(self) -> None:
        result = self.run_telemetry(
            [sys.executable, "-c", "raise SystemExit(23)"]
        )
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertIn("command_rc=23", result.stdout)


if __name__ == "__main__":
    unittest.main()
