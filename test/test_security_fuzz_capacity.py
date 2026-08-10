#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Structural guards for the fuzz runner capacity split."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from test_ci_control_reporting import job_step_blocks


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
FUZZ_COMMAND = (
    "cargo +nightly fuzz run hostile_ingress -- -max_total_time=60 -timeout=5"
)


class SecurityFuzzCapacityTests(unittest.TestCase):
    def test_fuzz_job_requires_successful_lean_predecessor(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(
            workflow,
            r"(?m)^  fuzz-hostile-ingress:\n"
            r"    needs: fuzz-hostile-ingress-lean\n"
            r"    runs-on: ubuntu-24\.04$",
        )

        jobs = job_step_blocks(WORKFLOW)
        lean = "\n".join("\n".join(step) for step in jobs["fuzz-hostile-ingress-lean"])
        fuzz = "\n".join("\n".join(step) for step in jobs["fuzz-hostile-ingress"])
        self.assertIn("security-lean-aggregate -- lake test", lean)
        self.assertNotIn(FUZZ_COMMAND, lean)
        self.assertIn(FUZZ_COMMAND, fuzz)
        self.assertNotIn(" lake test", fuzz)

    def test_fuzz_control_keeps_full_run_and_reports_disk(self) -> None:
        jobs = job_step_blocks(WORKFLOW)
        control = next(
            "\n".join(step)
            for step in jobs["fuzz-hostile-ingress"]
            if re.search(r"(?m)^      - id: control_11$", "\n".join(step))
        )
        self.assertIn("python3 ../scripts/ci_disk_telemetry.py security-fuzz", control)
        self.assertIn("df -h .", control)
        self.assertIn("du -sh target fuzz/target", control)
        self.assertIn(FUZZ_COMMAND, control)
        self.assertNotIn("continue-on-error: false", control)


if __name__ == "__main__":
    unittest.main()
