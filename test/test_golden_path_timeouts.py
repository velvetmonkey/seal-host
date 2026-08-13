#!/usr/bin/env python3
"""Regression guard for Golden Path job and in-shell timeout bounds."""
from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/golden-path.yml"


def job_blocks(text: str) -> dict[str, str]:
    text = text[text.index("\njobs:\n") + 1 :]
    matches = list(re.finditer(r"(?m)^  ([a-z0-9-]+):\n", text))
    return {
        match.group(1): text[match.end(): matches[index + 1].start() if index + 1 < len(matches) else len(text)]
        for index, match in enumerate(matches)
    }


class GoldenPathTimeoutTests(unittest.TestCase):
    def test_every_job_has_measured_timeout_and_long_shell_steps_are_bounded(self) -> None:
        blocks = job_blocks(WORKFLOW.read_text(encoding="utf-8"))
        self.assertEqual(set(blocks), {"lean-aggregate", "deterministic-shell"})
        for job, block in blocks.items():
            with self.subTest(job=job):
                self.assertRegex(block, r"(?m)^    timeout-minutes: [1-9][0-9]*$")
        self.assertIn("timeout --signal=TERM --kill-after=30s 2100s", blocks["lean-aggregate"])
        self.assertIn("timeout --signal=TERM --kill-after=30s 3000s", blocks["deterministic-shell"])


if __name__ == "__main__":
    unittest.main()
