#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for child-process exchange diagnostics."""

from __future__ import annotations

import subprocess
import sys
import unittest

from process_witness import ChildProcessExchangeError, raise_with_child_stderr


class ProcessWitnessTests(unittest.TestCase):
    def test_dead_child_reports_exit_and_verbatim_stderr_with_cause(self) -> None:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.write('first\\nsecond'); raise SystemExit(3)",
            ],
            stderr=subprocess.PIPE,
            text=True,
        )
        proc.wait(timeout=5)
        original = ValueError("proximate failure")

        with self.assertRaises(ChildProcessExchangeError) as raised:
            raise_with_child_stderr(proc, original)

        try:
            self.assertEqual(
                str(raised.exception),
                "child exited during exchange: exit=3\n"
                "child stderr follows verbatim:\nfirst\nsecond",
            )
            self.assertIs(raised.exception.__cause__, original)
        finally:
            assert proc.stderr is not None
            proc.stderr.close()

    def test_live_child_reraises_original_without_reading_stderr(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            stderr=subprocess.PIPE,
            text=True,
        )
        original = ValueError("proximate failure")
        try:
            self.assertIsNone(proc.poll())
            with self.assertRaises(ValueError) as raised:
                raise_with_child_stderr(proc, original)
            self.assertIs(raised.exception, original)
            self.assertIsNone(proc.poll())
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            assert proc.stderr is not None
            proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
