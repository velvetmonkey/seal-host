#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The public-export verifier must fail before it can inspect bad inputs."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_public_export.sh"


def run_verifier(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(VERIFIER), *args], text=True, capture_output=True, check=False
    )


class VerifyPublicExportInputTests(unittest.TestCase):
    def test_absent_input_is_refused(self) -> None:
        result = run_verifier()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("SIGNED_EXPORT_DIRECTORY", result.stderr)

    def test_empty_input_is_refused_before_tool_lookup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-export-empty-") as directory:
            result = run_verifier(directory)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing source, SBOM, or checksum artifacts", result.stderr)

    def test_unreadable_input_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-export-unreadable-") as directory:
            path = Path(directory)
            original_mode = stat.S_IMODE(path.stat().st_mode)
            os.chmod(path, 0)
            try:
                result = run_verifier(directory)
            finally:
                os.chmod(path, original_mode)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("signed export directory is unreadable", result.stderr)


if __name__ == "__main__":
    unittest.main()
