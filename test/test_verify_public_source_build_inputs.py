#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The clean public-source consumer refuses unusable archive inputs early."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_public_source_build.sh"


def run_verifier(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(VERIFIER), *args], text=True, capture_output=True, check=False
    )


class VerifyPublicSourceBuildInputTests(unittest.TestCase):
    def test_absent_input_is_refused(self) -> None:
        result = run_verifier()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("PUBLIC_SOURCE_TARBALL", result.stderr)

    def test_empty_archive_is_refused_before_tool_lookup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-source-empty-") as directory:
            archive = Path(directory) / "source.tar.gz"
            archive.touch()
            result = run_verifier(str(archive))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("public source archive is empty", result.stderr)

    def test_unreadable_archive_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-source-unreadable-") as directory:
            archive = Path(directory) / "source.tar.gz"
            archive.write_bytes(b"not read")
            original_mode = stat.S_IMODE(archive.stat().st_mode)
            os.chmod(archive, 0)
            try:
                result = run_verifier(str(archive))
            finally:
                os.chmod(archive, original_mode)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("public source archive is unreadable", result.stderr)


if __name__ == "__main__":
    unittest.main()
