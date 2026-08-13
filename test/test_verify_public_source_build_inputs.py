#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The clean public-source consumer refuses unusable archive inputs early."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import tarfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_public_source_build.sh"


def run_verifier(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(VERIFIER), *args], text=True, capture_output=True, check=False, env=env
    )


def write_tar(path: Path, *, duplicate: bool = False, empty: bool = False) -> None:
    with tarfile.open(path, "w:gz") as archive:
        if not empty:
            payload = path.with_suffix(".payload")
            payload.write_bytes(b"recorded fixture data\n")
            archive.add(payload, arcname="payload.txt")
            payload.unlink()
            if duplicate:
                payload = path.with_suffix(".payload")
                payload.write_bytes(b"duplicate\n")
                archive.add(payload, arcname="payload.txt")
                payload.unlink()


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

    def test_truncated_archive_has_named_refusal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-source-truncated-") as directory:
            archive = Path(directory) / "source.tar.gz"
            write_tar(archive)
            archive.write_bytes(archive.read_bytes()[:-8])
            result = run_verifier(str(archive))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("public source archive is corrupt or truncated", result.stderr)

    def test_inconsistent_member_list_has_named_refusal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-source-members-") as directory:
            archive = Path(directory) / "source.tar.gz"
            write_tar(archive, duplicate=True)
            result = run_verifier(str(archive))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("public source archive member list is inconsistent", result.stderr)

    def test_zero_real_data_has_named_refusal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-source-zero-data-") as directory:
            archive = Path(directory) / "source.tar.gz"
            write_tar(archive, empty=True)
            result = run_verifier(str(archive))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("public source archive contains no real data", result.stderr)

    def test_recorded_producer_archive_member_tamper_is_refused(self) -> None:
        fixture = ROOT / "test/fixtures/public-source-recorded.tar.gz"
        self.assertTrue(fixture.is_file())
        with tempfile.TemporaryDirectory(prefix="public-source-tamper-") as directory:
            tampered = Path(directory) / fixture.name
            data = bytearray(fixture.read_bytes())
            offset = 100_000
            data[offset] ^= 1
            tampered.write_bytes(data)
            result = run_verifier(
                str(tampered),
                env={**os.environ, "SEAL_PUBLIC_SOURCE_PREFLIGHT_ONLY": "1"},
            )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("public source archive is corrupt or truncated", result.stderr)


if __name__ == "__main__":
    unittest.main()
