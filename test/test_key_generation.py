#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for fail-closed documented key generation."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
KEY_FILENAMES = (
    "approval.key",
    "config.key",
    "config.pub",
    "approval.pub",
)


class KeyGenerationTests(unittest.TestCase):
    def test_approval_import_failure_exits_nonzero_without_key_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="seal-keygen-import-failure-") as directory:
            fixture = Path(directory)
            script = self._copy_generator(fixture)
            output_dir = fixture / ".seal"

            self._assert_import_failure(
                fixture,
                script,
                output_dir,
                "key generation failed: No module named 'sign_approval'",
            )

    def test_config_import_failure_exits_nonzero_without_key_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="seal-keygen-import-failure-") as directory:
            fixture = Path(directory)
            script = self._copy_generator(fixture)
            tools = fixture / "test" / "tools"
            tools.mkdir(parents=True)
            self._write_fake_signer(tools / "sign_approval.py", "3", "4", approval=True)
            output_dir = fixture / ".seal"

            self._assert_import_failure(
                fixture,
                script,
                output_dir,
                "key generation failed: No module named 'sign_config'",
            )

    def test_complete_valid_keyset_is_published_together(self) -> None:
        with tempfile.TemporaryDirectory(prefix="seal-keygen-success-") as directory:
            fixture = Path(directory)
            script = self._copy_generator(fixture)
            tools = fixture / "test" / "tools"
            tools.mkdir(parents=True)
            self._write_fake_signer(tools / "sign_config.py", "1", "2")
            self._write_fake_signer(tools / "sign_approval.py", "3", "4", approval=True)
            output_dir = fixture / ".seal"

            result = subprocess.run(
                [sys.executable, str(script), "--out-dir", str(output_dir)],
                cwd=fixture,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            expected = {
                "approval.key": "3" * 64 + "\n",
                "config.key": "1" * 64 + "\n",
                "config.pub": "2" * 64 + "\n",
                "approval.pub": "4" * 64 + "\n",
            }
            self.assertEqual(
                {name: (output_dir / name).read_text(encoding="ascii") for name in KEY_FILENAMES},
                expected,
            )
            self.assertEqual(list(output_dir.glob(".seal-keygen-*")), [])

    def _assert_import_failure(
        self,
        fixture: Path,
        script: Path,
        output_dir: Path,
        expected_error: str,
    ) -> None:
        result = subprocess.run(
            [sys.executable, str(script), "--out-dir", str(output_dir)],
            cwd=fixture,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(expected_error, result.stderr)
        self.assertEqual(
            [path for path in fixture.rglob("*") if path.name in KEY_FILENAMES],
            [],
        )

    @staticmethod
    def _copy_generator(fixture: Path) -> Path:
        scripts = fixture / "scripts"
        scripts.mkdir()
        script = scripts / "generate_keys.py"
        shutil.copy2(ROOT / "scripts" / "generate_keys.py", script)
        return script

    @staticmethod
    def _write_fake_signer(
        path: Path,
        private_digit: str,
        public_digit: str,
        *,
        approval: bool = False,
    ) -> None:
        generate_name = "generate_approval_keypair" if approval else "generate_keypair"
        path.write_text(
            textwrap.dedent(
                f"""
                PRIVATE = {private_digit!r} * 64
                PUBLIC = {public_digit!r} * 64

                def {generate_name}():
                    return PRIVATE, PUBLIC

                def public_key_hex_from_private(private):
                    if private != PRIVATE:
                        raise ValueError("unexpected private key")
                    return PUBLIC
                """
            ).lstrip(),
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
