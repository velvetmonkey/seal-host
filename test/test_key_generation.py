#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for fail-closed documented key generation."""

from __future__ import annotations

from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate_keys.py"
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
            self.assertEqual(
                stat.S_IMODE(output_dir.stat().st_mode),
                0o700,
                f"{output_dir} mode",
            )
            for name in KEY_FILENAMES:
                path = output_dir / name
                self.assertEqual(
                    stat.S_IMODE(path.stat().st_mode),
                    0o600,
                    f"{path} mode",
                )
            self.assertEqual(list(output_dir.glob(".seal-keygen-*")), [])

    def test_private_key_mode_observation_distinguishes_0644(self) -> None:
        with tempfile.TemporaryDirectory(prefix="seal-keygen-mode-check-") as directory:
            fixture = Path(directory)
            script = self._copy_generator(fixture)
            source = script.read_text(encoding="utf-8")
            private_mode_setting = "os.chmod(path, 0o600)"
            self.assertEqual(source.count(private_mode_setting), 1)
            script.write_text(
                source.replace(private_mode_setting, "os.chmod(path, 0o644)"),
                encoding="utf-8",
            )
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
            for name in KEY_FILENAMES:
                path = output_dir / name
                self.assertEqual(
                    stat.S_IMODE(path.stat().st_mode),
                    0o644,
                    f"{path} mode",
                )

    def test_real_generator_emits_matching_ed25519_keypairs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="seal-keygen-real-") as directory:
            keysets: list[dict[str, str]] = []
            for run in range(2):
                output_dir = Path(directory) / f".seal-{run}"
                result = subprocess.run(
                    [
                        sys.executable,
                        str(GENERATOR),
                        "--out-dir",
                        str(output_dir),
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                keyset: dict[str, str] = {}
                private_keys: list[str] = []
                for label in ("config", "approval"):
                    private = (
                        output_dir / f"{label}.key"
                    ).read_text(encoding="ascii").strip()
                    public = (
                        output_dir / f"{label}.pub"
                    ).read_text(encoding="ascii").strip()
                    derived = Ed25519PrivateKey.from_private_bytes(
                        bytes.fromhex(private)
                    ).public_key().public_bytes(
                        serialization.Encoding.Raw,
                        serialization.PublicFormat.Raw,
                    ).hex()
                    self.assertEqual(public, derived)
                    self.assertNotEqual(private, "0" * 64)
                    keyset[f"{label}.key"] = private
                    keyset[f"{label}.pub"] = public
                    private_keys.append(private)
                self.assertNotEqual(private_keys[0], private_keys[1])
                keysets.append(keyset)

            for name in KEY_FILENAMES:
                self.assertNotEqual(
                    keysets[0][name],
                    keysets[1][name],
                    f"{name} was repeated across independent generator runs",
                )

    def test_stale_staging_directories_are_removed_on_startup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="seal-keygen-stale-") as directory:
            fixture = Path(directory)
            script = self._copy_generator(fixture)
            tools = fixture / "test" / "tools"
            tools.mkdir(parents=True)
            self._write_fake_signer(tools / "sign_config.py", "1", "2")
            self._write_fake_signer(tools / "sign_approval.py", "3", "4", approval=True)
            output_dir = fixture / ".seal"
            stale_dir = output_dir / ".seal-keygen-abandoned"
            stale_dir.mkdir(parents=True)
            (stale_dir / "value-0.tmp").write_text("private\n", encoding="ascii")

            result = subprocess.run(
                [sys.executable, str(script), "--out-dir", str(output_dir)],
                cwd=fixture,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(stale_dir.exists())

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
        shutil.copy2(GENERATOR, script)
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
