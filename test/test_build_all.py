#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Behavioral regression tests for the one-shot build script."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BuildAllTests(unittest.TestCase):
    def test_each_build_failure_is_returned_without_later_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            scripts = fixture / "scripts"
            fake_bin = fixture / "bin"
            scripts.mkdir()
            fake_bin.mkdir()
            (fixture / "rust").mkdir()
            crypto_build = fixture / ".lake/packages/mcp-seal/c/build.sh"
            crypto_build.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/build_all.sh", scripts / "build_all.sh")

            self._write_executable(
                fake_bin / "lake",
                """
                #!/usr/bin/env bash
                if [[ "${FAIL_STAGE:-}" == "lake-build" && "$*" == "build +Ffi" ]]; then
                  exit 41
                fi
                if [[ "${FAIL_STAGE:-}" == "axiom-check" && "$*" == "exe axiom_check" ]]; then
                  exit 42
                fi
                exit 0
                """,
            )
            self._write_executable(
                crypto_build,
                """
                #!/usr/bin/env bash
                mkdir -p c/build
                : > c/build/libsealcrypto.o
                """,
            )
            self._write_executable(
                scripts / "build_ffi_so.sh",
                """
                #!/usr/bin/env bash
                if [[ "${FAIL_STAGE:-}" == "ffi" ]]; then
                  exit 43
                fi
                exit 0
                """,
            )
            self._write_executable(
                fake_bin / "cargo",
                """
                #!/usr/bin/env bash
                if [[ "${FAIL_STAGE:-}" == "cargo" ]]; then
                  exit 44
                fi
                exit 0
                """,
            )

            cases = (
                ("lake-build", 41, "==> lake exe axiom_check"),
                ("axiom-check", 42, "==> scripts/build_ffi_so.sh"),
                ("ffi", 43, "==> cargo build (rust host)"),
                ("cargo", 44, "==> done:"),
            )
            for stage, expected_status, forbidden_output in cases:
                with self.subTest(stage=stage):
                    environment = os.environ.copy()
                    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
                    environment["FAIL_STAGE"] = stage
                    environment["LEANBUILD"] = "lake"
                    result = subprocess.run(
                        ["bash", str(scripts / "build_all.sh")],
                        cwd=fixture,
                        env=environment,
                        text=True,
                        capture_output=True,
                        check=False,
                    )

                    self.assertEqual(
                        result.returncode,
                        expected_status,
                        result.stdout + result.stderr,
                    )
                    self.assertNotIn(forbidden_output, result.stdout)
                    self.assertNotIn("==> done:", result.stdout)

            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            environment["LEANBUILD"] = "lake"
            result = subprocess.run(
                ["bash", "build_all.sh"],
                cwd=scripts,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("==> done: rust/target/debug/seal-host-rs", result.stdout)

    @staticmethod
    def _write_executable(path: Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
