#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the release reproducibility production path."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseReproducibilityTests(unittest.TestCase):
    def test_release_workflow_uses_reproducible_build_and_archiver(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        package = (ROOT / "scripts/package_release.sh").read_text()
        self.assertIn("run: scripts/build_rust_release.sh", workflow)
        self.assertIn('"$ROOT/scripts/create_release_archive.sh"', package)

    def test_archive_normalizes_path_order_modes_owners_and_times(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archives = []
            for index, parent_name in enumerate(("short", "a-much-longer-output-path")):
                stage = base / parent_name / "seal-host-v-test-linux-x86_64"
                paths = [
                    stage / "licenses/third/z.txt",
                    stage / "lib/libsealffi.so",
                    stage / "bin/seal-host-rs",
                    stage / "licenses/a.txt",
                ]
                for path in (paths if index == 0 else reversed(paths)):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(path.name.encode())
                    path.chmod(0o600 if index == 0 else 0o666)
                    os.utime(path, (100 + index, 200 + index))
                for directory in stage.rglob("*"):
                    if directory.is_dir():
                        directory.chmod(0o700 if index == 0 else 0o775)
                archive = base / f"archive-{index}.tar.gz"
                subprocess.run(
                    [ROOT / "scripts/create_release_archive.sh", stage, archive],
                    check=True,
                )
                archives.append(archive)

            self.assertEqual(self._sha256(archives[0]), self._sha256(archives[1]))
            with tarfile.open(archives[0], "r:gz") as opened:
                members = opened.getmembers()
                self.assertEqual([member.name for member in members], sorted(member.name for member in members))
                for member in members:
                    self.assertEqual(member.uid, 0)
                    self.assertEqual(member.gid, 0)
                    self.assertEqual(member.mtime, 0)
                    expected_mode = 0o755 if member.isdir() or member.name.endswith("/bin/seal-host-rs") else 0o644
                    self.assertEqual(member.mode, expected_mode, member.name)

    def test_lean_compiler_remaps_different_checkout_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            objects = []
            for parent in ("one", "directory-with-a-different-length"):
                checkout = base / parent
                source = checkout / "generated.c"
                output = checkout / "generated.o"
                checkout.mkdir()
                source.write_text('const char *source_path(void) { return __FILE__; }\n')
                environment = os.environ.copy()
                environment["SEAL_REPRO_ROOT"] = str(checkout)
                environment["SEAL_REPRO_LEAN_PREFIX"] = subprocess.run(
                    ["lean", "--print-prefix"], check=True, text=True, capture_output=True
                ).stdout.strip()
                subprocess.run(
                    [ROOT / "scripts/reproducible_cc.sh", "-c", source, "-o", output],
                    env=environment,
                    check=True,
                )
                objects.append(output)

            self.assertEqual(self._sha256(objects[0]), self._sha256(objects[1]))
            self.assertNotIn(str(base).encode(), objects[0].read_bytes())

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
