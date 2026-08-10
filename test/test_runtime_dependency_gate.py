#!/usr/bin/env python3

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "runtime_dependency_gate.sh"


class RuntimeDependencyGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="seal-runtime-gate-", dir=Path.home()
        )
        self.root = Path(self.temp.name)
        self.private = self.root / "private"
        self.private.mkdir()
        private_source = self.root / "private.c"
        private_source.write_text(
            "int private_answer(void) { return 42; }\n", encoding="utf-8"
        )
        self.private_library = self.private / "libprivate.so"
        subprocess.run(
            [
                "cc", "-shared", "-fPIC", "-Wl,-soname,libprivate.so",
                "-o", str(self.private_library), str(private_source),
            ],
            check=True,
        )

        host_source = self.root / "host.c"
        host_source.write_text(
            """\
#include <stdio.h>
extern int private_answer(void);
int main(void) {
    if (private_answer() != 42) return 1;
    fputs("usage: seal-host-rs\\n", stderr);
    return 2;
}
""",
            encoding="utf-8",
        )
        self.host = self.root / "seal-host-rs"
        subprocess.run(
            [
                "cc", "-o", str(self.host), str(host_source),
                f"-L{self.private}", "-lprivate", "-Wl,-rpath,$ORIGIN/../lib",
            ],
            check=True,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def stage(self, name: str, *, external_symlink: bool) -> Path:
        stage = self.root / name
        (stage / "bin").mkdir(parents=True)
        (stage / "lib").mkdir()
        shutil.copy2(self.host, stage / "bin" / "seal-host-rs")
        staged_library = stage / "lib" / "libprivate.so"
        if external_symlink:
            os.symlink(self.private_library, staged_library)
        else:
            shutil.copy2(self.private_library, staged_library)
        return stage

    def run_gate(self, stage: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(GATE), str(stage)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_accepts_bundled_library_when_stage_is_under_home(self) -> None:
        result = self.run_gate(self.stage("bundled-stage", external_symlink=False))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "PASS self-contained public runtime dependency gate", result.stdout
        )

    def test_rejects_library_symlinked_from_outside_bundle(self) -> None:
        result = self.run_gate(self.stage("escaped-stage", external_symlink=True))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "release has an unresolved or private runtime dependency",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
