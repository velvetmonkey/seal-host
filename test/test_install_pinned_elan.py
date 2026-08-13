#!/usr/bin/env python3
"""Tests for observable, exact elan installer resolution."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install_pinned_elan.py"


class InstallPinnedElanTests(unittest.TestCase):
    def resolve(self, pin: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(INSTALLER), "--resolve-only", "--machine", "x86_64", "--pin", str(pin)],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )

    def test_repository_pin_resolves_exact_release_and_checksum(self) -> None:
        result = self.resolve(ROOT / ".github" / "elan-version.json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("elan-version=v4.2.3", result.stdout)
        self.assertIn("/download/v4.2.3/elan-x86_64-unknown-linux-gnu.tar.gz", result.stdout)
        self.assertNotIn("/latest/", result.stdout)
        self.assertIn("df0b2b3a439961ffcbb3985214365ffe40f49bc871df04dff268c7d8e21ca8b2", result.stdout)

    def test_changing_pin_changes_resolved_release(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            pin = Path(directory) / "elan.json"
            pin.write_text(json.dumps({"version": "v4.2.2", "assets": {"x86_64-unknown-linux-gnu": "0" * 64}}), encoding="utf-8")
            result = self.resolve(pin)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("elan-version=v4.2.2", result.stdout)
        self.assertIn("/download/v4.2.2/elan-x86_64-unknown-linux-gnu.tar.gz", result.stdout)

    def test_unreachable_release_root_sets_unrunnable_outputs(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / "output"
            environment = os.environ.copy()
            environment["GITHUB_OUTPUT"] = str(output)
            result = subprocess.run(
                ["python3", str(INSTALLER), "--download-only", "--machine", "x86_64", "--release-root", "http://127.0.0.1:1/releases"],
                cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
            )
            outputs = output.read_text(encoding="utf-8")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrunnable=true", outputs)
        self.assertIn("unrunnable-reason=pinned elan v4.2.3 installer could not run", outputs)

    def test_golden_path_invokes_pin_and_declares_blocked_controls(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "golden-path.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            workflow.count(
                "run: python3 scripts/install_pinned_elan.py --mathlib-cache"
            ),
            2,
        )
        self.assertNotIn("leanprover/lean-action", workflow)
        self.assertIn(
            'SEAL_CONTROL_DEPENDENCIES: \'{"control_05":["control_11",'
            '"control_12","control_13","control_14","control_15","control_16",'
            '"control_17","control_18","control_19"],"control_12":["control_13",'
            '"control_14","control_15","control_16","control_17","control_18",'
            '"control_19"]}\'',
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
