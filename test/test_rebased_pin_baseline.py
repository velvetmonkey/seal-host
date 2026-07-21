#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Lock the active pins inherited by the main-based remediation branch."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
KERNEL_SHA256 = "a37901811df4767fd08142243622b8372254e6ec5bd2d3aca18f0e61d0f109af"
VERIFIED_WASM_SHA256 = "c9f32b00543c2dd3b1493b3d89ded98abd4d50b8f2dd4e17c2d5256813388eda"
SOURCE_KIT_REV = "1d3566947196fb688f7eff87c4edda2a0ac015fd"
FLEET_ASSURANCE_KIT_REV = "dc44c578cbdddb620d389d5201b465e658692b47"
GOLDEN_PATH_KIT_REV = "62f5fe5d2f3f9d1d700b524aa1d415db449799fc"


class RebasedPinBaselineTests(unittest.TestCase):
    def test_kernel_wasm_and_kit_pins_match_rebased_baseline(self) -> None:
        fleet = json.loads((ROOT / "release/fleet-lock.json").read_text(encoding="utf-8"))
        manifest = json.loads((ROOT / "lake-manifest.json").read_text(encoding="utf-8"))
        source_kit = next(package for package in manifest["packages"] if package["name"] == "«mcp-seal»")
        wasm = hashlib.sha256((ROOT / "wasm-spike/verified/seal.wasm").read_bytes()).hexdigest()

        self.assertEqual(fleet["kernel_sha256"], KERNEL_SHA256)
        self.assertEqual(wasm, VERIFIED_WASM_SHA256)
        self.assertEqual(source_kit["rev"], SOURCE_KIT_REV)
        self.assertEqual(
            fleet["repositories"]["seal-assurance-kit"]["commit"],
            FLEET_ASSURANCE_KIT_REV,
        )

    def test_golden_path_demo_and_workflow_share_main_kit_revision(self) -> None:
        demo = (ROOT / "demo/golden_path_filesystem.py").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/golden-path.yml").read_text(encoding="utf-8")
        demo_match = re.search(r'^PHASE_B_KIT_REV = "([0-9a-f]{40})"$', demo, re.MULTILINE)
        workflow_match = re.search(r"^\s+ref: ([0-9a-f]{40})$", workflow, re.MULTILINE)
        self.assertIsNotNone(demo_match)
        self.assertIsNotNone(workflow_match)
        self.assertEqual(demo_match.group(1), GOLDEN_PATH_KIT_REV)
        self.assertEqual(workflow_match.group(1), GOLDEN_PATH_KIT_REV)


if __name__ == "__main__":
    unittest.main()
