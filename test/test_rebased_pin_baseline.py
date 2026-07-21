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
KERNEL_SHA256 = "d7d81e277ba0b5e9df385129d86abf6f7469e6da2a65bb2ec35626caa44ea2be"
VERIFIED_WASM_SHA256 = "d7d81e277ba0b5e9df385129d86abf6f7469e6da2a65bb2ec35626caa44ea2be"
SOURCE_KIT_REV = "c3bea29a9982616d3ed1dd0d953f105eac7522bf"
FLEET_ASSURANCE_KIT_REV = "d5e14d173bd8b2170e244a91ad2ddc42ae168cff"
GOLDEN_PATH_KIT_REV = "d5e14d173bd8b2170e244a91ad2ddc42ae168cff"

GOLDEN_PATH_DEMOS = (
    "golden_path_composition.py",
    "golden_path_convergence.py",
    "golden_path_deploy.py",
    "golden_path_filesystem.py",
    "golden_path_postgres.py",
    "golden_path_temporal.py",
    "golden_path_token.py",
)


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
        workflow = (ROOT / ".github/workflows/golden-path.yml").read_text(encoding="utf-8")
        workflow_match = re.search(r"^\s+ref: ([0-9a-f]{40})$", workflow, re.MULTILINE)
        self.assertIsNotNone(workflow_match)
        self.assertEqual(workflow_match.group(1), GOLDEN_PATH_KIT_REV)
        for demo_name in GOLDEN_PATH_DEMOS:
            with self.subTest(demo=demo_name):
                demo = (ROOT / "demo" / demo_name).read_text(encoding="utf-8")
                demo_match = re.search(
                    r'^PHASE_B_KIT_REV = "([0-9a-f]{40})"$', demo, re.MULTILINE
                )
                self.assertIsNotNone(demo_match)
                self.assertEqual(demo_match.group(1), GOLDEN_PATH_KIT_REV)


if __name__ == "__main__":
    unittest.main()
