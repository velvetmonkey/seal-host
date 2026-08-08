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
# The published fleet artifact and this repo's verified conformance build are
# independent facts while publication is pending.
FLEET_KERNEL_SHA256 = "0b5e792500592b56847f70b1e27e47aecdc65023c7c59fd79695102c465f26ec"
VERIFIED_WASM_SHA256 = "0b5e792500592b56847f70b1e27e47aecdc65023c7c59fd79695102c465f26ec"
SOURCE_KIT_REV = "316d74126b4cb164d501fea21738d6880469bcb4"
FLEET_ASSURANCE_KIT_REV = "193c6be1bf83f9d93f14840f2b928fcb46937cc0"
GOLDEN_PATH_KIT_REV = "dfa49da640e975318163a5047b2baa04ec9c9b73"

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

        self.assertEqual(fleet["kernel_sha256"], FLEET_KERNEL_SHA256)
        self.assertEqual(wasm, VERIFIED_WASM_SHA256)
        if wasm != fleet["kernel_sha256"]:
            print(
                "PIN STATE: "
                f"fleet={fleet['kernel_sha256']} "
                f"local={wasm}: local ahead of fleet, publish pending"
            )
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
