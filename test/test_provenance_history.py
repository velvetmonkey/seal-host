#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Keep every asserted Golden Path kit/kernel history surface in sync."""

import json
import os
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
HISTORY = ROOT / "wasm-spike/verified/pin-history.json"
PROVENANCE = ROOT / "wasm-spike/verified/PROVENANCE.txt"
DEMO = ROOT / "demo/golden_path_filesystem.py"
COLLAPSED_WORDING = (
    "earlier commits carried superseded pins",
    "superseded the prior fleet pin",
)


def demo_text() -> str:
    override_ref = os.environ.get("PIN_HISTORY_DEMO_GIT_REF")
    if override_ref:
        return subprocess.check_output(
            ["git", "show", f"{override_ref}:demo/golden_path_filesystem.py"],
            cwd=ROOT,
            text=True,
        )
    return DEMO.read_text(encoding="utf-8")


class ProvenanceHistoryTests(unittest.TestCase):
    def records(self) -> list[dict[str, str]]:
        history = json.loads(HISTORY.read_text(encoding="utf-8"))
        self.assertEqual(set(history), {"schema", "golden_path_assurance_kit"})
        self.assertEqual(history["schema"], 1)
        return history["golden_path_assurance_kit"]

    def test_pin_history_record_is_well_formed(self) -> None:
        records = self.records()
        self.assertGreaterEqual(len(records), 5)
        self.assertEqual(records[0]["status"], "active")
        self.assertEqual(len({record["kit_commit"] for record in records}), len(records))
        for record in records:
            self.assertEqual(set(record), {"kit_commit", "kernel_sha256", "status"})
            self.assertRegex(record["kit_commit"], r"^[0-9a-f]{40}$")
            self.assertRegex(record["kernel_sha256"], r"^[0-9a-f]{64}$")
            self.assertIn(record["status"], {"active", "parent-same-kernel", "superseded"})

    def test_provenance_and_demo_account_for_every_history_pair(self) -> None:
        provenance = PROVENANCE.read_text(encoding="utf-8")
        demo = demo_text()
        for record in self.records():
            pair = f'{record["kit_commit"]} -> {record["kernel_sha256"]}'
            self.assertIn(pair, provenance)
            self.assertIn(pair, demo)

    def test_collapsed_history_wording_is_rejected(self) -> None:
        surfaces = PROVENANCE.read_text(encoding="utf-8") + "\n" + demo_text()
        lowered = surfaces.lower()
        for wording in COLLAPSED_WORDING:
            self.assertNotIn(wording, lowered)
        self.assertIsNone(re.search(r"earlier .*superseded pins", lowered))


if __name__ == "__main__":
    unittest.main()
