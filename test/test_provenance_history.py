#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prevent historical fleet pins from being anonymized in provenance."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ProvenanceHistoryTests(unittest.TestCase):
    def test_historical_fleet_pin_remains_explicit(self) -> None:
        provenance = (ROOT / "wasm-spike/verified/PROVENANCE.txt").read_text(encoding="utf-8")
        self.assertIn("superseded the fleet pin df42cbad", provenance)


if __name__ == "__main__":
    unittest.main()
