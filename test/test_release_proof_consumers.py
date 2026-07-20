#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Static CI regressions for release proofs that must be consumed after production."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseProofConsumerTests(unittest.TestCase):
    def test_public_export_verifies_produced_signatures(self) -> None:
        workflow = (ROOT / ".github/workflows/public-export.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/verify_public_export.sh", workflow)
        verifier = (ROOT / "scripts/verify_public_export.sh").read_text(encoding="utf-8")
        self.assertIn("cosign verify-blob", verifier)

    def test_public_export_rejects_a_tampered_blob(self) -> None:
        verifier = (ROOT / "scripts/verify_public_export.sh").read_text(encoding="utf-8")
        self.assertIn("tampered blob unexpectedly verified", verifier)


if __name__ == "__main__":
    unittest.main()
