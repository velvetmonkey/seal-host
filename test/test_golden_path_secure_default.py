#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the filesystem Golden Path's secure-default preflight leg."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))
sys.path.insert(0, str(ROOT / "test" / "integration"))
sys.path.insert(0, str(ROOT / "test" / "tools"))

import golden_path as gp  # noqa: E402
import golden_path_filesystem as filesystem  # noqa: E402
from sign_config import generate_keypair, sign_payload  # noqa: E402
from test_host_rs import config_payload  # noqa: E402


class GoldenPathSecureDefaultTests(unittest.TestCase):
    def test_signed_config_passes_and_tamper_is_denied_without_mode_flag(self) -> None:
        host = ROOT / "rust" / "target" / "debug" / "seal-host-rs"
        self.assertTrue(host.is_file(), f"build the debug host first: {host}")

        for era in filesystem.MCP_ERAS:
            with self.subTest(era=era.value):
                with tempfile.TemporaryDirectory(
                    prefix=f"seal-secure-golden-path-{era.value}-"
                ) as directory:
                    work = Path(directory)
                    os.chmod(work, 0o700)
                    approvals = work / "unused-approvals.ndjson"
                    approvals.write_text("", encoding="utf-8")
                    config_seed, config_pub = generate_keypair()
                    _, approval_pub = generate_keypair()
                    trusted = work / "trusted.json"
                    trusted.write_text(
                        sign_payload(config_payload(work, approvals), config_seed),
                        encoding="utf-8",
                    )
                    gp.initialize_replay_store(trusted, config_pub, host=host)

                    original_host = filesystem.HOST
                    filesystem.HOST = host
                    filesystem.CHECKS.clear()
                    try:
                        filesystem.secure_default_preflight_leg(
                            trusted, config_pub, approval_pub, work, era
                        )
                    finally:
                        filesystem.HOST = original_host

                    observed = {
                        row.name: (row.status, row.evidence)
                        for row in filesystem.CHECKS
                    }
                    self.assertEqual(
                        observed["secure-default signed config"][0], "PASS"
                    )
                    self.assertEqual(
                        observed["secure-default tamper denial"][0], "PASS"
                    )
                    self.assertIn(
                        "trusted config rejected",
                        observed["secure-default tamper denial"][1],
                    )


if __name__ == "__main__":
    unittest.main()
