#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Keep the published Compose command within the host's actual CLI surface."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ComposeCliTests(unittest.TestCase):
    def test_compose_uses_only_recognized_host_flags(self) -> None:
        compose = (ROOT / "deploy/container/compose.yaml").read_text(encoding="utf-8")
        flags = set(re.findall(r"^\s+- (--[a-z0-9-]+)\s*$", compose, re.MULTILINE))
        recognized = {
            "--production",
            "--insecure-development-mode",
            "--config",
            "--pubkey",
            "--channel",
            "--token-file",
            "--approval-pubkey",
            "--receipt-dir",
            "--health",
            "--health-listen",
            "--health-token-file",
            "--",
        }
        self.assertFalse(flags - recognized, f"unknown host flags: {sorted(flags - recognized)}")
        self.assertNotIn("--replay-db", flags)


if __name__ == "__main__":
    unittest.main()
