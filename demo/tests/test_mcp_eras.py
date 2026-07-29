#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sys
import unittest
from pathlib import Path

DEMO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEMO))

import mcp_eras  # noqa: E402


class McpEraDeclarationsTest(unittest.TestCase):
    def test_every_golden_path_program_declares_its_eras(self):
        programs = {path.name for path in DEMO.glob("golden_path*.py")}
        self.assertEqual(set(mcp_eras.DEMO_ERAS), programs)

    def test_only_filesystem_is_dual_era_pattern(self):
        dual = {
            name
            for name, eras in mcp_eras.DEMO_ERAS.items()
            if mcp_eras.McpEra.MCP_2026 in eras
        }
        self.assertEqual(dual, {"golden_path_filesystem.py"})
        for name, eras in mcp_eras.DEMO_ERAS.items():
            self.assertIn(mcp_eras.McpEra.MCP_2025, eras, name)

    def test_2025_request_retains_legacy_shape(self):
        request = mcp_eras.request(
            mcp_eras.McpEra.MCP_2025,
            1,
            "tools/list",
            client_name="era-test",
        )
        self.assertNotIn("params", request)

    def test_2026_request_carries_required_meta(self):
        request = mcp_eras.request(
            mcp_eras.McpEra.MCP_2026,
            1,
            "tools/call",
            {"name": "x", "arguments": {}},
            client_name="era-test",
        )
        self.assertEqual(
            request["params"]["_meta"],
            {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {
                    "name": "era-test",
                    "version": "1",
                },
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        )


if __name__ == "__main__":
    unittest.main()
