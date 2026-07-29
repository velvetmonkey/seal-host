#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Machine-readable MCP era declarations and request construction for demos."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any


class McpEra(str, Enum):
    MCP_2025 = "2025"
    MCP_2026 = "2026"

    @property
    def revision(self) -> str:
        return {
            McpEra.MCP_2025: "2025-06-18",
            McpEra.MCP_2026: "2026-07-28",
        }[self]

    @property
    def entry_method(self) -> str:
        return {
            McpEra.MCP_2025: "initialize",
            McpEra.MCP_2026: "server/discover",
        }[self]


# This is the harness-readable declaration of which wire contract each checked-in
# golden-path program speaks. Adding a demo without declaring it is a test failure.
DEMO_ERAS: dict[str, tuple[McpEra, ...]] = {
    "golden_path.py": (McpEra.MCP_2025,),
    "golden_path_postgres.py": (McpEra.MCP_2025,),
    "golden_path_deploy.py": (McpEra.MCP_2025,),
    "golden_path_token.py": (McpEra.MCP_2025,),
    "golden_path_convergence.py": (McpEra.MCP_2025,),
    "golden_path_temporal.py": (McpEra.MCP_2025,),
    "golden_path_composition.py": (McpEra.MCP_2025,),
    "golden_path_filesystem.py": (McpEra.MCP_2025, McpEra.MCP_2026),
}


def declared_eras(source: str | Path) -> tuple[McpEra, ...]:
    name = Path(source).name
    try:
        return DEMO_ERAS[name]
    except KeyError as error:
        raise ValueError(f"golden-path demo has no MCP era declaration: {name}") from error


def parse_era(value: str, supported: tuple[McpEra, ...]) -> McpEra:
    try:
        era = McpEra(value)
    except ValueError as error:
        raise ValueError(f"unknown MCP demo era: {value}") from error
    if era not in supported:
        choices = ", ".join(item.value for item in supported)
        raise ValueError(f"MCP era {value} is not declared for this demo; choose {choices}")
    return era


def request_meta(era: McpEra, client_name: str) -> dict[str, Any] | None:
    if era is McpEra.MCP_2025:
        return None
    return {
        "io.modelcontextprotocol/protocolVersion": era.revision,
        "io.modelcontextprotocol/clientInfo": {"name": client_name, "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def request(
    era: McpEra,
    request_id: int,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    client_name: str,
) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if era is McpEra.MCP_2026:
        modern_params = dict(params or {})
        if "_meta" in modern_params:
            raise ValueError("demo request params must not override era-owned _meta")
        modern_params["_meta"] = request_meta(era, client_name)
        message["params"] = modern_params
    elif params is not None:
        message["params"] = params
    return message
