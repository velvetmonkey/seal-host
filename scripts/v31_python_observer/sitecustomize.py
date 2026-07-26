# SPDX-License-Identifier: Apache-2.0
"""Observe JSON decoding in an otherwise unmodified Python MCP server."""

import hashlib
import json
import math
import sys

try:
    from mcp import types as mcp_types
except ModuleNotFoundError as error:
    if error.name != "mcp":
        raise
    mcp_types = None

_original_loads = json.loads
_original_model_validate_json = (
    mcp_types.JSONRPCMessage.model_validate_json if mcp_types is not None else None
)


def _semantic(value):
    if isinstance(value, float) and not math.isfinite(value):
        return {"$nonFiniteNumber": str(value)}
    if isinstance(value, list):
        return [_semantic(item) for item in value]
    if isinstance(value, dict):
        return {key: _semantic(item) for key, item in value.items()}
    return value


def _emit(raw_value, method, params, parse_layer):
    if method != "tools/call":
        return
    raw = raw_value.encode("utf-8") if isinstance(raw_value, str) else bytes(raw_value)
    wire_frame = raw if raw.endswith(b"\n") else raw + b"\n"
    params = params if isinstance(params, dict) else {}
    record = {
        "event": "v31_server_json_parse",
        "parse_layer": parse_layer,
        "request_sha256": hashlib.sha256(raw).hexdigest(),
        "wire_frame_sha256": hashlib.sha256(wire_frame).hexdigest(),
        "accepted": True,
        "tool": params.get("name"),
        "arguments": _semantic(params.get("arguments")),
    }
    print(
        "V31_SERVER_OBSERVATION "
        + json.dumps(record, separators=(",", ":"), ensure_ascii=True),
        file=sys.stderr,
        flush=True,
    )


def _observed_loads(value, *args, **kwargs):
    parsed = _original_loads(value, *args, **kwargs)
    if isinstance(parsed, dict):
        _emit(value, parsed.get("method"), parsed.get("params"), "json.loads")
    return parsed


def _observed_model_validate_json(
    cls,
    json_data,
    *,
    strict=None,
    extra=None,
    context=None,
    by_alias=None,
    by_name=None,
):
    assert _original_model_validate_json is not None
    try:
        parsed = _original_model_validate_json(
            json_data,
            strict=strict,
            extra=extra,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )
    except Exception as error:
        raw = json_data.encode("utf-8") if isinstance(json_data, str) else bytes(json_data)
        wire_frame = raw if raw.endswith(b"\n") else raw + b"\n"
        record = {
            "event": "v31_server_json_parse",
            "parse_layer": "mcp.types.JSONRPCMessage.model_validate_json",
            "request_sha256": hashlib.sha256(raw).hexdigest(),
            "wire_frame_sha256": hashlib.sha256(wire_frame).hexdigest(),
            "accepted": False,
            "parse_error": str(error),
        }
        print(
            "V31_SERVER_OBSERVATION "
            + json.dumps(record, separators=(",", ":"), ensure_ascii=True),
            file=sys.stderr,
            flush=True,
        )
        raise
    message = parsed.root
    _emit(
        json_data,
        getattr(message, "method", None),
        getattr(message, "params", None),
        "mcp.types.JSONRPCMessage.model_validate_json",
    )
    return parsed


json.loads = _observed_loads
if mcp_types is not None:
    mcp_types.JSONRPCMessage.model_validate_json = classmethod(_observed_model_validate_json)
