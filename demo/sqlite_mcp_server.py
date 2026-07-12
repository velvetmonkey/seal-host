#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tiny destructive-sandbox MCP server backed by Python's sqlite3.

This is deliberately capable of executing arbitrary SQL. It exists so the
manual Claude integration can demonstrate a real effect without putting a
production database at risk. Never point it at a database you care about.
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def send(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def result(request_id, text, *, error=False):
    send({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": text}],
            "isError": error,
        },
    })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    args = parser.parse_args()
    database = Path(args.database).expanduser().resolve()
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE IF NOT EXISTS receipt_sandbox (id INTEGER PRIMARY KEY, note TEXT)")
    connection.execute("INSERT OR IGNORE INTO receipt_sandbox(id,note) VALUES (1,'safe to delete')")
    connection.commit()

    tools = [
        {
            "name": "execute_sql",
            "description": "Execute arbitrary SQL against a disposable SQLite sandbox.",
            "inputSchema": {
                "type": "object",
                "properties": {"sql": {"type": "string"}},
                "required": ["sql"],
                "additionalProperties": False,
            },
        },
        {
            "name": "search_objects",
            "description": "List SQLite objects whose names contain query.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": False,
            },
        },
    ]

    for line in sys.stdin:
        try:
            message = json.loads(line)
            request_id = message.get("id")
            method = message.get("method")
            if method == "initialize":
                send({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "seal-sqlite-sandbox", "version": "1.0.0"},
                    },
                })
            elif method == "tools/list":
                send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}})
            elif method == "tools/call":
                params = message.get("params") or {}
                arguments = params.get("arguments") or {}
                if params.get("name") == "execute_sql":
                    sql = arguments.get("sql")
                    if not isinstance(sql, str):
                        result(request_id, "sql must be a string", error=True)
                        continue
                    cursor = connection.execute(sql)
                    rows = cursor.fetchall() if cursor.description else []
                    connection.commit()
                    result(request_id, json.dumps({"rows": rows, "rowcount": cursor.rowcount}))
                elif params.get("name") == "search_objects":
                    query = arguments.get("query")
                    if not isinstance(query, str):
                        result(request_id, "query must be a string", error=True)
                        continue
                    rows = connection.execute(
                        "SELECT name,type FROM sqlite_master WHERE name LIKE ? ORDER BY name",
                        (f"%{query}%",),
                    ).fetchall()
                    result(request_id, json.dumps(rows))
                else:
                    result(request_id, "unknown tool", error=True)
            elif request_id is not None:
                send({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                })
        except Exception as error:
            request_id = message.get("id") if isinstance(message, dict) else None
            send({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32000, "message": str(error)},
            })


if __name__ == "__main__":
    main()
