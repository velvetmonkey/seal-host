#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Minimal synthetic "ledger" MCP server for the approval-loop quickstart.

- Zero external deps.
- Implements just enough JSON-RPC stdio for seal-host to drive:
  initialize, tools/list, tools/call.
- A single guarded tool "ledger.post" (high-stakes write in policy).
- On successful forward of the call, prints an unmistakable side-effect line
  to stdout (will be relayed) and also to stderr for capture:
    SYNTHETIC_LEDGER_ACTION: post amount=... memo=...  (committed)

The guard/approval decision is made by seal-host + policy + human approver.
This server only executes what is forwarded to it.

Used ONLY for the one-command "see the loop" demo (no real money, no real ledger).
"""

import json
import sys


def send(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def log_side_effect(text):
    # Observable proof that action flowed through approval.
    sys.stdout.write(json.dumps({
        "jsonrpc": "2.0",
        "id": None,
        "result": {"content": [{"type": "text", "text": text}]}
    }, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    print(text, file=sys.stderr, flush=True)


def main():
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except Exception:
            continue
        mid = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params") or {}

        if method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments") or {}
            if name in ("ledger.post", "db.execute"):
                sql = args.get("sql", "")
                amt = args.get("amount", 0)
                memo = args.get("memo", "")
                effect = f"SYNTHETIC_LEDGER_ACTION: {name} amount={amt} sql_or_memo={(sql or memo)[:40]} (committed via approval)"
                log_side_effect(effect)
                send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": effect}], "isError": False}})
                continue
            # other calls: just acknowledge (won't be reached for guarded)
            send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": f"ack {name}"}], "isError": False}})
            continue

        if method == "tools/list":
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [{"name": "db.execute"}, {"name": "ledger.post"}]}})
            continue

        # Passthrough / initialize / notifications: echo the line verbatim (matches mock used by e2e tests).
        # This ensures the quickstart and tests see a reply on stdout for initialize passthrough.
        print(line, end="", flush=True)


if __name__ == "__main__":
    main()
