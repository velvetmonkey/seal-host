#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import json
import sys

for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("method") == "tools/call":
        name = msg.get("params", {}).get("name", "")
        result = {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "result": {
                "content": [{"type": "text", "text": f"called {name}"}],
                "isError": False,
            },
        }
        print(json.dumps(result, separators=(",", ":")), flush=True)
    else:
        print(line, end="", flush=True)
