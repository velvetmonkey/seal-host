#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Wrap a trusted-config payload in the signed envelope the seal-host loads.

Usage: sign_config.py <payload.json> <pubkey> [> trusted.json]

The payload (epoch + per-kernel sections) is serialized to compact JSON — the
SealV2-canonical byte form the host verifies — and the stub signature commits
to those exact bytes. G6 replaces the stub with real Ed25519 over the same
bytes.
"""

import json
import sys


def sign_payload(payload_obj, pubkey: str) -> str:
    payload = json.dumps(payload_obj, separators=(",", ":"))
    envelope = {
        "payload": payload,
        "signature": f"stub-ed25519:{pubkey}:{payload}",
    }
    return json.dumps(envelope, separators=(",", ":"))


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        payload_obj = json.load(f)
    print(sign_payload(payload_obj, sys.argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
