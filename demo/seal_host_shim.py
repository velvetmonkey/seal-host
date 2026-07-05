#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Drop-in shim: present the V1 mcp-seal CLI (`--policy <p.json> -- <cmd>…`)
while actually running the FULL seal-host (Rust FFI host, all seven kernels).

Translates the V1 policy JSON into the signed epoch'd trusted-config envelope
on the fly, then execs seal-host-rs. This lets an unmodified V1 consumer
(e.g. canary's demo/run_p3.py via SEAL_BIN) put the whole verified host in
front of a real LangGraph agent.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test" / "tools"))
from sign_config import generate_keypair, public_key_hex_from_private, sign_payload  # noqa: E402

CONFIG_SK = os.environ.get("SEAL_CONFIG_SIGNING_KEY_HEX")
if CONFIG_SK:
    PUBKEY = public_key_hex_from_private(CONFIG_SK)
else:
    CONFIG_SK, PUBKEY = generate_keypair()
BIN = os.environ.get("SEAL_HOST_RS", str(ROOT / "rust" / "target" / "debug" / "seal-host-rs"))


def main() -> int:
    args = sys.argv[1:]
    if len(args) < 4 or args[0] != "--policy" or args[2] != "--":
        sys.exit("usage: seal_host_shim.py --policy <policy.json> -- <server-cmd> <args...>")
    policy = json.loads(Path(args[1]).read_text(encoding="utf-8"))
    server_cmd = args[3:]

    payload = {"epoch": 1, "safety": policy}
    fd, config_path = tempfile.mkstemp(prefix="seal-host-trusted-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(sign_payload(payload, CONFIG_SK))

    os.execv(BIN, [BIN, "--config", config_path, "--pubkey", PUBKEY,
                   "--channel", "file", "--", *server_cmd])


if __name__ == "__main__":
    raise SystemExit(main())
