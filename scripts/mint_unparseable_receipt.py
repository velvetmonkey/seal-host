#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Mint the fleet's unparseable-request BLOCK receipt, reproducibly.

The fleet fixtures (seal-assurance-kit fixtures/receipt-unparseable.json,
seal-verify-action fixtures/pass/unparseable.receipt.json, seal-check
test/fixtures/unparseable-block.receipt.json) are REAL native-host output on
the pinned `1e309` line — the line serde cannot parse but the Lean kernel
mediates fine (the differential corpus pins it; rust/tests/host_path.rs
`receipt_layer_never_vetoes_kernel_verdicts` proves the behaviour).

Before this script the mint was a manual host run (kit commit f3660b5); every
re-pin re-derived it by hand. Run this, then copy the printed receipt to the
three fixture homes — ONE mint, three byte-identical copies (sha256sum them).

Signing uses the RFC 8032 test-vector-1 seed so the fixture's pubkey stays
the fleet-pinned d75a9801… (a published test key; the fixture is evidence,
not an authority).

Usage: python3 scripts/mint_unparseable_receipt.py [out_dir]
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "rust" / "target" / "debug" / "seal-host-rs"

sys.path.insert(0, str(ROOT / "test" / "tools"))
from sign_config import sign_payload  # noqa: E402

# RFC 8032 Ed25519 test vector 1 seed -> pubkey d75a9801…
VECTOR1_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
VECTOR1_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

# The pinned divergent line: 1e309 overflows f64, the whole serde parse
# fails, the kernel mediates fine. Golden-vectored in Host/Audit.lean (v2)
# and authorization_decision.rs request_hash_golden_vectors_match_lean.
LINE = (
    '{"jsonrpc":"2.0","id":90,"method":"tools/call","params":'
    '{"name":"db.execute","arguments":{"database":"prod",'
    '"sql":"drop table accounts","x":1e309}}}'
)


def main() -> int:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp(prefix="seal-mint-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    if not HOST.is_file():
        subprocess.run(["cargo", "build"], cwd=ROOT / "rust", check=True)

    work = Path(tempfile.mkdtemp(prefix="seal-mint-work-"))
    approvals = work / "approvals.ndjson"
    approvals.write_text("", encoding="utf-8")
    receipts = work / "receipts"
    payload = {
        "epoch": 1,
        "safety": {
            "approval": {"control_file": str(approvals), "ttl_seconds": 120},
            "tools": [{
                "name": "db.execute",
                "mode": "guarded",
                "match": {"type": "contains_any_ci", "arg": "sql", "needles": ["drop"]},
                # Legacy target committed: "db", arguments.database, "write",
                # arguments.sql. Stage A commits the entire arguments object.
                "target": [{"full_arguments": True}],
            }],
        },
    }
    trusted = work / "trusted.json"
    trusted.write_text(sign_payload(payload, VECTOR1_SEED), encoding="utf-8")

    proc = subprocess.Popen(
        [str(HOST), "--insecure-development-mode", "--config", str(trusted), "--pubkey", VECTOR1_PUB,
         "--receipt-dir", str(receipts), "--", "/bin/cat"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    proc.stdin.write(LINE + "\n")
    proc.stdin.flush()
    blocked = proc.stdout.readline().rstrip("\n")
    proc.stdin.close()
    proc.wait(timeout=10)
    if proc.returncode != 0:
        raise RuntimeError(f"host exited {proc.returncode}: {proc.stderr.read()}")
    if not re.search(r"approval required: [0-9a-f]{64}", blocked):
        raise RuntimeError(f"expected the kernel's own BLOCK, got: {blocked}")

    produced = sorted(receipts.glob("receipt-*.json"))
    if len(produced) != 1:
        raise RuntimeError(f"expected exactly one BLOCK receipt, got {produced}")
    receipt = json.loads(produced[0].read_text(encoding="utf-8"))
    if receipt.get("verdict") != "BLOCK" or "request_parse_error" not in receipt:
        raise RuntimeError("minted receipt is not the unparseable BLOCK shape")
    # The kernel-attested request commitment must already agree (the producer
    # cross-checked it before persisting); assert it anyway — this file
    # becomes fleet evidence.
    audit = json.loads(json.loads(receipt["emitted_bytes"])["audit"])
    if audit["request_sha256"] != receipt["request_sha256"]:
        raise RuntimeError("kernel-attested hash disagrees with request_sha256")

    out = out_dir / "receipt-unparseable.json"
    out.write_text(produced[0].read_text(encoding="utf-8"), encoding="utf-8")
    print(f"minted: {out}")
    print(f"  request_sha256: {receipt['request_sha256']}")
    print(f"  kernel wasm pin: {receipt['kernel_identity']['wasm_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
