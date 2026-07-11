#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
External consumer test for the target-bound signer + provider accept logic.

This is deliberately outside the approver modules and the main test_host_rs
(imports only the sign_approval helper and uses the same cryptography path
the real Ed25519TokenProvider uses for verify).

It produces a signed allow and a signed decline for a target, "feeds" the
NDJSON lines to a verification routine that mirrors the host provider
(payload parse + ed25519 verify + nonce/iat presence + branch to record/decline),
and asserts no drop warnings and correct extraction.

Run: python3 test/integration/test_approval_consumer.py
"""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "tools"))
from sign_approval import generate_approval_keypair, sign_approval_token


def verify_as_provider(lines: str, vk_hex: str):
    """Mirror of Ed25519TokenProvider.poll accept path (real crypto)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    vk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(vk_hex))
    records = []
    declines = []
    warnings = []
    for line in lines.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            tok = json.loads(line)
            payload_s = tok["payload"]
            sig = bytes.fromhex(tok["signature"])
            vk.verify(sig, payload_s.encode("utf-8"))
            rec = json.loads(payload_s)
            if not rec.get("nonce") or rec.get("issuedAt") is None:
                warnings.append(("missing_required_field", rec.get("target")))
                continue
            if rec.get("decision") == "deny":
                declines.append(rec)
            else:
                records.append(rec)
        except Exception as e:
            warnings.append(("bad_signature_or_parse", str(e)[:40]))
    return records, declines, warnings


def main() -> int:
    sk, vk = generate_approval_keypair()
    target = "deadbeef" * 8
    allow_line = sign_approval_token(sk, target, 1720000000000, "nonce-allow-xyz", allow=True)
    deny_line = sign_approval_token(sk, target, 1720000000001, "nonce-deny-xyz", allow=False)

    ndjson = allow_line + "\n" + deny_line + "\n"

    recs, decs, warns = verify_as_provider(ndjson, vk)
    print("consumer: produced signed allow and decline")
    print("consumer: fed NDJSON to provider-equivalent verifier")
    print("records:", len(recs), "declines:", len(decs), "warnings:", len(warns))
    assert len(recs) == 1 and recs[0]["target"] == target
    assert len(decs) == 1 and decs[0]["target"] == target
    assert len(warns) == 0, f"expected no drops for valid signed: {warns}"
    print("consumer: SUCCESS - signed records and declines extracted with zero drops")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
