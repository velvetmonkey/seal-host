#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Wrap a trusted-config payload in the signed envelope the seal-host loads.

Usage: SEAL_CONFIG_SIGNING_KEY_HEX=<32-byte-hex-seed> sign_config.py <payload.json>

The payload (epoch + per-kernel sections) is serialized to compact JSON, and
the Ed25519 signature commits to those exact bytes. Config-signing keys are
separate from approval-token keys; this helper never writes or logs private
keys.
"""

import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical_payload(payload_obj) -> str:
    return json.dumps(payload_obj, separators=(",", ":"))


def _private_key_from_hex(private_key_hex: str) -> Ed25519PrivateKey:
    raw = bytes.fromhex(private_key_hex)
    if len(raw) != 32:
        raise ValueError("SEAL_CONFIG_SIGNING_KEY_HEX must be a 32-byte Ed25519 seed")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_hex_from_private(private_key_hex: str) -> str:
    sk = _private_key_from_hex(private_key_hex)
    return sk.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def generate_keypair() -> tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    private_hex = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public_hex = sk.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    return private_hex, public_hex


def sign_payload(payload_obj, private_key_hex: str | None = None) -> str:
    if private_key_hex is None:
        private_key_hex = os.environ.get("SEAL_CONFIG_SIGNING_KEY_HEX")
    if not private_key_hex:
        raise ValueError("SEAL_CONFIG_SIGNING_KEY_HEX is required")
    payload = json.dumps(payload_obj, separators=(",", ":"))
    sig = _private_key_from_hex(private_key_hex).sign(payload.encode("utf-8")).hex()
    # "$schema" is OUTER-envelope metadata only (checkEnvelope reads just
    # payload+signature, so extra keys are tolerated); the signature commits
    # to the payload bytes, which carry no schema pointer and are never
    # rewritten. The name is the authority's checked-in schema artifact.
    envelope = {
        "$schema": "policy-bundle.schema.json",
        "payload": payload,
        "signature": sig,
    }
    return json.dumps(envelope, separators=(",", ":"))


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        payload_obj = json.load(f)
    try:
        print(sign_payload(payload_obj))
    except ValueError as e:
        print(f"sign_config.py: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
