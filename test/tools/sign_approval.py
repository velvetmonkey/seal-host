#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pure target-bound signer for ed25519-token approval/decline records.

Signs (target ‖ nonce ‖ issuedAt) [ + decision for deny ] as the payload.
The *button* (CLI/TG) is ONLY an intent signal; the signing key is what
authorizes. This is the origin of the signed token.

Usage from other modules:
  from sign_approval import generate_approval_keypair, sign_approval_token

  sk, pk = generate_approval_keypair()
  line = sign_approval_token(sk, target_hex, issued_ms, nonce, allow=True)
  # for deny:
  line = sign_approval_token(sk, target_hex, issued_ms, nonce, allow=False)

The returned line is ready to append to the --token-file (NDJSON).
No I/O here: pure.

TCB for CLI channel (demo): host process + this key on same machine.
Co-resident attacker who can read the keyfile or ptrace/substitute the
signing process can emit valid signed records for targets.
"""

import json
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _sk_from_hex(private_key_hex: str) -> Ed25519PrivateKey:
    raw = bytes.fromhex(private_key_hex)
    if len(raw) != 32:
        raise ValueError("approval private key must be 32-byte hex seed")
    return Ed25519PrivateKey.from_private_bytes(raw)


def generate_approval_keypair() -> Tuple[str, str]:
    """Return (priv_hex, pub_hex) for an approval-channel Ed25519 key."""
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return priv, pub


def public_key_hex_from_private(priv_hex: str) -> str:
    sk = _sk_from_hex(priv_hex)
    return sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def sign_approval_token(
    private_key: str | Ed25519PrivateKey,
    target: str,
    issued_at_ms: int,
    nonce: str,
    allow: bool = True,
) -> str:
    """Return a compact NDJSON token line for the ed25519-token channel.

    For allow: payload omits decision (backward compat with existing).
    For deny: includes "decision":"deny".
    Signature is Ed25519 over the exact compact JSON payload bytes.
    """
    if isinstance(private_key, str):
        sk = _sk_from_hex(private_key)
    else:
        sk = private_key

    payload_obj: dict = {
        "target": target,
        "issuedAt": issued_at_ms,
        "nonce": nonce,
    }
    if not allow:
        payload_obj["decision"] = "deny"

    payload = json.dumps(payload_obj, separators=(",", ":"))
    sig = sk.sign(payload.encode("utf-8")).hex()
    envelope = {"payload": payload, "signature": sig}
    return json.dumps(envelope, separators=(",", ":"))


def sign_token(sk: Ed25519PrivateKey, target: str, issued_at: int, nonce: str, allow: bool = True) -> str:
    """Compat wrapper used by some tests (accepts live key object)."""
    return sign_approval_token(sk, target, issued_at, nonce, allow=allow)


if __name__ == "__main__":
    # Smoke: print a sample allow and deny (do not use these keys).
    priv, pub = generate_approval_keypair()
    t = "00000000000000000000000000000000000000000000000000000000000000ff"
    print("PUB:", pub)
    print("ALLOW:", sign_approval_token(priv, t, 1720000000000, "nonce-demo-1", allow=True))
    print("DENY :", sign_approval_token(priv, t, 1720000000000, "nonce-demo-2", allow=False))
