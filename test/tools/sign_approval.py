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

import base64
import hashlib
import json
import os
from typing import Any, Optional, Tuple

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


_APPROVAL_V2_DOMAIN = b"seal.approval-record/v2"
_MAX_CANONICAL_JSON_INTEGER = 9_007_199_254_740_991


def _canonical_json(value: Any) -> bytes:
    """AUTHORIZATION-RECORD.md §2.1 canonical JSON."""

    def encode(inner: Any) -> str:
        if inner is None:
            return "null"
        if inner is True:
            return "true"
        if inner is False:
            return "false"
        if isinstance(inner, int):
            if inner < 0 or inner > _MAX_CANONICAL_JSON_INTEGER:
                raise ValueError("integer outside approval v2 canonical range")
            return str(inner)
        if isinstance(inner, str):
            encoded = ['"']
            for char in inner:
                codepoint = ord(char)
                if 0xD800 <= codepoint <= 0xDFFF:
                    raise ValueError("surrogate is not a Unicode scalar")
                if char == '"':
                    encoded.append(r"\"")
                elif char == "\\":
                    encoded.append(r"\\")
                elif codepoint <= 0x1F:
                    encoded.append(f"\\u00{codepoint:02x}")
                else:
                    encoded.append(char)
            encoded.append('"')
            return "".join(encoded)
        if isinstance(inner, list):
            return "[" + ",".join(encode(item) for item in inner) + "]"
        if isinstance(inner, dict):
            if not all(isinstance(key, str) for key in inner):
                raise ValueError("canonical JSON object keys must be strings")
            names = sorted(inner, key=lambda key: key.encode("utf-8"))
            return "{" + ",".join(
                encode(name) + ":" + encode(inner[name]) for name in names
            ) + "}"
        raise ValueError(f"unsupported canonical JSON value: {type(inner).__name__}")

    return encode(value).encode("utf-8")


def _base64url_nopad(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sign_approval_v2_token(
    private_key: str | Ed25519PrivateKey,
    *,
    target: str,
    authorized_at: int,
    expiry: int,
    nonce: str,
    session: str,
    framed_bytes: bytes,
    shown_bytes: bytes,
    renderer_name: str,
    renderer_version: str,
    renderer_manifest_sha256: str,
    approver: str,
) -> str:
    """Produce an ApprovalRecord v2 token over exact request/display tuples."""
    if isinstance(private_key, str):
        sk = _sk_from_hex(private_key)
    else:
        sk = private_key

    public_key = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signer_key_id = hashlib.sha256(public_key).hexdigest()
    payload_obj = {
        "approval_record_version": 2,
        "target": target,
        "authorized_at": authorized_at,
        "expiry": expiry,
        "nonce": nonce,
        "session": session,
        "subject_sha256": hashlib.sha256(framed_bytes).hexdigest(),
        "subject_length": len(framed_bytes),
        "subject_scope": "mcp-jsonrpc-request-frame-including-delimiter",
        "subject_encoding": "bytes",
        "shown_sha256": hashlib.sha256(shown_bytes).hexdigest(),
        "shown_length": len(shown_bytes),
        "shown_media_type": "text/plain",
        "shown_character_encoding": "utf-8",
        "renderer": {
            "name": renderer_name,
            "version": renderer_version,
            "manifest_sha256": renderer_manifest_sha256,
        },
        "approver": approver,
        "authorization_signer_key_id": signer_key_id,
        "authorization_signature_algorithm": "Ed25519",
        "authorization_domain": "seal.approval-record/v2",
    }
    canonical_payload = _canonical_json(payload_obj)
    signature = sk.sign(_APPROVAL_V2_DOMAIN + b"\x00" + canonical_payload)
    envelope = {
        "payload": canonical_payload.decode("utf-8"),
        "signature_algorithm": "Ed25519",
        "signature_encoding": "base64url-nopad",
        "signer_key_id": signer_key_id,
        "signature": _base64url_nopad(signature),
    }
    return json.dumps(envelope, separators=(",", ":"), ensure_ascii=False)


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
