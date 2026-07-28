#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
r"""
CLI approver for seal-host ed25519-token channel (developer ingress).

One-shot: given a saved host refusal (or, for compatibility, a target and exact
blocked MCP request frame), decide approve or deny, sign a request-bound
ApprovalRecord v2, and append it to the token file.

  block happens -> (human sees target) -> CLI signs+appends -> action flows (or refused) -> receipt/audit

SECURITY (per design council):
- The button here is ONLY INTENT. The signing key does the authorization.
- `echo '{"target": "..."}' >> ndjson` (control-file channel) is DEV-ONLY and
  UNAUTHENTICATED. It bypasses origin checks. Use only for local throwaway tests.
- TCB (CLI channel): seal-host process + this CLI process + the local key.
  Co-resident attacker (same uid, can read keyfile, ptrace, LD_PRELOAD the
  signer, or tamper the token file before host polls) can forge approvals.
  The host + key on the same machine is the boundary.

Usage (key via env for demo, or --key-file):
  python3 demo/approve_cli.py \
    --token-file /tmp/seal-tokens.ndjson \
    --refusal-file /tmp/blocked-response.json \
    --approve   # or --deny, or omit for prompt

  # or non-interactive one-liner in scripts:
  python3 - <<'PY' ...
  from demo.approve_cli import ... but prefer the bin.

Approvals use ApprovalRecord v2 and bind the target, exact framed request
(including its delimiter), exact text shown here, times, nonce, session,
renderer, approver, and signing-key identity. Explicit declines retain the
legacy signed-decline envelope because ApprovalRecord v2 has no decline shape.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test" / "tools"))
from sign_approval import (
    generate_approval_keypair,
    public_key_hex_from_private,
    sign_approval_token,
    sign_approval_v2_token,
)

RENDERER_NAME = "seal-approve-cli-raw-mcp-frame"
RENDERER_VERSION = "1.0.0"
RENDERER_MANIFEST = (
    b'{"name":"seal-approve-cli-raw-mcp-frame","version":"1.0.0",'
    b'"format":"heading, target line, then exact UTF-8 MCP request frame including delimiter"}'
)
RENDERER_MANIFEST_SHA256 = hashlib.sha256(RENDERER_MANIFEST).hexdigest()


def now_ms() -> int:
    return int(time.time() * 1000)


def load_privkey(args: argparse.Namespace) -> str:
    if args.key:
        return args.key
    if args.key_file:
        return Path(args.key_file).read_text(encoding="utf-8").strip()
    env = os.environ.get("SEAL_APPROVAL_KEY_HEX")
    if env:
        return env
    # Demo fallback: ephemeral (prints pub so you can wire --approval-pubkey)
    priv, pub = generate_approval_keypair()
    print(f"[demo] generated ephemeral approval key (pub={pub})", file=sys.stderr)
    print("[demo] set SEAL_APPROVAL_KEY_HEX=... or pass --key for real use", file=sys.stderr)
    return priv


def material_from_refusal(path: Path) -> tuple[str, bytes]:
    try:
        refusal = json.loads(path.read_text(encoding="utf-8"))
        text = refusal["result"]["content"][0]["text"]
        subject = refusal["result"]["framed_subject"]
        target_match = re.search(r"approval required: ([0-9a-f]{64})", text)
        if not target_match:
            raise ValueError("content text lacks an exact approval target")
        if subject.get("encoding") != "base64":
            raise ValueError("framed_subject.encoding is not base64")
        framed_bytes = base64.b64decode(subject["base64"], validate=True)
        if len(framed_bytes) != subject["length"]:
            raise ValueError("framed_subject.length does not match decoded bytes")
        digest = hashlib.sha256(framed_bytes).hexdigest()
        if digest != subject["sha256"]:
            raise ValueError("framed_subject.sha256 does not match decoded bytes")
        return target_match.group(1), framed_bytes
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        binascii.Error,
    ) as error:
        raise ValueError(f"invalid host refusal in {path}: {error}") from error


def main() -> int:
    p = argparse.ArgumentParser(
        description="Sign target-bound allow/deny for seal-host ed25519 channel."
    )
    p.add_argument("--token-file", required=True, help="NDJSON file passed as --token-file to host")
    p.add_argument("--target", help="64-hex target from 'approval required: <hex>' (prompt if omitted)")
    p.add_argument(
        "--refusal-file",
        help="saved host refusal JSON; supplies and verifies the target and exact framed subject",
    )
    p.add_argument("--approve", action="store_true", help="Emit allow (default if neither)")
    p.add_argument("--deny", action="store_true", help="Emit explicit decline (first-class refused)")
    p.add_argument("--key", help="32-byte privkey hex (or use SEAL_APPROVAL_KEY_HEX)")
    p.add_argument("--key-file", help="path to file containing the 32-byte privkey hex")
    p.add_argument("--nonce", help="override nonce (default: random uuid)")
    p.add_argument("--issued-at", type=int, help="override authorized_at ms (default: now)")
    p.add_argument("--expiry", type=int, help="override expiry ms (default: authorized_at + 120s)")
    p.add_argument("--session", help="approval session label (default: random CLI session)")
    p.add_argument("--approver", default="local CLI operator", help="identity shown in the v2 record")
    p.add_argument(
        "--request-file",
        help="exact UTF-8 MCP request frame, including its LF or CRLF delimiter (required for approval)",
    )
    p.add_argument("--yes", "-y", action="store_true", help="do not prompt for confirmation")
    p.add_argument(
        "--plain",
        action="store_true",
        help="DEV-ONLY legacy decline only; unauthenticated v1 approvals are no longer admitted",
    )
    args = p.parse_args()

    if args.approve and args.deny:
        p.error("--approve and --deny are mutually exclusive")
    if args.refusal_file and args.request_file:
        p.error("--refusal-file and --request-file are mutually exclusive")

    token_path = Path(args.token_file)
    token_path.parent.mkdir(parents=True, exist_ok=True)

    refusal_framed_bytes = None
    refusal_target = None
    if args.refusal_file:
        try:
            refusal_target, refusal_framed_bytes = material_from_refusal(Path(args.refusal_file))
        except ValueError as error:
            p.error(str(error))
        if args.target and args.target != refusal_target:
            p.error("--target disagrees with the target in --refusal-file")

    target = args.target or refusal_target
    if not target:
        target = input("target (64 lowercase hex from block message): ").strip()
    if len(target) != 64 or any(c not in "0123456789abcdef" for c in target):
        print("ERROR: target must be exactly 64 lowercase hex", file=sys.stderr)
        return 2

    allow = not args.deny  # default allow unless --deny
    decision = "allow" if allow else "deny"

    if allow and args.plain:
        p.error(
            "--plain cannot emit an admitted approval: the host refuses v1 and "
            "the v2 approval channel requires an Ed25519 signature"
        )
    if allow and not (args.request_file or refusal_framed_bytes is not None):
        p.error(
            "--refusal-file or --request-file is required for ApprovalRecord v2; "
            "the target alone does not identify the exact framed request"
        )
    if not args.approver:
        p.error("--approver must be non-empty")
    if args.session == "":
        p.error("--session must be non-empty")

    priv = load_privkey(args)
    # validate by deriving pub (will raise on bad)
    pub = public_key_hex_from_private(priv)

    nonce = args.nonce or uuid.uuid4().hex
    issued = args.issued_at if args.issued_at is not None else now_ms()

    if args.plain:
        # ApprovalRecord v2 has no unsigned/control-file representation. The
        # legacy control-file decline remains explicit and fail-closed.
        line = json.dumps(
            {"target": target, "issuedAt": issued, "nonce": nonce, "decision": "deny"},
            separators=(",", ":"),
        )
        print("WARNING: --plain writes a DEV-ONLY UNAUTHENTICATED legacy decline.")
    elif not allow:
        line = sign_approval_token(priv, target, issued, nonce, allow=False)
    else:
        framed_bytes = (
            refusal_framed_bytes
            if refusal_framed_bytes is not None
            else Path(args.request_file).read_bytes()
        )
        if not framed_bytes.endswith((b"\n", b"\r\n")):
            p.error("framed subject must include the request frame's LF or CRLF delimiter")
        body = framed_bytes[:-2] if framed_bytes.endswith(b"\r\n") else framed_bytes[:-1]
        if b"\n" in body or b"\r" in body:
            p.error("framed subject must contain exactly one line-framed MCP request")
        try:
            body.decode("utf-8")
            request = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            p.error(f"framed subject is not one UTF-8 JSON request frame: {error}")
        if not isinstance(request, dict) or request.get("method") != "tools/call":
            p.error("framed subject must contain the blocked tools/call request")

        shown = (
            f"Seal approval request\n"
            f"target: {target}\n"
            "exact MCP request frame (including delimiter):\n"
        ).encode("utf-8") + framed_bytes
        sys.stdout.buffer.write(shown)
        sys.stdout.buffer.flush()
        if not args.yes and input("Approve this exact request? [y/N] ").strip().lower() != "y":
            print("No approval emitted.")
            return 1

        expiry = args.expiry if args.expiry is not None else issued + 120_000
        if expiry < issued:
            p.error("--expiry must be greater than or equal to --issued-at")
        line = sign_approval_v2_token(
            priv,
            target=target,
            authorized_at=issued,
            expiry=expiry,
            nonce=nonce,
            session=args.session or f"approve-cli/{uuid.uuid4().hex}",
            framed_bytes=framed_bytes,
            shown_bytes=shown,
            renderer_name=RENDERER_NAME,
            renderer_version=RENDERER_VERSION,
            renderer_manifest_sha256=RENDERER_MANIFEST_SHA256,
            approver=args.approver,
        )

    # Append atomically enough for demo (single writer assumption)
    with token_path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")

    print(f"{'signed' if not args.plain else 'recorded'} {decision} for target={target}")
    print(f"  nonce={nonce} authorizedAt={issued}")
    print(f"  appended to {token_path}")
    print(f"  using pubkey={pub}")
    print("")
    print("TCB (CLI): host + CLI + local key on same machine.")
    print("  Co-resident attacker who reads the key or controls the signer can forge.")
    if allow:
        print("  ApprovalRecord v2 binds the exact framed MCP request and exact text shown above.")
    elif args.plain:
        print("  This decline is unauthenticated and DEV-ONLY.")
    else:
        print("  Explicit decline uses the legacy signed-decline envelope (v2 has no decline shape).")
    print("")
    print("Next: re-issue the exact MCP frame; host will poll the token, verify, and flow or refuse.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
