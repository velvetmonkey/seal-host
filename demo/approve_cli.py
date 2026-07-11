#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
r"""
CLI approver for seal-host ed25519-token channel (developer ingress).

One-shot: given a target (from a block's "approval required: <hex>"), decide
approve or deny, sign a TARGET-BOUND token, append to the token file.

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
    --target 0000...64hex \
    --approve   # or --deny, or omit for prompt

  # or non-interactive one-liner in scripts:
  python3 - <<'PY' ...
  from demo.approve_cli import ... but prefer the bin.

The emitted record is {"payload": "<compact json with target|nonce|issuedAt[|decision]>","signature":"..."}
Exactly what Ed25519TokenProvider verifies.
"""

import argparse
import os
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
)


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


def main() -> int:
    p = argparse.ArgumentParser(
        description="Sign target-bound allow/deny for seal-host ed25519 channel."
    )
    p.add_argument("--token-file", required=True, help="NDJSON file passed as --token-file to host")
    p.add_argument("--target", help="64-hex target from 'approval required: <hex>' (prompt if omitted)")
    p.add_argument("--approve", action="store_true", help="Emit allow (default if neither)")
    p.add_argument("--deny", action="store_true", help="Emit explicit decline (first-class refused)")
    p.add_argument("--key", help="32-byte privkey hex (or use SEAL_APPROVAL_KEY_HEX)")
    p.add_argument("--key-file", help="path to file containing the 32-byte privkey hex")
    p.add_argument("--nonce", help="override nonce (default: random uuid)")
    p.add_argument("--issued-at", type=int, help="override issuedAt ms (default: now)")
    p.add_argument("--yes", "-y", action="store_true", help="do not prompt for confirmation")
    args = p.parse_args()

    if args.approve and args.deny:
        p.error("--approve and --deny are mutually exclusive")

    token_path = Path(args.token_file)
    token_path.parent.mkdir(parents=True, exist_ok=True)

    target = args.target
    if not target:
        target = input("target (64 lowercase hex from block message): ").strip()
    if len(target) != 64 or any(c not in "0123456789abcdef" for c in target):
        print("ERROR: target must be exactly 64 lowercase hex", file=sys.stderr)
        return 2

    allow = not args.deny  # default allow unless --deny
    decision = "allow" if allow else "deny"

    priv = load_privkey(args)
    # validate by deriving pub (will raise on bad)
    pub = public_key_hex_from_private(priv)

    nonce = args.nonce or uuid.uuid4().hex
    issued = args.issued_at or now_ms()

    line = sign_approval_token(priv, target, issued, nonce, allow=allow)

    # Append atomically enough for demo (single writer assumption)
    with token_path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")

    print(f"signed {decision} for target={target}")
    print(f"  nonce={nonce} issuedAt={issued}")
    print(f"  appended to {token_path}")
    print(f"  using pubkey={pub}")
    print("")
    print("TCB (CLI): host + CLI + local key on same machine.")
    print("  Co-resident attacker who reads the key or controls the signer can forge.")
    print("  This demo uses the signed ed25519-token channel (not the unauthenticated control-file).")
    print("  `echo >> control_file` remains DEV-ONLY / UNAUTHENTICATED (labeled in DEPLOY.md).")
    print("")
    print("Next: re-issue the exact MCP call; host will poll the token, verify, and flow or refuse.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
