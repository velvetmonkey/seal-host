#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
r"""
Telegram approver (demo-grade bridge) for seal-host ed25519-token channel.

Block -> (human sees target in agent) -> ping via Telegram (or human pastes target)
-> inline buttons (Approve / Deny) -> callback (HMAC-bound intent ONLY)
-> bridge (this process) verifies from.id allowlist + HMAC(target,nonce,decision)
-> bridge signs the TARGET-BOUND record with its held key -> appends to token-file
-> action flows or explicit "refused" -> receipt/audit

SECURITY CORE (non-negotiable):
- The Telegram button/callback is an INTENT SIGNAL, NEVER the signing key.
- Callbacks are accepted ONLY from allowlisted from.id.
- Callback data is HMAC'ed over (target, nonce, decision) using a bridge-held
  secret (demo). This binds the intent and makes simple forgeries detectable.
- The *bridge* holds the Ed25519 signing key (demo-grade convenience).
- TCB (Telegram channel, demo): seal-host + this bridge process + its signing
  key + the allowlist + Telegram's delivery for the chosen user ids.
  A compromised Telegram account (if allowlisted) or a MITM on the bot token
  channel can supply intents that the bridge will honor.
- Production upgrade (documented): device-held key. The user's phone holds the
  private key; a deep-link / Telegram Web App / mini-app triggers a local sign
  of the exact (target ‖ nonce ‖ issuedAt ‖ decision) and the *signed token*
  (not a raw button) is returned to the bridge or directly to the token file
  via a tight origin channel. The bridge never sees the key. This shrinks the
  origin TCB to the user's device + audited client.

`echo >> ndjson` (control-file) and this demo bridge are both labeled.

One-command quickstart uses the CLI path (zero external). Telegram path requires:
  TELEGRAM_BOT_TOKEN=... python3 demo/approve_telegram.py --token-file ... --allowed 123456

The core verify + sign functions are importable for unit tests without a live bot.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test" / "tools"))
from sign_approval import (
    generate_approval_keypair,
    public_key_hex_from_private,
    sign_approval_token,
)


DEMO_HMAC_SECRET = b"seal-demo-intent-hmac-secret-do-not-use-in-prod"


def now_ms() -> int:
    return int(time.time() * 1000)


def compute_intent_hmac(target: str, nonce: str, decision: str, secret: bytes = DEMO_HMAC_SECRET) -> str:
    """HMAC over the bound tuple; used in callback_data and verification."""
    msg = f"{target}|{nonce}|{decision}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()[:16]  # short for TG callback limit


def verify_intent_callback(data: str, secret: bytes = DEMO_HMAC_SECRET) -> Optional[Tuple[str, str, str]]:
    """Return (decision, target, nonce) if HMAC validates, else None."""
    # data format: "dec:<allow|deny>:<64hex>:<nonce>:<hmac16>"
    try:
        parts = data.split(":", 4)
        if len(parts) != 5 or parts[0] != "dec":
            return None
        _, dec, target, nonce, mac = parts
        if dec not in ("allow", "deny"):
            return None
        if len(target) != 64 or any(c not in "0123456789abcdef" for c in target):
            return None
        expected = compute_intent_hmac(target, nonce, dec, secret)
        if not hmac.compare_digest(expected, mac):
            return None
        return (dec, target, nonce)
    except Exception:
        return None


def build_callback_data(decision: str, target: str, nonce: str) -> str:
    mac = compute_intent_hmac(target, nonce, decision)
    # dec:allow:... or dec:deny:...
    dshort = "allow" if decision == "allow" else "deny"
    return f"dec:{dshort}:{target}:{nonce}:{mac}"


def tg_api(token: str, method: str, params: Optional[dict] = None) -> dict:
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = None
    if params:
        data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"tg {method} failed: {e} {body}") from e


def send_buttons(token: str, chat_id: int, target: str, text: str = None):
    if text is None:
        text = f"Approval required for target:\n{target}\n\nApprove or Deny?"
    nonce = uuid.uuid4().hex[:16]
    kb = {
        "inline_keyboard": [
            [
                {"text": "✅ Approve", "callback_data": build_callback_data("allow", target, nonce)},
                {"text": "❌ Deny", "callback_data": build_callback_data("deny", target, nonce)},
            ]
        ]
    }
    tg_api(token, "sendMessage", {
        "chat_id": chat_id,
        "text": text,
        "reply_markup": json.dumps(kb),
    })
    return nonce


def append_token(token_file: Path, priv: str, target: str, nonce: str, allow: bool):
    issued = now_ms()
    line = sign_approval_token(priv, target, issued, nonce, allow=allow)
    with token_file.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    return line


def handle_update(u: dict, token: str, allowed: List[int], priv: str, token_file: Path, secret: bytes):
    # message or callback_query
    if "callback_query" in u:
        cq = u["callback_query"]
        from_id = cq.get("from", {}).get("id")
        data = cq.get("data", "")
        chat_id = cq.get("message", {}).get("chat", {}).get("id") or from_id
        if from_id not in allowed:
            tg_api(token, "answerCallbackQuery", {"callback_query_id": cq["id"], "text": "not allowed", "show_alert": True})
            return
        verified = verify_intent_callback(data, secret)
        if not verified:
            tg_api(token, "answerCallbackQuery", {"callback_query_id": cq["id"], "text": "invalid or tampered intent", "show_alert": True})
            return
        decision, target, nonce = verified
        allow = (decision == "allow")
        append_token(token_file, priv, target, nonce, allow=allow)
        tg_api(token, "answerCallbackQuery", {"callback_query_id": cq["id"], "text": f"recorded: {decision}"})
        # edit to final
        try:
            tg_api(token, "editMessageText", {
                "chat_id": chat_id,
                "message_id": cq["message"]["message_id"],
                "text": f"Recorded {decision.upper()} for target {target[:12]}... (nonce {nonce[:8]})",
            })
        except Exception:
            pass
        return

    msg = u.get("message") or {}
    from_id = msg.get("from", {}).get("id")
    text = (msg.get("text") or "").strip()
    chat_id = msg.get("chat", {}).get("id") or from_id
    if from_id not in allowed:
        return
    if text.startswith("/start"):
        tg_api(token, "sendMessage", {"chat_id": chat_id, "text": "Send a 64-hex target (from your block message) or wait for a ping with buttons."})
        return
    # crude: any line containing 64 hex is treated as target to ping buttons for
    import re
    m = re.search(r"\b([0-9a-f]{64})\b", text)
    if m:
        t = m.group(1)
        send_buttons(token, chat_id, t, text=f"Target from your message:\n{t}\n\nDecide:")
        return
    if text:
        tg_api(token, "sendMessage", {"chat_id": chat_id, "text": "Reply with the 64-hex target to get Approve/Deny buttons."})


def run_bot(token: str, allowed: List[int], priv: str, token_file: Path, poll_interval: float = 1.0):
    offset = 0
    print(f"Telegram approver bridge starting. allowed_ids={allowed}")
    print(f"token file: {token_file}")
    print("WARNING: demo-grade. Bridge holds signing key. See source header for TCB and upgrade notes.")
    while True:
        try:
            res = tg_api(token, "getUpdates", {"offset": offset, "timeout": 20, "allowed_updates": json.dumps(["message", "callback_query"])})
            for u in res.get("result", []):
                offset = max(offset, u["update_id"] + 1)
                handle_update(u, token, allowed, priv, token_file, DEMO_HMAC_SECRET)
        except Exception as e:
            print("tg poll error:", e, file=sys.stderr)
            time.sleep(2)
        time.sleep(poll_interval)


def main() -> int:
    ap = argparse.ArgumentParser(description="Telegram intent bridge (demo) for seal approvals")
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--allowed", required=True, help="comma-separated numeric from.id values, e.g. 12345678")
    ap.add_argument("--key", help="priv hex (or SEAL_APPROVAL_KEY_HEX)")
    ap.add_argument("--poll", type=float, default=0.8)
    args = ap.parse_args()

    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        print("TELEGRAM_BOT_TOKEN required (get from @BotFather)", file=sys.stderr)
        return 2

    allowed = [int(x.strip()) for x in args.allowed.split(",") if x.strip()]
    if not allowed:
        print("at least one --allowed id", file=sys.stderr)
        return 2

    priv = args.key or os.environ.get("SEAL_APPROVAL_KEY_HEX")
    if not priv:
        priv, pub = generate_approval_keypair()
        print(f"[demo] ephemeral approval pub={pub}  (set SEAL_APPROVAL_KEY_HEX for persistent)", file=sys.stderr)

    # validate pub derivation
    pub = public_key_hex_from_private(priv)

    token_path = Path(args.token_file)
    token_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"bridge pubkey for --approval-pubkey: {pub}")
    print("Device-held-key production note: see header and docs/ (origin-tight, key never on bridge).")
    run_bot(token, allowed, priv, token_path, args.poll)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
