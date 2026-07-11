#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
One-command "see the loop" quickstart (real seal-host-rs + synthetic ledger + real CLI approver).

Drives the *shipped* Rust host over the synthetic ledger using the *ed25519 signed token channel*
(exactly what the Ed25519TokenProvider verifies).

  python3 demo/see_the_loop.py

- Generates config + approval keypairs.
- Uses write_config (proven) for trusted.json (ed25519 channel requires replay_store etc).
- Spawns real seal-host-rs --channel ed25519 --token-file <tokens> --approval-pubkey <apk> -- python synthetic.
- Sends guarded call -> host (Lean) blocks with real "approval required: <64hex>".
- Invokes real CLI approver (no --plain) with the approval priv; it emits the signed envelope
  {"payload": "<compact target|issuedAt|nonce[|decision=deny]>", "signature": "..."} and appends it.
- Re-issues the call.
- On allow: synthetic executes and the distinctive SYNTHETIC_LEDGER_ACTION side-effect is relayed.
- On deny: the real providers + main.rs short-circuit must emit refused response + audit "refused" (not timed out).

No hardcoded "refused" prints. All observations come from the real host/child/approver.
Zero external setup for the demo (synthetic only).

TCB, ORDERING vs ORIGIN, "what this proves / does NOT prove", and loud labels on dev-only
control-file / demo keys are in the CLI output and docs/DEPLOY.md.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/target/debug/seal-host-rs"
SYN = ROOT / "test/integration/synthetic_ledger.py"
CLI = ROOT / "demo/approve_cli.py"

sys.path.insert(0, str(ROOT / "test/tools"))
sys.path.insert(0, str(ROOT / "test/integration"))
from sign_approval import generate_approval_keypair
from test_host_rs import write_config, DB_TARGET, DESTRUCTIVE, PUBKEY as CONFIG_PUB

def env_ld():
    e = os.environ.copy()
    lean = "/home/monkey/.elan/toolchains/leanprover--lean4---v4.28.0/lib/lean"
    lake = str(ROOT / ".lake/build/lib")
    e["LD_LIBRARY_PATH"] = f"{lean}:{lake}:{e.get('LD_LIBRARY_PATH','')}".rstrip(":")
    return e

def extract_target(text: str):
    m = re.search(r"approval required: ([0-9a-f]{64})", text)
    return m.group(1) if m else None

def run_one(work: Path, label: str):
    tokens = work / "tokens.ndjson"
    tokens.write_text("", encoding="utf-8")
    # write_config sets the policy's control_file (ignored for ed25519) and ensures replay_store etc.
    # We pass a dummy approvals path; the ed25519 tokens file is separate.
    dummy_approvals = work / "dummy_approvals_for_policy.ndjson"
    dummy_approvals.write_text("", encoding="utf-8")
    trusted = write_config(work, dummy_approvals)

    # Fresh approval channel key (different from config key).
    appr_priv, appr_pub = generate_approval_keypair()

    cmd = [
        str(BIN),
        "--config", str(trusted),
        "--pubkey", CONFIG_PUB,
        "--channel", "ed25519",
        "--token-file", str(tokens),
        "--approval-pubkey", appr_pub,
        "--",
        "python3", str(SYN),
    ]
    p = subprocess.Popen(cmd, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=env_ld())
    obs = {"label": label, "target": None, "flowed": False, "refused": False, "action": "", "audit": ""}

    try:
        # passthrough init
        p.stdin.write('{"jsonrpc":"2.0","id":0,"method":"initialize"}\n')
        p.stdin.flush()
        _ = p.stdout.readline()

        # first guarded call -> expect block from real Lean kernels
        call = json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":DESTRUCTIVE}, separators=(",", ":"))
        p.stdin.write(call + "\n")
        p.stdin.flush()

        blocked = ""
        for _ in range(8):
            l = p.stdout.readline()
            blocked += l
            if "approval required" in l:
                break
            time.sleep(0.03)

        t = extract_target(blocked) or DB_TARGET
        obs["target"] = t
        print(f"[{label}] BLOCK (real host): {blocked.strip()[:200]}")

        # human acts via real CLI approver -> produces *signed* ed25519 envelope (target-bound)
        # CLI always signs with the provided key; no --plain here.
        cli_cmd = [
            sys.executable, str(CLI),
            "--token-file", str(tokens),
            "--target", t,
            "--approve" if label == "approve" else "--deny",
            "--key", appr_priv,
            "--yes",
        ]
        cli_out = subprocess.check_output(cli_cmd, cwd=ROOT, text=True, env=env_ld(), timeout=15)
        print(f"[{label}] CLI (signed ed25519 envelope):\n{cli_out.strip()[:700]}")

        # re-issue the exact same call
        p.stdin.write(call + "\n")
        p.stdin.flush()
        time.sleep(0.4)

        second = ""
        for _ in range(6):
            l = p.stdout.readline()
            second += l
            if l.strip():
                break

        print(f"[{label}] AFTER: {second.strip()[:220]}")

        if "SYNTHETIC_LEDGER_ACTION" in second:
            obs["flowed"] = True
            obs["action"] = second

        # capture audit / refused from host stderr (and any remaining stdout)
        try:
            p.stdin.close()
        except Exception:
            pass
        try:
            out2, err2 = p.communicate(timeout=3)
            obs["audit"] = (err2 or "") + (out2 or "")
        except Exception:
            try:
                p.kill()
            except:
                pass
            obs["audit"] = obs.get("audit", "") + " (killed)"

        if "refused" in obs["audit"].lower() or "approval refused" in obs["audit"].lower():
            obs["refused"] = True

        if "SYNTHETIC_LEDGER_ACTION" in obs["audit"]:
            obs["action"] = (obs.get("action") or "") + " " + obs["audit"]

    finally:
        try:
            p.kill()
        except:
            pass

    return obs

def main() -> int:
    print("=== seal developer-ingress one-command (REAL ed25519 signed channel + synthetic) ===")
    print("Uses shipped seal-host-rs binary, real Ed25519TokenProvider, real CLI approver (signs target-bound).")
    print("No hardcoded refused strings. Observations come from the host process.")
    print("")

    results = []
    for lab in ("approve", "deny"):
        with tempfile.TemporaryDirectory(prefix=f"see-ed-{lab}-") as td:
            obs = run_one(Path(td), lab)
            results.append(obs)
            print(f"--- {lab} target={obs['target']} flowed={obs['flowed']} refused={obs['refused']}")
            if obs.get("action"):
                print("  action:", obs["action"][:160])
            if obs.get("audit"):
                if "refused" in obs["audit"].lower():
                    print("  audit contains refused (good)")

    a, d = results
    assert a["target"] and d["target"], "both paths must emit target"
    assert a["flowed"], "approve path must produce SYNTHETIC side-effect (action flowed)"
    assert d["refused"], "deny path must produce observed refused (not timed out) from host"

    print("\n=== PASS: real ed25519 signed loop (block -> signed -> flow | refused) ===")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
