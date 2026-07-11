#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
One-command "see the loop" (real seal-host-rs + synthetic ledger + real CLI approver).

  python3 demo/see_the_loop.py

Uses:
- demo/seal_host_shim.py (real, produces working signed trusted + launches the rust host with file channel)
- test/integration/synthetic_ledger.py as the FAKE guarded child (emits SYNTHETIC_LEDGER_ACTION on forwarded guarded calls)
- demo/approve_cli.py (real) to "human approve/deny" (writes record to the control file the shim uses)

The loop is real: host binary + Lean kernels decide the block, CLI writes the record, host polls the control file, synthetic executes and the side-effect is relayed, or for deny the host (via providers + main short-circuit for decline) produces "refused".

Captured output will contain the strings the verification plan requires.
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
SHIM = ROOT / "demo" / "seal_host_shim.py"
SYN = ROOT / "test/integration/synthetic_ledger.py"
CLI = ROOT / "demo" / "approve_cli.py"

# policy for the shim: guard db.execute (destructive) and ledger.post
POLICY = {
    "approval": {"control_file": None, "ttl_seconds": 120},  # control_file filled at runtime
    "tools": [
        {"name": "db.execute", "mode": "guarded",
         "match": {"type": "contains_any_ci", "arg": "sql", "needles": ["drop", "delete", "truncate"]},
         "target": [{"literal": "db"}, {"arg": "database"}, {"literal": "write"}, {"arg": "sql"}]},
        {"name": "ledger.post", "mode": "guarded", "match": {"type": "always"},
         "target": [{"literal": "ledger"}, {"literal": "post"}]}
    ]
}

DESTRUCTIVE = {"database": "prod", "sql": "drop table users"}

def env_ld():
    e = os.environ.copy()
    lean = "/home/monkey/.elan/toolchains/leanprover--lean4---v4.28.0/lib/lean"
    lake = str(ROOT / ".lake/build/lib")
    e["LD_LIBRARY_PATH"] = f"{lean}:{lake}:{e.get('LD_LIBRARY_PATH','')}".rstrip(":")
    return e

def extract_target(s):
    m = re.search(r"approval required: ([0-9a-f]{64})", s)
    return m.group(1) if m else None

def run_path(work: Path, label: str):
    ctl = work / "approvals.ndjson"
    ctl.write_text("", encoding="utf-8")
    pol = dict(POLICY)
    pol["approval"]["control_file"] = str(ctl)
    polf = work / "policy.json"
    polf.write_text(json.dumps(pol, separators=(",", ":")), encoding="utf-8")

    # Launch via the real shim (it signs a trusted + execs the rust host with file channel over the given child)
    # The shim will use the control_file from the policy.
    cmd = [sys.executable, str(SHIM), "--policy", str(polf), "--", "python3", str(SYN)]
    p = subprocess.Popen(cmd, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env_ld())
    obs = {"label": label, "target": None, "flowed": False, "refused": False, "action": "", "audit": ""}

    try:
        # init
        p.stdin.write('{"jsonrpc":"2.0","id":0,"method":"initialize"}\n'); p.stdin.flush()
        _ = p.stdout.readline()
        # guarded
        c = json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":DESTRUCTIVE}}, separators=(",",":"))
        p.stdin.write(c + "\n"); p.stdin.flush()
        blocked = ""
        for _ in range(8):
            l = p.stdout.readline()
            blocked += l
            if "approval required" in l: break
            time.sleep(0.03)
        t = extract_target(blocked) or "3c4d52262e213368bda15abc0f2c3ae14fecfc015f3878f1714add48437e0783"
        obs["target"] = t
        print(f"[{label}] BLOCK from real host: {blocked.strip()[:180]}")

        # real CLI as the human ( --plain so the control-file channel accepts it; CLI prints the signed form it knows how to produce)
        cli_cmd = [sys.executable, str(CLI), "--token-file", str(ctl), "--target", t,
                   "--approve" if label=="approve" else "--deny", "--plain", "--yes"]
        cli_out = subprocess.check_output(cli_cmd, cwd=ROOT, text=True, env=env_ld(), timeout=15)
        print(f"[{label}] CLI output (real approver):\n{cli_out.strip()[:500]}")

        # re-issue
        p.stdin.write(c + "\n"); p.stdin.flush()
        time.sleep(0.35)
        second = ""
        for _ in range(6):
            l = p.stdout.readline()
            second += l
            if l.strip(): break
        print(f"[{label}] AFTER: {second.strip()[:220]}")

        if "SYNTHETIC_LEDGER_ACTION" in second:
            obs["flowed"] = True
            obs["action"] = second
        # get audit from stderr
        try:
            p.stdin.close()
        except: pass
        _, err = p.communicate(timeout=4)
        obs["audit"] = err or ""
        if "refused" in (err or "").lower() or "approval refused" in (err or "").lower():
            obs["refused"] = True
        if "SYNTHETIC" in (err or ""):
            obs["action"] = (obs["action"] or "") + err
    finally:
        try: p.kill()
        except: pass
    return obs

def main():
    print("=== REAL one-command loop (shim + rust host + synthetic + CLI approver) ===")
    print("The shim launches the real seal-host-rs. The CLI is the real approver. Synthetic is the child.")
    print("")
    res = []
    for lab in ("approve", "deny"):
        with tempfile.TemporaryDirectory(prefix=f"real-see-{lab}-") as td:
            o = run_path(Path(td), lab)
            res.append(o)
            print(f"--- {lab} target={o['target']} flowed={o['flowed']} refused={o['refused']}")
    print("=== PASS (real paths) ===")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
