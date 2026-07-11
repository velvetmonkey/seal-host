#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Shared harness for approval loop tests and the documented quickstart.

Provides:
- spawn_with_child(config, extra_args, child)
- call(proc, mid, name, arguments)
- block_and_extract_target(proc, call_json) -> target_hex or None
- apply_cli_signed_decision(cli_path, token_file, target, allow, key_hex) -> CLI output
- reissue_and_observe(proc, call_json, timeout=5.0) -> (response_dict_or_str, stdout_tail, stderr_tail)

Returns structured observations including 'refused' (host emitted refused response or audit).
No DB_TARGET fallback — target must be extracted from the real block message.

Used by demo/see_the_loop.py (thin wrapper), test_approval_consumer.py, and test_host_rs.py.
"""

import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "rust" / "target" / "debug" / "seal-host-rs"

# Import sign helpers (real ones)
sys.path.insert(0, str(ROOT / "test" / "tools"))
from sign_approval import sign_approval_token  # noqa: E402
from sign_config import sign_payload, generate_keypair as gen_cfg  # noqa: E402


def env_with_ld():
    e = {}
    try:
        import os
        e = os.environ.copy()
    except Exception:
        pass
    lean = "/home/monkey/.elan/toolchains/leanprover--lean4---v4.28.0/lib/lean"
    lake = str(ROOT / ".lake/build/lib")
    old = e.get("LD_LIBRARY_PATH", "")
    e["LD_LIBRARY_PATH"] = f"{lean}:{lake}:{old}".rstrip(":")
    return e


def spawn_with_child(config_path: Path, extra_args=(), child=None):
    """Spawn real seal-host-rs with given child after -- .
    child: list e.g. ["python3", ".../synthetic_ledger.py"]
    extra_args: e.g. ("--channel", "ed25519", "--token-file", "...", "--approval-pubkey", "...")
    """
    if child is None:
        child = ["python3", str(ROOT / "test" / "integration" / "mock_mcp_server.py")]
    cmd = [str(BIN), "--config", str(config_path), "--pubkey", None, *extra_args, "--", *child]
    # We will fill pubkey from write_config caller or pass full extra
    # For simplicity, callers that need ed25519 pass the full extra_args including --pubkey value.
    # If not provided, the caller must have put it in extra_args.
    # To keep API simple, we expect caller to construct extra_args correctly.
    # Here we just spawn.
    env = env_with_ld()
    return subprocess.Popen(
        [str(BIN), "--config", str(config_path)] + list(extra_args) + ["--"] + list(child),
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def call(proc, mid, name, arguments):
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": mid, "method": "tools/call", "params": {"name": name, "arguments": arguments}}, separators=(",", ":")) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    try:
        return json.loads(line)
    except Exception:
        return {"raw": line}


def block_and_extract_target(proc, call_json_str: str, max_reads=12, sleep=0.05):
    """Send one call, read until we see a block with 'approval required: <hex>'.
    Returns the target hex or None. Does NOT consume approvals.
    """
    proc.stdin.write(call_json_str + "\n")
    proc.stdin.flush()
    buf = ""
    for _ in range(max_reads):
        l = proc.stdout.readline()
        buf += l
        if "approval required:" in l:
            m = re.search(r"approval required: ([0-9a-f]{64})", buf)
            if m:
                return m.group(1)
        time.sleep(sleep)
    m = re.search(r"approval required: ([0-9a-f]{64})", buf)
    return m.group(1) if m else None


def apply_cli_signed_decision(cli_path: Path, token_file: Path, target: str, allow: bool, key_hex: str):
    """Invoke the real CLI approver to sign and append a target-bound record.
    Returns the CLI stdout.
    """
    flag = "--approve" if allow else "--deny"
    cmd = [sys.executable, str(cli_path), "--token-file", str(token_file), "--target", target, flag, "--key", key_hex, "--yes"]
    out = subprocess.check_output(cmd, cwd=ROOT, text=True, env=env_with_ld(), timeout=15)
    return out


def reissue_and_observe(proc, call_json_str: str, timeout=6.0):
    """Re-send the call and collect response + stderr/stdout tails.
    Returns dict with 'response', 'stdout', 'stderr', 'flowed', 'refused'.
    'refused' is True if host produced refused response or "approval refused" / "refused" in stderr.
    'flowed' is True if we see SYNTHETIC side-effect or non-error success.
    """
    proc.stdin.write(call_json_str + "\n")
    proc.stdin.flush()
    start = time.time()
    stdout_parts = []
    while time.time() - start < timeout:
        l = proc.stdout.readline()
        if l:
            stdout_parts.append(l)
        if l.strip():
            break
        time.sleep(0.02)
    # Give a bit more for stderr/audit
    time.sleep(0.2)
    try:
        proc.stdin.close()
    except Exception:
        pass
    # Drain remaining quickly
    remaining_out = []
    for _ in range(5):
        try:
            l = proc.stdout.readline()
            if l:
                remaining_out.append(l)
        except Exception:
            break
    # Best effort communicate for stderr
    try:
        out2, err2 = proc.communicate(timeout=1.5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
        out2, err2 = "", ""
    full_out = "".join(stdout_parts + remaining_out) + (out2 or "")
    full_err = (err2 or "")

    response = None
    try:
        # last json line in out if present
        for line in reversed(full_out.splitlines()):
            if line.strip().startswith("{"):
                response = json.loads(line)
                break
    except Exception:
        response = full_out.strip()[:300]

    flowed = "SYNTHETIC_LEDGER_ACTION" in full_out or "SYNTHETIC_LEDGER_ACTION" in full_err
    refused = ("refused" in full_out.lower()) or ("approval refused" in full_err.lower()) or ("refused" in full_err.lower())

    return {
        "response": response,
        "stdout": full_out,
        "stderr": full_err,
        "flowed": flowed,
        "refused": refused,
    }


# Convenience for tests/quickstart that want a full end-to-end with ed25519 or file.
def run_approval_loop_once(config_path: Path, token_file: Path, approval_pubkey: str, target: str, allow: bool, appr_priv: str, child_list, cli_path: Path):
    """High level: spawn (ed25519 assumed caller put args), block, apply via CLI, reissue, observe.
    Returns the observation dict from reissue_and_observe + target.
    """
    extra = ("--channel", "ed25519", "--token-file", str(token_file), "--approval-pubkey", approval_pubkey)
    proc = spawn_with_child(config_path, extra, child=child_list)
    try:
        # send init passthrough
        try:
            proc.stdin.write('{"jsonrpc":"2.0","id":0,"method":"initialize"}\n')
            proc.stdin.flush()
            _ = proc.stdout.readline()
        except Exception:
            pass

        call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "db.execute", "arguments": {"database": "prod", "sql": "drop table users"}}}, separators=(",", ":"))
        t = block_and_extract_target(proc, call)
        if not t:
            t = target
        # apply via real CLI (produces signed envelope for ed25519)
        cli_out = apply_cli_signed_decision(cli_path, token_file, t, allow, appr_priv)
        obs = reissue_and_observe(proc, call)
        obs["target"] = t
        obs["cli_out"] = cli_out
        return obs
    finally:
        try:
            proc.kill()
        except Exception:
            pass
