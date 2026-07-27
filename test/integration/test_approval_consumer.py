#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
External consumer test (outside approver modules) — two explicit steps, zero fallbacks.

Step A (provider): run the unit test that exercises the real Ed25519TokenProvider
with signed allow + decline lines. Print full output. Fail if not ok.

Step A' (provider, cross-language): sign allow + decline NDJSON with the REAL
Python signer (sign_approval.py) and feed the file to the REAL
Ed25519TokenProvider via rust/tests/python_signed_provider.rs — asserts
1 record, 1 decline, 0 warnings. Closes the 0011268d gap (Step A self-signs
in Rust; Python-signed bytes never previously reached the provider).

Step B (host short-circuit): call the canonical run_signed_ed25519_loop(allow=False)
with matching tool args, assert the explicit "approval refused (signed decline" string
is present in combined stdout+stderr, print the full transcript.

Step B' (host allow path): run_signed_ed25519_loop(allow=True) — assert the
python-signed approval makes the identical call FLOW, full transcript printed.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "test" / "integration"))
from approval_loop import run_signed_ed25519_loop  # noqa: E402


def main() -> int:
    ROOT = Path(__file__).resolve().parents[2]

    print("=== Step A: real Ed25519TokenProvider unit test ===")
    env = os.environ.copy()
    lean_prefix = subprocess.check_output(["lean", "--print-prefix"], text=True).strip()
    lean = str(Path(lean_prefix) / "lib" / "lean")
    lake = str(ROOT / ".lake/build/lib")
    env["LIBRARY_PATH"] = f"{lean}:{lake}:{env.get('LIBRARY_PATH', '')}".rstrip(":")
    env["LD_LIBRARY_PATH"] = f"{lean}:{lake}:{env.get('LD_LIBRARY_PATH', '')}".rstrip(":")
    res = subprocess.run(
        ["cargo", "test", "ed25519_provider_accepts_signed_decline_and_allow", "--lib"],
        cwd=ROOT / "rust",
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    print(res.stdout)
    print(res.stderr)
    if res.returncode != 0 or "FAILED" in res.stdout or "FAILED" in res.stderr:
        print("Step A FAILED")
        return 1
    print("Step A OK (real provider accepted signed allow + decline)")

    print("\n=== Step A': real provider consumes PYTHON-signed NDJSON ===")
    # Closes the 0011268d gap: Step A's unit test self-signs in Rust; here the
    # REAL Python signer produces the bytes and the REAL provider consumes them.
    sys.path.insert(0, str(ROOT / "test" / "tools"))
    from sign_approval import (  # noqa: E402
        generate_approval_keypair,
        sign_approval_token,
        sign_approval_v2_token,
    )

    sk_hex, pk_hex = generate_approval_keypair()
    target = "00000000000000000000000000000000000000000000000000000000000000cd"
    decline_nonce = "py-decline-n1"
    allow_line = sign_approval_token(sk_hex, target, 2000, "py-allow-n1", allow=True)
    decline_line = sign_approval_token(sk_hex, target, 2001, decline_nonce, allow=False)
    with tempfile.TemporaryDirectory(prefix="consumer-stepA2-") as td:
        ndjson = Path(td) / "python-signed.ndjson"
        ndjson.write_text(allow_line + "\n" + decline_line + "\n", encoding="utf-8")
        framed_bytes = b'{"integer":1234567890123456789}\n'
        shown_bytes = b"1234567890123456768"
        v2_target = "00000000000000000000000000000000000000000000000000000000000000d2"
        v2_session = "python-v2-session"
        v2_line = sign_approval_v2_token(
            sk_hex,
            target=v2_target,
            authorized_at=2_000,
            expiry=122_000,
            nonce="py-v2-nonce",
            session=v2_session,
            framed_bytes=framed_bytes,
            shown_bytes=shown_bytes,
            renderer_name="python-test-renderer",
            renderer_version="2.0.0",
            renderer_manifest_sha256="ab" * 32,
            approver="python-test-human",
        )
        v2_ndjson = Path(td) / "python-signed-v2.ndjson"
        v2_ndjson.write_text(v2_line + "\n", encoding="utf-8")
        env2 = env.copy()
        env2["SEAL_PY_SIGNED_NDJSON"] = str(ndjson)
        env2["SEAL_PY_SIGNED_PUBKEY"] = pk_hex
        env2["SEAL_PY_SIGNED_TARGET"] = target
        env2["SEAL_PY_SIGNED_DECLINE_NONCE"] = decline_nonce
        env2["SEAL_PY_SIGNED_V2_NDJSON"] = str(v2_ndjson)
        env2["SEAL_PY_SIGNED_V2_TARGET"] = v2_target
        env2["SEAL_PY_SIGNED_V2_SESSION"] = v2_session
        res2 = subprocess.run(
            ["cargo", "test", "--test", "python_signed_provider", "--", "--nocapture"],
            cwd=ROOT / "rust",
            capture_output=True,
            text=True,
            timeout=300,
            env=env2,
        )
        print(res2.stdout)
        print(res2.stderr)
        if res2.returncode != 0 or "FAILED" in res2.stdout or "FAILED" in res2.stderr:
            print("Step A' FAILED")
            return 1
        if "SKIP:" in res2.stdout or "SKIP:" in res2.stderr:
            print("Step A' FAILED: provider test skipped (env vars not seen)")
            return 1
    print(
        "Step A' OK (real provider consumed Python-signed legacy allow + decline "
        "and ApprovalRecord v2)"
    )

    print("\n=== Step B: host short-circuit with signed decline ===")
    with tempfile.TemporaryDirectory(prefix="consumer-stepb-") as td:
        obs = run_signed_ed25519_loop(
            Path(td),
            allow=False,
            tool_name="db.execute",
            tool_args={"database": "prod", "sql": "drop table users"},
        )
        combined = (obs.get("stdout") or "") + "\n" + (obs.get("stderr") or "")
        block = obs.get("block_text") or ""
        print("FULL TRANSCRIPT (stdout + stderr):")
        if block:
            print("INITIAL_BLOCK:", block.strip())
        print(combined)
        if "approval refused (signed decline" not in combined:
            print("Step B FAILED: refused string not found in host output")
            return 1
        print("Step B OK (host emitted explicit refused for signed decline)")

    print("\n=== Step B': host allow path with python-signed approval ===")
    with tempfile.TemporaryDirectory(prefix="consumer-stepb2-") as td:
        obs = run_signed_ed25519_loop(
            Path(td),
            allow=True,
            tool_name="db.execute",
            tool_args={"database": "prod", "sql": "drop table users"},
        )
        combined = (obs.get("stdout") or "") + "\n" + (obs.get("stderr") or "")
        print("FULL TRANSCRIPT (stdout + stderr):")
        if obs.get("block_text"):
            print("INITIAL_BLOCK:", obs["block_text"].strip())
        print(combined)
        if not obs.get("flowed"):
            print("Step B' FAILED: call did not flow after python-signed allow")
            return 1
        if obs.get("refused"):
            print("Step B' FAILED: unexpected refusal on the allow path")
            return 1
    print("Step B' OK (python-signed allow flowed through the real host)")

    print("\nconsumer: SUCCESS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
