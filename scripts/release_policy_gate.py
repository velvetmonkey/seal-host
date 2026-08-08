#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail a release on stale pins, leaked secrets, identity residue, or missing licences."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_KERNEL = "28bb3ae71985357163e3b651791e2a70c462ea5d1313a59b4967d4c20ea77657"
STALE_KERNELS = ("df42cbada2297741bfeab99f222b96ac02e43a4ce8695b24922b425b8d66b1e8", "ebd17c14")
SECRET_PATTERNS = {
    "GitHub token": re.compile(rb"gh[opsu]_[A-Za-z0-9]{30,}"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS key": re.compile(rb"AKIA[0-9A-Z]{16}"),
}
TEXT_SUFFIXES = {".c", ".cjs", ".css", ".html", ".js", ".json", ".lean", ".md", ".mjs", ".py", ".rs", ".sh", ".toml", ".txt", ".yml", ".yaml"}

# These are measured, historical records. Rewriting their recorded workstation
# paths would falsify the evidence, so exempt only the exact reviewed bytes.
# Any future edit invalidates the exemption and requires an explicit review.
IDENTITY_HISTORY_ALLOWLIST = {
    Path("demo/RUN-STATE.md"): "047f931a195dbe18a4ca9af0fb6354ae9d4938aeaffca747d022149856060094",
    Path("docs/V31-DOWNSTREAM-PARSER-AGREEMENT.md"): "5556ff5528de5cb33a5b82c2b5301a056b5ec889496c16be5c73f1c4409e0e32",
    Path("evidence/reachability-v0/RUN.md"): "5e17b859e045d5677ea0e947b1cfc48796f06b7ffda8efea9c14c39ce6f092b4",
    Path("wasm-spike/verified/PROVENANCE.txt"): "178b0b133ce1a2a3f7caef93e12f59232dfecdcca23ea8998db74cd7b5de952f",
}

# These exact lines are append-only/superseded pin history, not active pins.
# Allowing a path or hash wholesale would let a stale value escape elsewhere.
STALE_KERNEL_HISTORY_LINES = {
    (
        Path("demo/golden_path_filesystem.py"),
        b"# 0db03efd27fc3775988d5e4bd527d8e6206b6c47 -> df42cbada2297741bfeab99f222b96ac02e43a4ce8695b24922b425b8d66b1e8",
    ),
    (
        Path("wasm-spike/verified/PROVENANCE.txt"),
        b"  0db03efd27fc3775988d5e4bd527d8e6206b6c47 -> df42cbada2297741bfeab99f222b96ac02e43a4ce8695b24922b425b8d66b1e8",
    ),
    (
        Path("wasm-spike/verified/pin-history.json"),
        b'      "kernel_sha256": "df42cbada2297741bfeab99f222b96ac02e43a4ce8695b24922b425b8d66b1e8",',
    ),
}


def tracked() -> list[Path]:
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).split(b"\0")
    return [ROOT / name.decode() for name in names if name]


def main() -> None:
    failures: list[str] = []
    files = tracked()
    for required in ("LICENSE", "NOTICE", "SECURITY.md"):
        if ROOT / required not in files:
            failures.append(f"missing tracked {required}")
    for path in files:
        data = path.read_bytes()
        relative = path.relative_to(ROOT)
        is_gate = relative == Path("scripts/release_policy_gate.py")
        if relative == Path("receipt-verifier/wasm/seal.wasm"):
            actual = hashlib.sha256(data).hexdigest()
            if actual != EXPECTED_KERNEL:
                failures.append(f"{path.relative_to(ROOT)} has kernel {actual}")
        if path.suffix in TEXT_SUFFIXES or path.name in {"Dockerfile", "Dockerfile.release"}:
            if not is_gate:
                for stale in STALE_KERNELS:
                    stale_bytes = stale.encode()
                    stale_lines = [line for line in data.splitlines() if stale_bytes in line]
                    allowed_lines = {
                        line
                        for allowed_path, line in STALE_KERNEL_HISTORY_LINES
                        if allowed_path == relative and stale_bytes in line
                    }
                    if any(line not in allowed_lines for line in stale_lines):
                        failures.append(f"{relative} mentions stale kernel {stale}")
            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(data):
                    failures.append(f"{path.relative_to(ROOT)} contains a possible {label}")
            if not is_gate and path.suffix != ".lean" and b"/home/monkey/" in data:
                allowed_digest = IDENTITY_HISTORY_ALLOWLIST.get(relative)
                if allowed_digest is None or hashlib.sha256(data).hexdigest() != allowed_digest:
                    failures.append(f"{relative} contains a workstation identity path")
    if failures:
        raise SystemExit("release policy gate failed:\n  " + "\n  ".join(failures))
    print(f"PASS release policy gate ({len(files)} tracked files)")


if __name__ == "__main__":
    main()
