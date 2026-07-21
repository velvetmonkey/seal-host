#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail a release on stale pins, leaked secrets, identity residue, or missing licences."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_KERNEL = "d7d81e277ba0b5e9df385129d86abf6f7469e6da2a65bb2ec35626caa44ea2be"
STALE_KERNELS = ("df42cbada2297741bfeab99f222b96ac02e43a4ce8695b24922b425b8d66b1e8", "ebd17c14")
SECRET_PATTERNS = {
    "GitHub token": re.compile(rb"gh[opsu]_[A-Za-z0-9]{30,}"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS key": re.compile(rb"AKIA[0-9A-Z]{16}"),
}
TEXT_SUFFIXES = {".c", ".cjs", ".css", ".html", ".js", ".json", ".lean", ".md", ".mjs", ".py", ".rs", ".sh", ".toml", ".txt", ".yml", ".yaml"}


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
        is_gate = path.relative_to(ROOT) == Path("scripts/release_policy_gate.py")
        if path.relative_to(ROOT) == Path("receipt-verifier/wasm/seal.wasm"):
            actual = hashlib.sha256(data).hexdigest()
            if actual != EXPECTED_KERNEL:
                failures.append(f"{path.relative_to(ROOT)} has kernel {actual}")
        if path.suffix in TEXT_SUFFIXES or path.name in {"Dockerfile", "Dockerfile.release"}:
            if not is_gate:
                for stale in STALE_KERNELS:
                    if stale.encode() in data:
                        failures.append(f"{path.relative_to(ROOT)} mentions stale kernel {stale}")
            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(data):
                    failures.append(f"{path.relative_to(ROOT)} contains a possible {label}")
            if not is_gate and path.suffix != ".lean" and b"/home/monkey/" in data:
                failures.append(f"{path.relative_to(ROOT)} contains a workstation identity path")
    if failures:
        raise SystemExit("release policy gate failed:\n  " + "\n  ".join(failures))
    print(f"PASS release policy gate ({len(files)} tracked files)")


if __name__ == "__main__":
    main()
