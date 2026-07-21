#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministically scrub workstation identity and reject public-source leaks."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else None
if ROOT is None or not ROOT.is_dir():
    raise SystemExit("usage: public_scrub.py SOURCE_TREE")

EXPECTED_KERNEL = "d7d81e277ba0b5e9df385129d86abf6f7469e6da2a65bb2ec35626caa44ea2be"
TEXT_SUFFIXES = {".c", ".cjs", ".css", ".html", ".js", ".json", ".lean", ".md", ".mjs", ".py", ".rs", ".sh", ".toml", ".txt", ".yml", ".yaml"}
SKIP_DIRS = {".git", ".lake", "node_modules", "target"}
FORBIDDEN_NAMES = {".env", "id_rsa", "id_ed25519"}
SECRETS = {
    "GitHub token": re.compile(rb"gh[opsu]_[A-Za-z0-9]{30,}"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS key": re.compile(rb"AKIA[0-9A-Z]{16}"),
}
HOME = re.compile(r"/home/[A-Za-z0-9._-]+/")

failures: list[str] = []
if not (ROOT / "LICENSE").is_file() or not (ROOT / "NOTICE").is_file():
    failures.append("root LICENSE and NOTICE are required")

for path in sorted(ROOT.rglob("*")):
    relative = path.relative_to(ROOT)
    if any(part in SKIP_DIRS for part in relative.parts):
        continue
    if path.is_dir():
        continue
    if path.name in FORBIDDEN_NAMES or path.suffix.lower() in {".key", ".p12", ".pfx"}:
        failures.append(f"forbidden public filename: {relative}")
        continue
    data = path.read_bytes()
    for label, pattern in SECRETS.items():
        if pattern.search(data):
            failures.append(f"possible {label}: {relative}")
    if path.suffix in TEXT_SUFFIXES or path.name in {"Dockerfile", "Dockerfile.release"}:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            failures.append(f"non-UTF-8 public text file: {relative}")
            continue
        scrubbed = HOME.sub("/workspace/operator/", text)
        if scrubbed != text:
            path.write_text(scrubbed, encoding="utf-8")

kernel = ROOT / "receipt-verifier/wasm/seal.wasm"
if not kernel.is_file():
    failures.append("missing public verifier kernel")
elif hashlib.sha256(kernel.read_bytes()).hexdigest() != EXPECTED_KERNEL:
    failures.append("public verifier kernel pin mismatch")

if failures:
    raise SystemExit("public scrub failed:\n  " + "\n  ".join(failures))
print("PASS deterministic public scrub, leak scan, licence check, and kernel pin")
