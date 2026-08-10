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

EXPECTED_KERNEL = "28bb3ae71985357163e3b651791e2a70c462ea5d1313a59b4967d4c20ea77657"
TEXT_SUFFIXES = {".c", ".cjs", ".css", ".html", ".js", ".json", ".lean", ".md", ".mjs", ".py", ".rs", ".sh", ".toml", ".txt", ".yml", ".yaml"}
TEXT_NAMES = {"Dockerfile", "Dockerfile.release"}
NON_TEXT_DIRS = (
    Path("rust/tests/corpora/JSONTestSuite").parts,
    Path("vendor/mcp-seal/test/external/vendor/json-testsuite").parts,
)
SKIP_DIRS = {".git", ".lake", "node_modules", "target"}
FORBIDDEN_NAMES = {".env", "id_rsa", "id_ed25519"}
SECRETS = {
    "GitHub token": re.compile(rb"gh[opsu]_[A-Za-z0-9]{30,}"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS key": re.compile(rb"AKIA[0-9A-Z]{16}"),
}
HOME = re.compile(rb"/home/[A-Za-z0-9._-]+/")


def length_safe_home_replacement(match: re.Match[bytes]) -> bytes:
    """Return an anonymous absolute path exactly as long as the HOME match."""
    source_length = len(match.group())
    workspace = b"/workspace/"
    if source_length > len(workspace):
        return workspace + b"x" * (source_length - len(workspace) - 1) + b"/"
    return b"/" + b"x" * (source_length - 2) + b"/"

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
    try:
        data = path.read_bytes()
    except OSError as error:
        failures.append(f"unable to classify public file {relative}: {error}")
        continue

    try:
        data.decode("utf-8")
        is_utf8 = True
    except UnicodeDecodeError:
        is_utf8 = False

    for label, pattern in SECRETS.items():
        if pattern.search(data):
            failures.append(f"possible {label}: {relative}")

    is_declared_text = path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES
    is_corpus = any(relative.parts[: len(directory)] == directory for directory in NON_TEXT_DIRS)
    if is_declared_text and not is_corpus and not is_utf8:
        failures.append(f"non-UTF-8 public text file: {relative}")

    home_matches = list(HOME.finditer(data))
    if home_matches and (b"\x00" in data or not is_utf8):
        kind = "NUL-bearing" if b"\x00" in data else "non-UTF-8"
        for match in home_matches:
            failures.append(
                f"refusing HOME rewrite in {kind} file: {relative} "
                f"at byte offset {match.start()}"
            )
    elif home_matches:
        rewritten = HOME.sub(length_safe_home_replacement, data)
        if len(rewritten) != len(data):
            failures.append(f"HOME rewrite changed byte length: {relative}")
        else:
            path.write_bytes(rewritten)

kernel = ROOT / "receipt-verifier/wasm/seal.wasm"
if not kernel.is_file():
    failures.append("missing public verifier kernel")
elif hashlib.sha256(kernel.read_bytes()).hexdigest() != EXPECTED_KERNEL:
    failures.append("public verifier kernel pin mismatch")

if failures:
    raise SystemExit("public scrub failed:\n  " + "\n  ".join(failures))
print("PASS deterministic public scrub, leak scan, licence check, and kernel pin")
