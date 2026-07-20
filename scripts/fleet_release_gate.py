#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check out the locked public fleet, run its suites, and verify its kernel copies."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "release/fleet-lock.json"
EXPECTED_REPOSITORIES = {
    "seal-check",
    "seal-assurance-kit",
    "seal-verify-action",
    "seal-demo",
    "seal-live-demo",
}
HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")


def reject(message: str) -> None:
    raise SystemExit(f"fleet lock rejected: {message}")


def load_lock(path: Path = LOCK_PATH) -> dict[str, object]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        reject(f"cannot read {path}: {error}")
    if not raw.strip():
        reject(f"{path} is empty")
    try:
        lock = json.loads(raw)
    except json.JSONDecodeError as error:
        reject(f"{path} is not valid JSON: {error}")
    if not isinstance(lock, dict):
        reject("top level must be an object")
    expected_keys = {"schema", "kernel_sha256", "repositories"}
    if set(lock) != expected_keys:
        reject(f"top-level keys must be exactly {sorted(expected_keys)}")
    if lock["schema"] != 1:
        reject("schema must be 1")
    kernel = lock["kernel_sha256"]
    if not isinstance(kernel, str) or HEX_64.fullmatch(kernel) is None:
        reject("kernel_sha256 must be 64 lowercase hexadecimal characters")
    repositories = lock["repositories"]
    if not isinstance(repositories, dict) or set(repositories) != EXPECTED_REPOSITORIES:
        reject(f"repositories must be exactly {sorted(EXPECTED_REPOSITORIES)}")
    for name, entry in repositories.items():
        if not isinstance(entry, dict) or set(entry) != {"url", "commit", "wasm"}:
            reject(f"{name} keys must be exactly ['commit', 'url', 'wasm']")
        url = entry["url"]
        commit = entry["commit"]
        wasm = entry["wasm"]
        if not isinstance(url, str) or not url.startswith("https://") or not url.endswith(".git"):
            reject(f"{name}.url must be an HTTPS git URL")
        if not isinstance(commit, str) or HEX_40.fullmatch(commit) is None:
            reject(f"{name}.commit must be 40 lowercase hexadecimal characters")
        if not isinstance(wasm, list) or not wasm or not all(isinstance(item, str) for item in wasm):
            reject(f"{name}.wasm must be a non-empty string list")
        for relative in wasm:
            candidate = Path(relative)
            if candidate.is_absolute() or ".." in candidate.parts:
                reject(f"{name}.wasm contains a non-relative path")
    return lock


def run(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    print(f"+ ({cwd.name}) {' '.join(command)}", flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def clone_fleet(parent: Path, lock: dict[str, object]) -> None:
    local_root = os.environ.get("SEAL_FLEET_LOCAL_ROOT")
    for name, entry in lock["repositories"].items():
        target = parent / name
        source = Path(local_root, name) if local_root else entry["url"]
        run(["git", "clone", "--quiet", "--no-checkout", str(source), str(target)], parent)
        run(["git", "checkout", "--quiet", "--detach", entry["commit"]], target)
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
        if actual != entry["commit"]:
            raise SystemExit(f"{name}: expected {entry['commit']}, got {actual}")


def check_pins(parent: Path, lock: dict[str, object]) -> None:
    expected = lock["kernel_sha256"]
    for name, entry in lock["repositories"].items():
        for relative in entry["wasm"]:
            path = parent / name / relative
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected:
                raise SystemExit(f"{name}/{relative}: kernel {actual}, expected {expected}")
            print(f"PASS kernel {name}/{relative} {actual}")


def run_suites(parent: Path) -> None:
    check = parent / "seal-check"
    for command in [
        ["node", "--check", "app.js"], ["node", "--check", "receipt.js"],
        *[["node", f"test/{name}"] for name in (
            "receipt-format.test.cjs", "receipt-harness.cjs", "cross-receipt.test.cjs",
            "receipt-verify.test.cjs", "unparseable-forge.test.cjs",
            "pathological-number.test.cjs", "verify-profile.test.cjs")],
        ["node", "scripts/claims-drift.mjs"],
    ]:
        run(command, check)

    assurance = parent / "seal-assurance-kit"
    run(["npm", "test"], assurance)

    action = parent / "seal-verify-action"
    run(["npm", "test"], action)
    run(["node", "scripts/claims-drift.mjs"], action)

    demo = parent / "seal-demo"
    for command in [
        ["node", "test/receipt-format.test.mjs"],
        ["node", "test/pathological-number.test.cjs"],
        ["node", "test/verify-profile.test.mjs"],
        ["node", "scripts/regenerate-fixtures.cjs", "--check"],
        ["node", "scripts/verify-migration.cjs"],
        ["node", "scripts/claims-drift.mjs"],
    ]:
        run(command, demo)

    live = parent / "seal-live-demo"
    for test in (
        "gateway-signed-config.cjs", "local-harness.cjs", "pathological-number.cjs",
        "receipt-format-unparseable.cjs", "verify-profile.cjs",
    ):
        run(["node", f"test/{test}"], live)
    run(["node", "scripts/claims-drift.mjs"], live)
    run(["docker", "compose", "config", "--quiet"], live)

    env = os.environ.copy()
    env["SEAL_FLEET_ROOT"] = str(parent)
    run(["node", "test/fleet-copy-differential.cjs"], assurance, env)
    run(["node", "test/fleet-verify-differential.cjs"], assurance, env)


def main() -> None:
    validate_only = sys.argv[1:] == ["--validate-lock"]
    if sys.argv[1:] and not validate_only:
        raise SystemExit("usage: fleet_release_gate.py [--validate-lock]")
    lock = load_lock()
    if validate_only:
        print(f"PASS fleet lock validation: {LOCK_PATH}")
        return
    if shutil.which("node") is None or shutil.which("docker") is None:
        raise SystemExit("fleet gate requires node and docker compose")
    with tempfile.TemporaryDirectory(prefix="seal-fleet-") as temporary:
        fleet = Path(temporary)
        clone_fleet(fleet, lock)
        check_pins(fleet, lock)
        run_suites(fleet)
    print("PASS locked fleet release gate")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
