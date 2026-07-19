#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check out the locked public fleet, run its suites, and verify its kernel copies."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "release/fleet-lock.json").read_text())


def run(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    print(f"+ ({cwd.name}) {' '.join(command)}", flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def clone_fleet(parent: Path) -> None:
    local_root = os.environ.get("SEAL_FLEET_LOCAL_ROOT")
    for name, entry in LOCK["repositories"].items():
        target = parent / name
        source = Path(local_root, name) if local_root else entry["url"]
        run(["git", "clone", "--quiet", "--no-checkout", str(source), str(target)], parent)
        run(["git", "checkout", "--quiet", "--detach", entry["commit"]], target)
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
        if actual != entry["commit"]:
            raise SystemExit(f"{name}: expected {entry['commit']}, got {actual}")


def check_pins(parent: Path) -> None:
    expected = LOCK["kernel_sha256"]
    for name, entry in LOCK["repositories"].items():
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
    if shutil.which("node") is None or shutil.which("docker") is None:
        raise SystemExit("fleet gate requires node and docker compose")
    with tempfile.TemporaryDirectory(prefix="seal-fleet-") as temporary:
        fleet = Path(temporary)
        clone_fleet(fleet)
        check_pins(fleet)
        run_suites(fleet)
    print("PASS locked fleet release gate")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
