#!/usr/bin/env python3
"""Compile a Cargo test, then run the exact fresh artifact Cargo reported."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path


def run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=capture, check=False)


def main() -> int:
    os.environ["PATH"] = "/home/monkey/.cargo/bin:" + os.environ.get("PATH", "")
    args = sys.argv[1:]
    force = bool(args and args[0] == "--force")
    if force:
        args = args[1:]
    if not args:
        print(
            "usage: scripts/cargo-test-prove-build.sh [--force] "
            "<cargo test arguments...>",
            file=sys.stderr,
        )
        return 64

    if "--" in args:
        separator = args.index("--")
        cargo_args = args[:separator]
        test_args = args[separator + 1 :]
    else:
        cargo_args = args
        test_args = []

    try:
        test_index = cargo_args.index("--test")
        test_name = cargo_args[test_index + 1]
    except (ValueError, IndexError):
        print("REFUSED: --test NAME is required", file=sys.stderr)
        return 64

    # Cargo's positional test filter belongs to the test executable, not to
    # the compile-only phase. Keep it out of `cargo test --no-run` and pass it
    # to the exact artifact below.
    compile_args = list(cargo_args)
    filter_arg: list[str] = []
    filter_index = test_index + 2
    if filter_index < len(compile_args) and not compile_args[filter_index].startswith("-"):
        filter_arg = [compile_args.pop(filter_index)]

    repository_root = Path(__file__).resolve().parent.parent
    manifest = str(repository_root / "rust/Cargo.toml")
    if "--manifest-path" in cargo_args:
        manifest_index = cargo_args.index("--manifest-path")
        if manifest_index + 1 < len(cargo_args):
            manifest = str(Path(cargo_args[manifest_index + 1]).resolve())
    else:
        compile_args = ["--manifest-path", manifest, *compile_args]

    if force:
        cleaned = run(["cargo", "clean", "--manifest-path", manifest, "-p", "seal-host-rs"])
        if cleaned.returncode:
            return cleaned.returncode

    compile_command = [
        "cargo",
        "test",
        "--no-run",
        "--message-format=json",
        *compile_args,
    ]
    compiled = run(compile_command, capture=True)
    sys.stderr.write(compiled.stderr)
    if compiled.returncode:
        return compiled.returncode

    fresh_artifact: str | None = None
    stale_artifact: str | None = None
    for line in compiled.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target", {})
        if target.get("name") != test_name or "test" not in target.get("kind", []):
            continue
        executable = message.get("executable")
        if not executable:
            continue
        if message.get("fresh") is False:
            fresh_artifact = executable
        else:
            stale_artifact = executable

    if fresh_artifact is None:
        detail = f" ({stale_artifact})" if stale_artifact else ""
        print(
            "REFUSED: Cargo did not report a fresh compiler-artifact for "
            f"test {test_name}{detail}; test result is untrusted",
            file=sys.stderr,
        )
        return 78

    artifact = Path(fresh_artifact)
    if not artifact.is_file():
        print(f"REFUSED: compiler-artifact executable is missing: {artifact}", file=sys.stderr)
        return 78

    print(f"BUILD PROVEN: Cargo compiler-artifact fresh=false executable={artifact}")
    executed = run([str(artifact), *filter_arg, *test_args], capture=True)
    sys.stdout.write(executed.stdout)
    sys.stderr.write(executed.stderr)
    if executed.returncode:
        return executed.returncode
    if re.search(r"^running\s+0 tests?$", executed.stdout, re.MULTILINE):
        print("REFUSED: test filter matched zero tests", file=sys.stderr)
        return 79
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
