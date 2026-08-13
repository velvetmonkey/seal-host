#!/usr/bin/env python3
"""Classify a Lake package-clone outage without disguising real build failures.

Lake resolves pinned packages lazily.  A transient failure while it clones one
is infrastructure: the control never reached the proof or demo it was meant
to check.  This adapter preserves the command's output and exit status, while
exposing that distinction to ``ci_control_aggregate.py`` through step outputs.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


CLONE_URL = re.compile(r"(?:cloning|clone)\s+(https?://\S+)", re.IGNORECASE)
GIT_FAILURE = re.compile(
    r"(?:external command git exited with code 128|fatal:.*(?:unable to access|could not read|repository))",
    re.IGNORECASE,
)


def write_output(name: str, value: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write(f"{name}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    if not arguments.command or arguments.command[0] != "--":
        parser.error("expected -- followed by the Lake-using command")

    command = arguments.command[1:]
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as error:
        print(f"::error::Lean dependency command could not start: {error}")
        return 1

    print(result.stdout, end="")
    url = CLONE_URL.search(result.stdout)
    if result.returncode and url and GIT_FAILURE.search(result.stdout):
        reason = (
            "Lean dependency fetch could not run from "
            f"{url.group(1)}: git clone failed (command exit {result.returncode})"
        )
        print(f"::error::{reason}")
        write_output("unrunnable", "true")
        write_output("unrunnable-reason", reason)
    else:
        write_output("unrunnable", "false")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
