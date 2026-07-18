#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render a doctrine NDJSON trace as TTY text or Markdown."""

import argparse
from pathlib import Path

from doctrine import load_trace, render_markdown, render_tty_event


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--format", choices=["tty", "markdown"], default="tty")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--color", choices=["always", "never"], default="never")
    args = parser.parse_args()
    if args.format == "markdown":
        if args.output is None:
            parser.error("--output is required for Markdown")
        render_markdown(args.trace, args.output)
    else:
        for event in load_trace(args.trace):
            render_tty_event(event, color=args.color == "always")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
