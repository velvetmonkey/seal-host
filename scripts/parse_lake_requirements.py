#!/usr/bin/env python3
"""Parse Lake's require array tables and retain their source line numbers."""

import json
import sys
import tomllib
from pathlib import Path


def require_header_lines(text: str) -> list[int]:
    lines = []
    for number, source_line in enumerate(text.splitlines(), start=1):
        candidate = source_line.strip()
        if not candidate.startswith("[["):
            continue
        closing = candidate.find("]]", 2)
        if closing == -1:
            continue
        if candidate[2:closing].strip() == "require":
            lines.append(number)
    return lines


def main() -> None:
    path = Path(sys.argv[1])
    text = path.read_text(encoding="utf-8")
    document = tomllib.loads(text)
    requirements = document.get("require", [])
    if not isinstance(requirements, list):
        raise ValueError("lakefile.toml require table is not an array")

    lines = require_header_lines(text)
    if len(lines) != len(requirements):
        raise ValueError(
            "could not associate parsed require tables with their source lines "
            f"({len(requirements)} parsed, {len(lines)} headers)"
        )

    result = []
    for line, requirement in zip(lines, requirements):
        result.append({
            "line": line,
            "name": requirement.get("name"),
            "rev": requirement.get("rev"),
        })
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        print(f"lakefile.toml TOML parse failed: {error}", file=sys.stderr)
        raise SystemExit(1)
