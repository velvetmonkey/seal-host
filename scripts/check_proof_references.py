#!/usr/bin/env python3
"""Resolve PROOF-REFERENCE theorem citations against the live axiom gate."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/PROOF-REFERENCE.md"
SYMBOL = r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)+"
DECLARATION = re.compile(r"\b(?:theorem|lemma|def|abbrev)\s+([A-Za-z_][A-Za-z0-9_'.]*)")
GUARD = re.compile(rf"#guard_msgs\s+in\s+#print\s+axioms\s+({SYMBOL})")


def uncomment(text: str) -> str:
    """Remove nested Lean comments while preserving line structure."""
    out: list[str] = []
    depth = 0
    i = 0
    while i < len(text):
        if text.startswith("/-", i):
            depth += 1
            out.extend("  ")
            i += 2
        elif depth and text.startswith("-/", i):
            depth -= 1
            out.extend("  ")
            i += 2
        elif depth:
            out.append("\n" if text[i] == "\n" else " ")
            i += 1
        elif text.startswith("--", i):
            end = text.find("\n", i)
            if end == -1:
                out.extend(" " * (len(text) - i))
                break
            out.extend(" " * (end - i))
            i = end
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def lean_files() -> dict[str, tuple[Path, str]]:
    files: dict[str, tuple[Path, str]] = {}
    for path in ROOT.rglob("*.lean"):
        if ".lake" in path.parts:
            continue
        module = ".".join(path.relative_to(ROOT).with_suffix("").parts)
        files[module] = (path, uncomment(path.read_text(encoding="utf-8")))
    return files


def declaration_index(files: dict[str, tuple[Path, str]]) -> dict[str, set[Path]]:
    declarations: dict[str, set[Path]] = defaultdict(set)
    for path, text in files.values():
        blocks: list[tuple[str, str]] = []
        for line in text.splitlines():
            namespace = re.match(r"\s*namespace\s+([A-Za-z_][A-Za-z0-9_'.]*)", line)
            if namespace:
                blocks.append(("namespace", namespace.group(1)))
                continue
            if re.match(r"\s*section(?:\s+[A-Za-z_][A-Za-z0-9_']*)?\s*$", line):
                blocks.append(("section", ""))
                continue
            if re.match(r"\s*end(?:\s+[A-Za-z_][A-Za-z0-9_'.]*)?\s*$", line):
                if blocks:
                    blocks.pop()
                continue
            prefix = ".".join(name for kind, name in blocks if kind == "namespace")
            for match in DECLARATION.finditer(line):
                name = match.group(1)
                full = f"{prefix}.{name}" if prefix else name
                declarations[full].add(path)
    return declarations


def import_closure(files: dict[str, tuple[Path, str]], root: str) -> set[Path]:
    reached: set[str] = set()
    pending = [root]
    while pending:
        module = pending.pop()
        if module in reached or module not in files:
            continue
        reached.add(module)
        _, text = files[module]
        for line in text.splitlines():
            match = re.match(r"\s*import\s+(.+?)\s*$", line)
            if match:
                pending.extend(match.group(1).split())
    return {files[module][0] for module in reached}


def table_symbols(text: str) -> list[str]:
    header = "| Claim | Theorem symbols | Axiom footprint |"
    lines = text.splitlines()
    try:
        start = lines.index(header) + 2
    except ValueError:
        raise ValueError(f"missing exact table header: {header}") from None
    symbols: list[str] = []
    for line in lines[start:]:
        if not line.startswith("|"):
            break
        cells = line.split("|")[1:-1]
        if len(cells) != 3:
            raise ValueError(f"malformed proof-reference row: {line}")
        row_symbols = re.findall(rf"`({SYMBOL})`", cells[1])
        if not row_symbols:
            raise ValueError(f"proof-reference row has no qualified theorem symbol: {line}")
        symbols.extend(row_symbols)
    return list(dict.fromkeys(symbols))


def main() -> int:
    document = DOC.read_text(encoding="utf-8")
    failures: list[str] = []
    if re.search(r"\.lean:\d+", document):
        failures.append("PROOF-REFERENCE.md contains a hand-maintained .lean:line citation")
    try:
        symbols = table_symbols(document)
    except ValueError as error:
        failures.append(str(error))
        symbols = []

    files = lean_files()
    declarations = declaration_index(files)
    live = import_closure(files, "Test.Axioms")
    pins: dict[str, set[Path]] = defaultdict(set)
    for path, text in files.values():
        for match in GUARD.finditer(text):
            pins[match.group(1)].add(path)

    lake = (ROOT / "lakefile.toml").read_text(encoding="utf-8")
    if not re.search(
        r'\[\[lean_exe\]\]\s*name\s*=\s*"axiom_check"\s*root\s*=\s*"Test\.Axioms"',
        lake,
    ):
        failures.append("lakefile.toml does not bind axiom_check to Test.Axioms")
    defaults = re.search(r"^defaultTargets\s*=\s*\[([^]]*)\]", lake, re.MULTILINE)
    if not defaults or '"axiom_check"' not in defaults.group(1):
        failures.append("axiom_check is not a Lake default target")

    workflows = "\n".join(
        path.read_text(encoding="utf-8")
        for pattern in ("*.yml", "*.yaml")
        for path in (ROOT / ".github/workflows").glob(pattern)
    )
    if "lake exe axiom_check" not in workflows:
        failures.append("no GitHub workflow runs lake exe axiom_check")
    if "python3 scripts/check_proof_references.py" not in workflows:
        failures.append("no GitHub workflow runs the proof-reference checker")

    for symbol in symbols:
        declared = declarations.get(symbol, set())
        guarded = pins.get(symbol, set())
        live_guards = guarded & live
        if not declared:
            failures.append(f"{symbol}: declaration not found")
        if not guarded:
            failures.append(f"{symbol}: guarded #print axioms pin not found")
        elif not live_guards:
            pin_names = ", ".join(str(path.relative_to(ROOT)) for path in sorted(guarded))
            failures.append(f"{symbol}: guarded only outside Test.Axioms closure ({pin_names})")
        if declared and live_guards:
            sources = ", ".join(str(path.relative_to(ROOT)) for path in sorted(declared))
            gates = ", ".join(str(path.relative_to(ROOT)) for path in sorted(live_guards))
            print(f"PASS {symbol}: source {sources}; live guard {gates}")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"proof reference check failed: {len(failures)} error(s)", file=sys.stderr)
        return 1
    print(f"PASS {len(symbols)} proof-reference symbols resolve through the live axiom gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
