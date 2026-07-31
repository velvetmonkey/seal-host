#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail closed when build_core.sh omits a project-local Lean import.

The wasm project object list is deliberately explicit. This gate parses that
list, resolves every listed module to its checked-in Lean source, and walks the
transitive project-local import graph. External package imports are compiled by
the separate package/stdlib portions of the wasm build and are outside this
project MODULES check.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
import sys


ROOT = Path(__file__).resolve().parents[1]
BUILD_CORE = ROOT / "wasm-spike" / "build_core.sh"

# Deliberately below today's inventory of 26 so one omitted module reaches the
# named closure diagnostic instead of being hidden behind the floor. The exact
# value is pinned in test/test_wasm_module_closure_gate.py.
MODULE_COUNT_FLOOR = 25

EXCLUDED_SOURCE_ROOTS = {
    ".git",
    ".lake",
    "node_modules",
    "rust",
    "target",
    "wasm-spike",
}
EXTERNAL_MODULE_ROOTS = {
    "Consensus",
    "Init",
    "Lean",
    "Mathlib",
    "Seal",
    "SealCore",
    "SealV2",
    "Std",
    "Temporal",
    "UnicodeBasic",
}
MODULE_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:/[A-Za-z_][A-Za-z0-9_]*)*$")
IMPORT_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")


class GateError(RuntimeError):
    """The gate could not establish a trustworthy answer."""


@dataclass(frozen=True)
class GateReport:
    parsed_modules: tuple[str, ...]
    closure: tuple[str, ...]
    missing: tuple[str, ...]
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors


def slash_name(module: str) -> str:
    return module.replace(".", "/")


def dotted_name(module: str) -> str:
    return module.replace("/", ".")


def parse_modules(build_core: Path = BUILD_CORE) -> list[str]:
    try:
        lines = build_core.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise GateError(f"cannot read {build_core}: {exc}") from exc

    assignments = [
        (line_number, line)
        for line_number, line in enumerate(lines, start=1)
        if re.match(r"^\s*MODULES\s*(?:\+?=)", line)
    ]
    if not assignments:
        raise GateError(f"cannot parse MODULES array from {build_core}")
    if len(assignments) != 1:
        locations = ", ".join(str(line_number) for line_number, _ in assignments)
        raise GateError(f"multiple MODULES assignments in {build_core}: lines {locations}")

    line_number, line = assignments[0]
    match = re.match(r"^\s*MODULES\s*=\s*\((.*)$", line)
    if not match:
        raise GateError(f"cannot parse MODULES array from {build_core}:{line_number}")
    body: list[str] = []
    remainder = match.group(1)
    if ")" in remainder:
        before, after = remainder.split(")", 1)
        if after.strip() and not after.lstrip().startswith("#"):
            raise GateError(
                f"unexpected text after MODULES array at {build_core}:{line_number}"
            )
        body.append(before)
    else:
        body.append(remainder)
        for continuation_number in range(line_number + 1, len(lines) + 1):
            continuation = lines[continuation_number - 1]
            if ")" in continuation:
                before, after = continuation.split(")", 1)
                if after.strip() and not after.lstrip().startswith("#"):
                    raise GateError(
                        "unexpected text after MODULES array at "
                        f"{build_core}:{continuation_number}"
                    )
                body.append(before)
                break
            body.append(continuation)
        else:
            raise GateError(
                f"unterminated MODULES array beginning at {build_core}:{line_number}"
            )

    try:
        modules = shlex.split("\n".join(body), comments=True, posix=True)
    except ValueError as exc:
        raise GateError(f"cannot parse MODULES array from {build_core}: {exc}") from exc
    invalid = [module for module in modules if not MODULE_TOKEN.fullmatch(module)]
    if invalid:
        raise GateError(f"invalid MODULES entries: {', '.join(invalid)}")
    duplicates = sorted({module for module in modules if modules.count(module) > 1})
    if duplicates:
        raise GateError(f"duplicate MODULES entries: {', '.join(duplicates)}")
    return modules


def project_sources(root: Path = ROOT) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    for path in root.rglob("*.lean"):
        relative = path.relative_to(root)
        if relative.parts[0] in EXCLUDED_SOURCE_ROOTS:
            continue
        module = ".".join(relative.with_suffix("").parts)
        if module in sources:
            raise GateError(f"duplicate Lean source for module {module}")
        sources[module] = path
    return sources


def strip_lean_comments(text: str) -> str:
    """Remove nested Lean comments while preserving line boundaries."""
    output: list[str] = []
    index = 0
    block_depth = 0
    while index < len(text):
        if block_depth:
            if text.startswith("/-", index):
                block_depth += 1
                output.extend("  ")
                index += 2
            elif text.startswith("-/", index):
                block_depth -= 1
                output.extend("  ")
                index += 2
            else:
                output.append("\n" if text[index] == "\n" else " ")
                index += 1
        elif text.startswith("/-", index):
            block_depth = 1
            output.extend("  ")
            index += 2
        elif text.startswith("--", index):
            newline = text.find("\n", index + 2)
            if newline == -1:
                output.extend(" " * (len(text) - index))
                break
            output.extend(" " * (newline - index))
            output.append("\n")
            index = newline + 1
        else:
            output.append(text[index])
            index += 1
    if block_depth:
        raise GateError("unterminated Lean block comment while parsing imports")
    return "".join(output)


def parse_imports(path: Path) -> list[str]:
    try:
        source = strip_lean_comments(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GateError(f"cannot read Lean source {path}: {exc}") from exc
    imports: list[str] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped == "prelude":
            continue
        match = re.match(r"^\s*import(?:\s+(.+?))?\s*$", line)
        if not match:
            # Lean imports form a header before declarations. Stopping here
            # prevents a later string literal containing a line beginning
            # with `import` from being mistaken for dependency syntax.
            break
        tail = match.group(1)
        if not tail:
            raise GateError(f"empty import at {path}:{line_number}")
        modules = tail.split()
        invalid = [module for module in modules if not IMPORT_TOKEN.fullmatch(module)]
        if invalid:
            raise GateError(
                f"cannot parse import at {path}:{line_number}: {' '.join(invalid)}"
            )
        imports.extend(modules)
    return imports


def evaluate(root: Path = ROOT, build_core: Path = BUILD_CORE) -> GateReport:
    parsed_slash = parse_modules(build_core)
    parsed = tuple(dotted_name(module) for module in parsed_slash)
    listed = set(parsed)
    sources = project_sources(root)
    local_roots = {module.split(".", 1)[0] for module in sources}
    errors: list[str] = []

    if len(parsed) < MODULE_COUNT_FLOOR:
        errors.append(
            f"parsed {len(parsed)} MODULES; refusing vacuous wasm import-closure check "
            f"below floor {MODULE_COUNT_FLOOR}"
        )

    queue = list(parsed)
    closure: set[str] = set()
    unresolved: set[tuple[str, str]] = set()
    while queue:
        module = queue.pop()
        if module in closure:
            continue
        path = sources.get(module)
        if path is None:
            unresolved.add((module, "MODULES"))
            continue
        closure.add(module)
        for imported in parse_imports(path):
            if imported in sources:
                queue.append(imported)
            elif imported.split(".", 1)[0] in local_roots:
                unresolved.add((imported, module))
            elif imported.split(".", 1)[0] not in EXTERNAL_MODULE_ROOTS:
                unresolved.add((imported, module))

    for module, importer in sorted(unresolved):
        errors.append(
            f"cannot resolve Lean module {slash_name(module)} imported by {slash_name(importer)}"
        )

    missing = tuple(sorted(closure - listed))
    if missing:
        errors.append(
            "transitive project imports absent from MODULES: "
            + ", ".join(slash_name(module) for module in missing)
        )

    return GateReport(
        parsed_modules=tuple(sorted(parsed)),
        closure=tuple(sorted(closure)),
        missing=missing,
        errors=tuple(errors),
    )


def main() -> int:
    try:
        report = evaluate()
    except GateError as exc:
        print(f"WASM MODULE CLOSURE RED: {exc}", file=sys.stderr)
        return 1
    if not report.passed:
        print("WASM MODULE CLOSURE RED", file=sys.stderr)
        for error in report.errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(
        "WASM MODULE CLOSURE PASS: "
        f"parsed {len(report.parsed_modules)} MODULES; "
        f"project import closure {len(report.closure)}; missing 0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
