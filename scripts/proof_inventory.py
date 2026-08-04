#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail closed unless every explicit theorem/lemma module is built by CI.

REACHED means that a local module is in the transitive source-import closure of
a concrete ``lake test``, ``lake build``, or ``lake exe`` command extracted
from a checked-in GitHub Actions workflow. Lake declarations that no workflow
invokes do not confer reachability.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
import argparse
import json
import re
import shlex
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
THEOREM_DECL = re.compile(
    r"^[^\S\n]*(?:@\[[^\n]*\][^\S\n]*)*(?:[^\s]+[^\S\n]+)*?"
    r"(?:theorem|lemma)[^\S\n]+(«[^»\n]+»|[^\s:([{]+)",
    re.MULTILINE,
)
IMPORT_TOKEN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$"
)
RUN_KEY = re.compile(r"^(\s*)(?:-\s*)?run:\s*(.*?)\s*$")
EXCLUDED_PARTS = {".git", ".lake", "node_modules", "target", "wasm-spike"}
EXTERNAL_LAKE_EXES = {"cache"}

# RULED by Ben on 2026-08-01. This theorem-bearing module is deliberately not
# walked by CI because its kernel reduction cost was measured at 6.0 GiB RSS /
# 1h51m CPU. It remains named in every inventory and is not counted as REACHED.
EXCEPTIONS = {
    "Host.CanonicalL0Liveness": (
        "dropped from the release claim (Ben, 2026-08-01); kernel reduction "
        "measured at 6.0 GiB RSS / 1h51m CPU"
    ),
}


class InventoryError(RuntimeError):
    """The inventory could not establish a trustworthy answer."""


@dataclass(frozen=True)
class BuildInvocation:
    workflow: str
    line: int
    kind: str
    target: str

    @property
    def label(self) -> str:
        rendered = f"lake {self.kind}"
        if self.target:
            rendered += f" {self.target}"
        return f"{self.workflow}:{self.line} ({rendered})"


@dataclass(frozen=True)
class Source:
    module: str
    path: Path
    declarations: tuple[str, ...]
    imports: tuple[str, ...]


@dataclass(frozen=True)
class InventoryRow:
    module: str
    declarations: int
    status: str
    builds: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class Inventory:
    rows: tuple[InventoryRow, ...]
    invocations: tuple[BuildInvocation, ...]
    roots: tuple[str, ...]
    scanned: int
    errors: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors and not any(row.status == "ORPHANED" for row in self.rows)


def strip_lean_comments(text: str) -> str:
    """Blank nested Lean comments and strings while preserving line boundaries."""
    output: list[str] = []
    index = 0
    block_depth = 0
    in_string = False
    raw_string_closer: str | None = None
    in_quoted_identifier = False
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
        elif raw_string_closer is not None:
            if text.startswith(raw_string_closer, index):
                output.extend(" " * len(raw_string_closer))
                index += len(raw_string_closer)
                raw_string_closer = None
            else:
                output.append("\n" if text[index] == "\n" else " ")
                index += 1
        elif in_string:
            if text[index] == "\\":
                output.append(" ")
                index += 1
                if index < len(text):
                    output.append("\n" if text[index] == "\n" else " ")
                    index += 1
            elif text[index] == '"':
                in_string = False
                output.append(" ")
                index += 1
            else:
                output.append("\n" if text[index] == "\n" else " ")
                index += 1
        elif in_quoted_identifier:
            output.append(text[index])
            if text[index] == "»":
                in_quoted_identifier = False
            index += 1
        elif text[index] == "r":
            raw_start = re.match(r'r(#{0,})"', text[index:])
            if raw_start:
                marker = raw_start.group(1)
                output.extend(" " * len(raw_start.group(0)))
                index += len(raw_start.group(0))
                raw_string_closer = f'"{marker}'
            else:
                output.append(text[index])
                index += 1
        elif text[index] == "«":
            in_quoted_identifier = True
            output.append(text[index])
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
        elif text[index] == '"':
            in_string = True
            output.append(" ")
            index += 1
        else:
            output.append(text[index])
            index += 1
    if block_depth:
        raise InventoryError("unterminated Lean block comment")
    if in_string:
        raise InventoryError("unterminated Lean string literal")
    if raw_string_closer is not None:
        raise InventoryError("unterminated Lean raw string literal")
    if in_quoted_identifier:
        raise InventoryError("unterminated Lean quoted identifier")
    return "".join(output)


def parse_imports(source: str, path: Path) -> tuple[str, ...]:
    imports: list[str] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped == "prelude":
            continue
        match = re.match(r"^\s*import(?:\s+(.+?))?\s*$", line)
        if not match:
            break
        tail = match.group(1)
        if not tail:
            raise InventoryError(f"empty import at {path}:{line_number}")
        modules = tail.split()
        invalid = [module for module in modules if not IMPORT_TOKEN.fullmatch(module)]
        if invalid:
            raise InventoryError(
                f"cannot parse import at {path}:{line_number}: {' '.join(invalid)}"
            )
        imports.extend(modules)
    return tuple(imports)


def local_source_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for path in root.rglob("*.lean"):
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        paths.append(path)
    return sorted(paths)


def read_sources(root: Path) -> tuple[dict[str, Source], list[str], set[str]]:
    sources: dict[str, Source] = {}
    errors: list[str] = []
    unreadable: set[str] = set()
    for path in local_source_paths(root):
        module = ".".join(path.relative_to(root).with_suffix("").parts)
        if module in sources:
            errors.append(f"duplicate Lean source for {module}")
            unreadable.add(module)
            continue
        try:
            stripped = strip_lean_comments(path.read_text(encoding="utf-8"))
            imports = parse_imports(stripped, path)
            declarations = tuple(THEOREM_DECL.findall(stripped))
        except (InventoryError, OSError, UnicodeDecodeError) as error:
            errors.append(f"{path}: {error}")
            unreadable.add(module)
            continue
        sources[module] = Source(module, path, declarations, imports)
    return sources, errors, unreadable


def workflow_run_lines(path: Path) -> list[tuple[int, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    commands: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        match = RUN_KEY.match(lines[index])
        if match is None:
            index += 1
            continue
        indent = len(match.group(1))
        value = match.group(2)
        if value.startswith(("|", ">")):
            index += 1
            while index < len(lines):
                line = lines[index]
                if line.strip() and len(line) - len(line.lstrip()) <= indent:
                    break
                if line.strip():
                    commands.append((index + 1, line.strip()))
                index += 1
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        commands.append((index + 1, value))
        index += 1
    return commands


def shell_words(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=True, posix=True)
    except ValueError as error:
        raise InventoryError(f"cannot parse workflow shell line {line!r}: {error}") from error


def extract_invocations(root: Path) -> tuple[BuildInvocation, ...]:
    workflow_dir = root / ".github" / "workflows"
    paths = sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
    if not paths:
        raise InventoryError(f"no GitHub Actions workflows found under {workflow_dir}")
    invocations: list[BuildInvocation] = []
    stop_tokens = {"|", "||", "&&", ";", "then", "fi", "2>&1"}
    for path in paths:
        for line_number, line in workflow_run_lines(path):
            if re.search(r"\blake\b", line) is None:
                continue
            words = shell_words(line)
            for index, word in enumerate(words):
                if word != "lake" or index + 1 >= len(words):
                    continue
                kind = words[index + 1]
                if kind not in {"test", "build", "exe"}:
                    continue
                arguments: list[str] = []
                for argument in words[index + 2 :]:
                    if argument in stop_tokens or argument.startswith((">", "2>")):
                        break
                    if argument.startswith("-"):
                        continue
                    arguments.append(argument)
                if kind == "test":
                    invocations.append(
                        BuildInvocation(str(path.relative_to(root)), line_number, kind, "")
                    )
                elif kind == "exe":
                    if not arguments:
                        raise InventoryError(f"{path}:{line_number}: lake exe has no target")
                    invocations.append(
                        BuildInvocation(
                            str(path.relative_to(root)), line_number, kind, arguments[0]
                        )
                    )
                elif arguments:
                    invocations.extend(
                        BuildInvocation(
                            str(path.relative_to(root)), line_number, kind, target
                        )
                        for target in arguments
                    )
                else:
                    invocations.append(
                        BuildInvocation(str(path.relative_to(root)), line_number, kind, "")
                    )
    if not invocations:
        raise InventoryError("workflows contain no lake test/build/exe invocations")
    return tuple(invocations)


def module_name_from_artifact(path: Path, base: Path, suffix: str) -> str:
    return ".".join(path.relative_to(base).with_suffix("").parts).removesuffix(suffix)


def upstream_modules(root: Path, extra_roots: tuple[Path, ...]) -> tuple[set[str], list[str]]:
    modules: set[str] = set()
    errors: list[str] = []
    package_roots = [root / ".lake" / "packages", *extra_roots]
    for packages in package_roots:
        if not packages.is_dir():
            continue
        for package in sorted(path for path in packages.iterdir() if path.is_dir()):
            for path in package.rglob("*.lean"):
                relative = path.relative_to(package)
                if any(
                    part in {".git", ".lake", "node_modules", "target"}
                    for part in relative.parts
                ):
                    continue
                parts = relative.with_suffix("").parts
                modules.add(".".join(parts))
                if parts and parts[0] in {"src", "lean"} and len(parts) > 1:
                    modules.add(".".join(parts[1:]))
            olean_root = package / ".lake" / "build" / "lib" / "lean"
            if olean_root.is_dir():
                for path in olean_root.rglob("*.olean"):
                    modules.add(module_name_from_artifact(path, olean_root, ""))
    try:
        result = subprocess.run(
            ["lean", "--print-prefix"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        errors.append(f"cannot invoke lean --print-prefix: {error}")
    else:
        if result.returncode != 0:
            errors.append(
                f"lean --print-prefix exited {result.returncode}: {result.stderr.strip()}"
            )
        else:
            lean_lib = Path(result.stdout.strip()) / "lib" / "lean"
            if not lean_lib.is_dir():
                errors.append(f"Lean module directory does not exist: {lean_lib}")
            else:
                for path in lean_lib.rglob("*.olean"):
                    modules.add(module_name_from_artifact(path, lean_lib, ""))
    return modules, errors


def read_lakefile(root: Path) -> dict[str, object]:
    path = root / "lakefile.toml"
    try:
        with path.open("rb") as handle:
            package = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InventoryError(f"cannot parse {path}: {error}") from error
    return package


def executable_map(package: dict[str, object]) -> dict[str, dict[str, object]]:
    tables = package.get("lean_exe", [])
    if not isinstance(tables, list):
        raise InventoryError("lakefile lean_exe declarations are not an array of tables")
    result: dict[str, dict[str, object]] = {}
    for table in tables:
        if not isinstance(table, dict) or not isinstance(table.get("name"), str):
            raise InventoryError("lakefile has a lean_exe without a string name")
        name = table["name"]
        if name in result:
            raise InventoryError(f"duplicate lean_exe declaration {name}")
        result[name] = table
    return result


def resolve_build_roots(
    package: dict[str, object],
    invocations: tuple[BuildInvocation, ...],
    local_modules: set[str],
    upstream: set[str],
) -> tuple[dict[BuildInvocation, set[str]], list[str]]:
    executables = executable_map(package)
    errors: list[str] = []

    def exe_roots(name: str, stack: tuple[str, ...] = ()) -> set[str]:
        if name in stack:
            errors.append(f"circular lean_exe needs: {' -> '.join([*stack, name])}")
            return set()
        table = executables.get(name)
        if table is None:
            if name not in EXTERNAL_LAKE_EXES:
                errors.append(f"workflow invokes undeclared lake executable {name}")
            return set()
        root_module = table.get("root")
        if not isinstance(root_module, str):
            errors.append(f"lean_exe {name} has no string root")
            return set()
        roots = {root_module}
        needs = table.get("needs", [])
        if not isinstance(needs, list) or not all(isinstance(item, str) for item in needs):
            errors.append(f"lean_exe {name}.needs is not an array of strings")
            return roots
        for needed in needs:
            roots.update(exe_roots(needed, (*stack, name)))
        return roots

    def named_target(target: str, invocation: BuildInvocation) -> set[str]:
        if target in executables:
            return exe_roots(target)
        if target.startswith("+"):
            module = target[1:].split(":", 1)[0]
        else:
            module = target.split(":", 1)[0]
        if module in local_modules:
            return {module}
        if module in upstream:
            return set()
        errors.append(f"{invocation.label}: cannot resolve build target {target}")
        return set()

    resolved: dict[BuildInvocation, set[str]] = {}
    for invocation in invocations:
        roots: set[str] = set()
        if invocation.kind == "test":
            driver = package.get("testDriver")
            if not isinstance(driver, str):
                errors.append(f"{invocation.label}: lakefile has no string testDriver")
            else:
                roots.update(exe_roots(driver))
        elif invocation.kind == "exe":
            roots.update(exe_roots(invocation.target))
        elif invocation.target:
            roots.update(named_target(invocation.target, invocation))
        else:
            defaults = package.get("defaultTargets")
            if not isinstance(defaults, list) or not all(
                isinstance(item, str) for item in defaults
            ):
                errors.append(f"{invocation.label}: lakefile has no string defaultTargets array")
            else:
                for target in defaults:
                    roots.update(named_target(target, invocation))
        for module in roots:
            if module not in local_modules and module not in upstream:
                errors.append(f"{invocation.label}: cannot resolve build root {module}")
        resolved[invocation] = {module for module in roots if module in local_modules}
    return resolved, errors


def local_graph(
    sources: dict[str, Source], upstream: set[str]
) -> tuple[dict[str, set[str]], list[str], set[str]]:
    graph: dict[str, set[str]] = {module: set() for module in sources}
    errors: list[str] = []
    uncertain: set[str] = set()
    for module, source in sources.items():
        for imported in source.imports:
            if imported in sources:
                graph[module].add(imported)
            elif imported not in upstream:
                errors.append(
                    f"cannot resolve import {imported} imported by {module} at {source.path}"
                )
                uncertain.add(module)
    return graph, errors, uncertain


def cycle_members(graph: dict[str, set[str]]) -> tuple[set[str], list[str]]:
    state: dict[str, int] = {}
    stack: list[str] = []
    members: set[str] = set()
    errors: list[str] = []
    reported: set[frozenset[str]] = set()

    def visit(module: str) -> None:
        state[module] = 1
        stack.append(module)
        for imported in sorted(graph[module]):
            if state.get(imported, 0) == 0:
                visit(imported)
            elif state.get(imported) == 1:
                start = stack.index(imported)
                cycle = [*stack[start:], imported]
                key = frozenset(cycle[:-1])
                if key not in reported:
                    reported.add(key)
                    members.update(key)
                    errors.append(f"circular local import: {' -> '.join(cycle)}")
        stack.pop()
        state[module] = 2

    for module in sorted(graph):
        if state.get(module, 0) == 0:
            visit(module)
    return members, errors


def transitive_dependents(graph: dict[str, set[str]], seeds: set[str]) -> set[str]:
    reverse: dict[str, set[str]] = defaultdict(set)
    for module, imports in graph.items():
        for imported in imports:
            reverse[imported].add(module)
    result = set(seeds)
    queue = list(seeds)
    while queue:
        module = queue.pop()
        for dependent in reverse[module]:
            if dependent not in result:
                result.add(dependent)
                queue.append(dependent)
    return result


def closure(root_module: str, graph: dict[str, set[str]]) -> set[str]:
    visited: set[str] = set()
    queue = [root_module]
    while queue:
        module = queue.pop()
        if module in visited:
            continue
        visited.add(module)
        queue.extend(graph.get(module, ()))
    return visited


def evaluate(root: Path = ROOT, extra_upstream_roots: tuple[Path, ...] = ()) -> Inventory:
    sources, source_errors, unreadable = read_sources(root)
    errors = list(source_errors)
    try:
        invocations = extract_invocations(root)
        package = read_lakefile(root)
    except (InventoryError, OSError, UnicodeDecodeError) as error:
        return Inventory((), (), (), len(sources) + len(unreadable), (str(error),))

    upstream, upstream_errors = upstream_modules(root, extra_upstream_roots)
    errors.extend(upstream_errors)
    graph, import_errors, uncertain = local_graph(sources, upstream)
    errors.extend(import_errors)
    cycles, cycle_errors = cycle_members(graph)
    errors.extend(cycle_errors)
    uncertain.update(cycles)
    uncertain.update(unreadable)
    uncertain = transitive_dependents(graph, uncertain)

    resolved, target_errors = resolve_build_roots(
        package, invocations, set(sources), upstream
    )
    errors.extend(target_errors)

    builds_by_module: dict[str, set[str]] = defaultdict(set)
    roots: set[str] = set()
    for invocation, invocation_roots in resolved.items():
        roots.update(invocation_roots)
        for root_module in invocation_roots:
            for module in closure(root_module, graph):
                builds_by_module[module].add(invocation.label)

    rows: list[InventoryRow] = []
    for module, source in sorted(sources.items()):
        if not source.declarations:
            continue
        if module in uncertain:
            status = "UNCLASSIFIED"
            reason = "an unresolved import or circular dependency affects this module"
        elif module in builds_by_module:
            status = "REACHED"
            reason = "in a workflow-invoked build's transitive import closure"
        elif module in EXCEPTIONS:
            status = "EXCEPTED"
            reason = EXCEPTIONS[module]
        else:
            status = "ORPHANED"
            reason = "in no workflow-invoked build's transitive import closure"
        rows.append(
            InventoryRow(
                module,
                len(source.declarations),
                status,
                tuple(sorted(builds_by_module.get(module, ()))),
                reason,
            )
        )
    return Inventory(
        tuple(rows),
        invocations,
        tuple(sorted(roots)),
        len(sources) + len(unreadable),
        tuple(sorted(set(errors))),
    )


def print_report(inventory: Inventory) -> None:
    counts = {
        status: sum(row.status == status for row in inventory.rows)
        for status in ("REACHED", "EXCEPTED", "ORPHANED", "UNCLASSIFIED")
    }
    print(
        f"scanned={inventory.scanned} theorem-bearing={len(inventory.rows)} "
        f"workflow-invocations={len(inventory.invocations)} build-roots={len(inventory.roots)}"
    )
    print(
        "  ".join(f"{status}={counts[status]}" for status in counts)
    )
    print("status\tmodule\tdeclarations\treason")
    for row in inventory.rows:
        print(f"{row.status}\t{row.module}\t{row.declarations}\t{row.reason}")
        if row.status == "REACHED":
            for build in row.builds:
                print(f"  BUILD\t{row.module}\t{build}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--upstream-root",
        action="append",
        type=Path,
        default=[],
        help="additional directory whose children are Lake dependency packages",
    )
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    inventory = evaluate(
        arguments.root.resolve(),
        tuple(path.resolve() for path in arguments.upstream_root),
    )
    if arguments.json:
        print(
            json.dumps(
                {
                    "scanned": inventory.scanned,
                    "roots": inventory.roots,
                    "invocations": [asdict(item) for item in inventory.invocations],
                    "rows": [asdict(row) for row in inventory.rows],
                    "errors": inventory.errors,
                },
                indent=2,
            )
        )
    else:
        print_report(inventory)
    sys.stdout.flush()
    for error in inventory.errors:
        print(f"PROOF INVENTORY UNCLASSIFIED: {error}", file=sys.stderr)
    for row in inventory.rows:
        if row.status == "ORPHANED":
            print(f"ORPHAN PROOF MODULE: {row.module}: {row.reason}", file=sys.stderr)
    return 0 if inventory.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
