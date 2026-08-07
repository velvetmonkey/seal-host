#!/usr/bin/env python3
"""Fail when a CI job reaches PyYAML without provisioning it first."""

from __future__ import annotations

import ast
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
import re
import sys

try:
    import yaml
except ModuleNotFoundError:
    print(
        "::error::PyYAML is required to inspect CI workflows; "
        "refusing to fall back to text scanning"
    )
    raise SystemExit(1)


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = Path(".github/workflows")
SETUP_ACTION = "./.github/actions/setup-pyyaml"
PYTHON_ROOTS = ("scripts", "test", "demo", ".github")
PYTHON_COMMAND = re.compile(
    r"(?<![A-Za-z0-9_])(?:\.\./|\./)?(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.py"
)
UNITTEST_DISCOVER = re.compile(r"-m\s+unittest\s+discover\b([^\n]*)")
UNITTEST_START = re.compile(r"(?:^|\s)-s\s+([^\s]+)")
UNITTEST_PATTERN = re.compile(r"(?:^|\s)-p\s+(['\"]?)([^\s'\"]+)\1")


@dataclass(frozen=True, order=True)
class Job:
    workflow: str
    job: str

    def label(self) -> str:
        return f"{self.workflow}:{self.job}"


@dataclass(frozen=True)
class Finding:
    job: Job
    dependency_step: int
    entrypoints: tuple[str, ...]
    provision_step: int | None


class CoverageError(Exception):
    """The repository cannot be analyzed without guessing."""


def python_files(root: Path) -> tuple[Path, ...]:
    files: set[Path] = set(root.glob("*.py"))
    for directory in PYTHON_ROOTS:
        base = root / directory
        if base.is_dir():
            files.update(base.rglob("*.py"))
    return tuple(sorted(path.relative_to(root) for path in files))


def module_aliases(path: Path) -> set[str]:
    parts = list(path.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    aliases = {".".join(parts)} if parts else set()
    if len(parts) > 1:
        # Repository scripts are commonly executed by path, which puts their
        # containing directory on sys.path (for example `from proof_inventory`).
        aliases.add(".".join(parts[1:]))
    return aliases


def imported_modules(tree: ast.AST, path: Path) -> tuple[set[str], bool]:
    imports: set[str] = set()
    imports_yaml = False
    package = list(path.with_suffix("").parts[:-1])
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
                imports_yaml |= alias.name == "yaml" or alias.name.startswith("yaml.")
        elif isinstance(node, ast.ImportFrom):
            imports_yaml |= node.module == "yaml" or (
                node.module is not None and node.module.startswith("yaml.")
            )
            if node.level:
                keep = max(0, len(package) - node.level + 1)
                prefix = package[:keep]
                if node.module:
                    prefix.extend(node.module.split("."))
                if prefix:
                    imports.add(".".join(prefix))
            elif node.module:
                imports.add(node.module)
    return imports, imports_yaml


def pyyaml_dependency_closure(root: Path) -> set[Path]:
    files = python_files(root)
    aliases: dict[str, set[Path]] = defaultdict(set)
    for path in files:
        for alias in module_aliases(path):
            aliases[alias].add(path)

    reverse_edges: dict[Path, set[Path]] = defaultdict(set)
    direct: set[Path] = set()
    for path in files:
        try:
            tree = ast.parse((root / path).read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as error:
            raise CoverageError(f"cannot parse Python source {path}: {error}") from error
        imports, imports_yaml = imported_modules(tree, path)
        if imports_yaml:
            direct.add(path)
        for imported in imports:
            candidates = aliases.get(imported, set())
            if not candidates:
                candidates = aliases.get(imported.split(".")[0], set())
            for dependency in candidates:
                reverse_edges[dependency].add(path)

    dependent = set(direct)
    queue = deque(direct)
    while queue:
        dependency = queue.popleft()
        for importer in reverse_edges.get(dependency, set()):
            if importer not in dependent:
                dependent.add(importer)
                queue.append(importer)
    return dependent


def resolve_command_path(root: Path, working_directory: Path, token: str) -> Path | None:
    candidate = (root / working_directory / token).resolve()
    try:
        return candidate.relative_to(root.resolve())
    except ValueError:
        return None


def command_entrypoints(
    root: Path, command: str, working_directory: Path
) -> set[Path]:
    found: set[Path] = set()
    for match in PYTHON_COMMAND.finditer(command):
        path = resolve_command_path(root, working_directory, match.group(0))
        if path is not None and (root / path).is_file():
            found.add(path)

    for match in UNITTEST_DISCOVER.finditer(command):
        arguments = match.group(1)
        start_match = UNITTEST_START.search(arguments)
        pattern_match = UNITTEST_PATTERN.search(arguments)
        start = start_match.group(1).strip("'\"") if start_match else "."
        pattern = pattern_match.group(2) if pattern_match else "test*.py"
        directory = (root / working_directory / start).resolve()
        try:
            directory.relative_to(root.resolve())
        except ValueError:
            continue
        if directory.is_dir():
            found.update(path.relative_to(root) for path in directory.rglob(pattern))
    return found


def validate_setup_action(root: Path) -> None:
    path = root / ".github/actions/setup-pyyaml/action.yml"
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise CoverageError(f"cannot read shared PyYAML setup action: {error}") from error
    try:
        steps = document["runs"]["steps"]
        command = "\n".join(step.get("run", "") for step in steps)
    except (KeyError, TypeError) as error:
        raise CoverageError("shared PyYAML setup action has no composite steps") from error
    required = (
        "python3 -c 'import yaml'",
        "pip install --break-system-packages pyyaml==6.0.2",
        "pip install pyyaml==6.0.2",
        "apt-get install -y -qq python3-yaml",
    )
    missing = [fragment for fragment in required if fragment not in command]
    if missing:
        raise CoverageError(
            "shared PyYAML setup action lost provisioning route(s): " + ", ".join(missing)
        )


def analyze(root: Path = ROOT) -> tuple[Finding, ...]:
    dependent = pyyaml_dependency_closure(root)
    findings: list[Finding] = []
    workflow_dir = root / WORKFLOWS
    paths = sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))
    if not paths:
        raise CoverageError("no workflow files found")
    for path in paths:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            raise CoverageError(f"cannot read workflow {path.relative_to(root)}: {error}") from error
        jobs = document.get("jobs") if isinstance(document, dict) else None
        if not isinstance(jobs, dict):
            continue
        for job_name, definition in jobs.items():
            if not isinstance(job_name, str) or not isinstance(definition, dict):
                continue
            steps = definition.get("steps")
            if not isinstance(steps, list):
                continue
            provision_step: int | None = None
            reached: list[tuple[int, set[Path]]] = []
            for index, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                if step.get("uses") == SETUP_ACTION:
                    if "if" in step:
                        raise CoverageError(
                            f"{path.name}:{job_name}: PyYAML setup must be unconditional"
                        )
                    provision_step = index if provision_step is None else provision_step
                command = step.get("run")
                if not isinstance(command, str):
                    continue
                working = step.get("working-directory", ".")
                if not isinstance(working, str) or "${{" in working:
                    working = "."
                entrypoints = command_entrypoints(root, command, Path(working))
                hits = entrypoints & dependent
                if hits:
                    reached.append((index, hits))
            if reached:
                first_step = min(index for index, _hits in reached)
                all_hits = sorted({hit for _index, hits in reached for hit in hits})
                findings.append(
                    Finding(
                        Job(path.name, job_name),
                        first_step,
                        tuple(str(hit) for hit in all_hits),
                        provision_step,
                    )
                )
    return tuple(sorted(findings, key=lambda item: item.job))


def main(root: Path = ROOT) -> int:
    try:
        validate_setup_action(root)
        findings = analyze(root)
    except CoverageError as error:
        print(f"::error::{error}")
        return 1

    failures = 0
    for finding in findings:
        provisioned = (
            finding.provision_step is not None
            and finding.provision_step < finding.dependency_step
        )
        status = "PROVISIONED" if provisioned else "UNPROVISIONED"
        print(
            f"{status} {finding.job.label()} via "
            + ", ".join(finding.entrypoints)
        )
        if not provisioned:
            failures += 1
            print(
                f"::error::{finding.job.label()} reaches PyYAML before "
                f"{SETUP_ACTION}"
            )
    if failures:
        print(f"FAIL: {failures} of {len(findings)} PyYAML-dependent jobs unprovisioned")
        return 1
    print(f"PASS: all {len(findings)} PyYAML-dependent jobs provision before use")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
