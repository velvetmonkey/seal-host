#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Classify every theorem-bearing Lean module by build reachability, and gate.

Exit codes (this is the contract; keep code and this docstring aligned):

  0  inventory produced; no unresolved imports; no UNCLASSIFIED rows; every
     ORPHANED row is on the permanent-exclusion list (G1 stop condition).
  1  inventory produced, but import/source uncertainty or a G1 finding prevents
     a clean pass (unresolved import, unexpected orphan, UNCLASSIFIED, …).
  2  cannot produce an inventory at all (missing lakefile facts, missing proof
     wire, undecodable source that aborts evaluation, unexpected exception, …).

This is a GATE. It is wired into CI (control_33). An instrument that always
exits 0 is not a gate; a fail-open here must turn the run red.

Scope differs from the Host-only `scripts/proof_inventory.py` (control_18):
this walks every tracked `*.lean`, derives build roots from `lakefile.toml`,
and separates proof-wire reachability from true orphans. It reuses
`proof_inventory`'s comment stripper and import parser; it does not modify
that file.

Buckets, tested in this order:

  UNCLASSIFIED   cannot decide: not addressable as a Lake module, or imports
                 could not be resolved/parsed. Uncertainty bites; rc=1.
  REACHED        in the import closure of `Test.Axioms` (the `axiom_check`
                 proof wire). Theorems elaborated by that build.
  BUILT_ONLY     in the closure of some other `defaultTargets` executable, but
                 not the proof wire.
  ON_DEMAND      in the closure of a declared non-default executable only.
  ORPHANED       theorem-bearing, addressable by a declared library glob or
                 executable root, but in no executable import closure any
                 declared target walks. G1's stop condition is zero of these
                 outside the permanent-exclusion list below.
  EXCLUDED       ORPHANED modules with a permanent, written exclusion. Still
                 visible; not a G1 failure.

Library globs alone do NOT move a module to ON_DEMAND. A `Host.+` match means
Lake can name the file; it does not mean any executable elaborates it. That
distinction is load-bearing for G1: if lib-glob coverage counted as ON_DEMAND,
ORPHANED would be unreachable by construction and "zero orphaned" would be a
tautology rather than a measurement (see frisk F2).

Import resolution fails closed for every unresolved name: a typo of a local
root (`Hosts.…`), an absent upstream module (`Mathlib.CompletelyFake`), and a
renamed namespace all produce a named note and rc=1. Upstream modules are
resolved against `.lake/packages` and the active Lean toolchain; if neither is
available, non-local imports are reported unresolved rather than accepted on
faith.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import argparse
import json
import os
import re
import subprocess
import sys
import tomllib

from proof_inventory import InventoryError, parse_imports, strip_lean_comments

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {".git", ".lake", "node_modules", "target"}

# The proof wire named by WAVE2-STATEMENTS.md and docs/LIMITATIONS.md.
# Derived from lakefile.toml as the root of this executable; the constant only
# names which executable is the proof wire.
PROOF_WIRE_EXE = "axiom_check"

# Permanent exclusions: theorem-bearing modules that are addressable and outside
# every executable closure, with a written reason. Silence is not an option.
# "It is outside the closure" is not a reason — each entry states why the
# module is allowed to stay outside the G1-zero-orphaned stop condition.
PERMANENT_EXCLUSIONS: dict[str, str] = {
    "Host.CanonicalL0Liveness": (
        "Ruled by Ben 2026-08-01: dropped from the release claim. Kernel "
        "reduction measured 6.0 GiB RSS / 1h51m CPU (2026-07-31); the release "
        "pipeline will not carry it. Nothing on the public claim surface "
        "asserts its theorems are built or axiom-checked. Source stays in "
        "tree and stays visible here as EXCLUDED, not silent."
    ),
    "Test.A2DivergenceClassification": (
        "Classification criterion and unasserted #print axioms for A2 parser "
        "divergence; not part of the axiom-footprint claim. Built every CI "
        "run by control_16 (`lake build Test.A2DivergenceClassification`) as "
        "a compile-time guard module, not as an axiom_check pin. Seven "
        "#print axioms lines carry zero #guard_msgs, so they cannot fail a "
        "build. Host-scoped proof_inventory does not see Test/ sources; this "
        "exclusion keeps the residual explicit rather than silent."
    ),
}

# Same declaration prefix as scripts/proof_inventory.py, deliberately, so the
# two tools' counts are comparable on the Host/ files they both scan.
THEOREM_DECL = re.compile(
    r"^[^\S\n]*(?:@\[[^\n]*\][^\S\n]*)*(?:[^\s]+[^\S\n]+)*?"
    r"(?:theorem|lemma)[^\S\n]+(«[^»\n]+»|[^\s:([{]+)",
    re.MULTILINE,
)
_MODIFIERS = (
    r"(?:(?:private|protected|noncomputable|nonrec|unsafe|partial|scoped|local)"
    r"[^\S\n]+)*"
)
EXAMPLE_DECL = re.compile(
    r"^[^\S\n]*(?:@\[[^\n]*\][^\S\n]*)*" + _MODIFIERS + r"example\b",
    re.MULTILINE,
)
INSTANCE_DECL = re.compile(
    r"^[^\S\n]*(?:@\[[^\n]*\][^\S\n]*)*" + _MODIFIERS + r"instance\b",
    re.MULTILINE,
)


class ReachError(RuntimeError):
    """The inventory could not be produced at all (maps to exit code 2)."""


@dataclass(frozen=True)
class Targets:
    default: tuple[str, ...]
    exe_roots: dict[str, str]
    lib_globs: dict[str, tuple[str, ...]]


@dataclass
class Row:
    module: str
    path: str
    bucket: str
    reason: str
    theorems: int
    examples: int
    instances: int
    addressable_by: str
    reached_via: list[str] = field(default_factory=list)


def lean_sources(root: Path) -> dict[str, Path]:
    """Every *.lean the repository TRACKS, keyed by path-implied module name.

    Scope is `git ls-files`, not a filesystem walk: untracked vendored trees
    (e.g. wasm-spike/lean4-src) are not this project's proof surface.
    """
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "*.lean"],
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ReachError(
            f"git ls-files failed ({completed.returncode}): "
            f"{completed.stderr.decode('utf-8', 'replace').strip()}"
        )
    sources: dict[str, Path] = {}
    for entry in completed.stdout.decode("utf-8").split("\0"):
        if not entry:
            continue
        relative = Path(entry)
        if set(relative.parts) & EXCLUDED_DIRS:
            continue
        module = ".".join(relative.with_suffix("").parts)
        if module in sources:
            raise ReachError(f"duplicate Lean source for module {module}")
        sources[module] = root / relative
    if not sources:
        raise ReachError("no tracked *.lean sources found")
    return dict(sorted(sources.items()))


def read_targets(root: Path) -> Targets:
    """Derive build roots from lakefile.toml. Never a hand-maintained list."""
    path = root / "lakefile.toml"
    if not path.is_file():
        raise ReachError("lakefile.toml is missing")
    with path.open("rb") as handle:
        config = tomllib.load(handle)
    exe_roots: dict[str, str] = {}
    for exe in config.get("lean_exe", []):
        name = exe["name"]
        exe_roots[name] = exe.get("root", name)
    lib_globs = {
        lib["name"]: tuple(lib.get("globs", [lib["name"]]))
        for lib in config.get("lean_lib", [])
    }
    default = tuple(config.get("defaultTargets", []))
    if not default:
        raise ReachError("lakefile.toml declares no defaultTargets")
    return Targets(default, exe_roots, lib_globs)


def glob_matches(glob: str, module: str) -> bool:
    if glob.endswith(".+"):
        base = glob[:-2]
        return module == base or module.startswith(f"{base}.")
    if glob.endswith(".*"):
        base = glob[:-2]
        return module.startswith(f"{base}.") and "." not in module[len(base) + 1 :]
    return module == glob


def addressable_by(module: str, targets: Targets) -> str | None:
    """Which Lake library glob or executable root can name this module at all."""
    for lib, globs in targets.lib_globs.items():
        for glob in globs:
            if glob_matches(glob, module):
                return f"lib:{lib}({glob})"
    for exe, exe_root in targets.exe_roots.items():
        if exe_root == module:
            return f"exe-root:{exe}"
    return None


def _walk_files(base: Path, suffix: str):
    """Yield files under base with the given suffix, never descending into EXCLUDED_DIRS."""
    if not base.is_dir():
        return
    stack = [base]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            name = entry.name
            if name in EXCLUDED_DIRS or name.startswith("."):
                continue
            if entry.is_dir():
                stack.append(entry)
            elif entry.is_file() and name.endswith(suffix):
                yield entry


def _index_lean_tree(base: Path, modules: dict[str, Path]) -> None:
    """Add module→path entries for every *.lean under base (skip nested .lake)."""
    for path in _walk_files(base, ".lean"):
        try:
            relative = path.relative_to(base)
        except ValueError:
            continue
        module = ".".join(relative.with_suffix("").parts)
        modules.setdefault(module, path)


def _index_olean_tree(base: Path, modules: dict[str, Path]) -> None:
    """Add module entries for toolchain .olean files (source may be absent)."""
    for path in _walk_files(base, ".olean"):
        # Path.suffix for 'x.olean.private' is '.private', so only true .olean match.
        if path.suffix != ".olean":
            continue
        try:
            relative = path.relative_to(base)
        except ValueError:
            continue
        module = ".".join(relative.with_suffix("").parts)
        modules.setdefault(module, path)


def resolve_toolchain_lib(root: Path) -> Path | None:
    """Locate the active Lean toolchain's lib/lean directory, if present."""
    toolchain_file = root / "lean-toolchain"
    if not toolchain_file.is_file():
        return None
    spec = toolchain_file.read_text(encoding="utf-8").strip()
    # leanprover/lean4:v4.28.0 → leanprover--lean4---v4.28.0
    if ":" not in spec:
        return None
    org_pkg, version = spec.split(":", 1)
    org_pkg = org_pkg.replace("/", "--")
    dirname = f"{org_pkg}---{version}"
    elan_home = Path(os.environ.get("ELAN_HOME", Path.home() / ".elan"))
    candidate = elan_home / "toolchains" / dirname / "lib" / "lean"
    return candidate if candidate.is_dir() else None


def external_modules(root: Path) -> tuple[dict[str, Path], list[str]]:
    """Index resolveable non-local modules from packages + toolchain.

    Returns (module→path, notes about what was scanned).
    """
    modules: dict[str, Path] = {}
    notes: list[str] = []
    packages = root / ".lake" / "packages"
    if packages.is_dir():
        for child in sorted(packages.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            _index_lean_tree(child, modules)
        notes.append(f"scanned .lake/packages ({len(list(packages.iterdir()))} entries)")
    else:
        notes.append("no .lake/packages directory")

    toolchain = resolve_toolchain_lib(root)
    if toolchain is not None:
        before = len(modules)
        _index_olean_tree(toolchain, modules)
        notes.append(
            f"scanned toolchain {toolchain} (+{len(modules) - before} modules)"
        )
    else:
        notes.append("no Lean toolchain lib/lean found")
    return modules, notes


def checked_imports(
    path: Path,
    sources: dict[str, Path],
    local_roots: set[str],
    externals: dict[str, Path],
    external_roots: set[str],
) -> tuple[tuple[str, ...] | None, list[str]]:
    """Parse imports; every name must resolve to a local or external module.

    Fail closed: a typo of a local root, an unknown root, and a missing
    upstream module all return messages (no default-allow for non-local names).
    """
    try:
        source = strip_lean_comments(path.read_text(encoding="utf-8"))
        imports = parse_imports(source, path)
    except (InventoryError, OSError, UnicodeDecodeError) as exc:
        return None, [f"{path}: {exc}"]

    messages: list[str] = []
    for imported in imports:
        if imported in sources or imported in externals:
            continue
        root_name = imported.split(".", 1)[0]
        if root_name in local_roots:
            messages.append(f"cannot resolve local import {imported}")
        elif root_name in external_roots:
            messages.append(f"cannot resolve upstream import {imported}")
        else:
            # Unknown root: typo of a local root (Hosts vs Host), renamed
            # namespace, or a dependency that is not present in packages/
            # toolchain. Fail closed either way.
            messages.append(
                f"cannot resolve import {imported} "
                f"(unknown root {root_name!r}; not a tracked local root and "
                f"not present in scanned packages/toolchain)"
            )
    if messages:
        return None, messages
    return imports, []


def import_closure(
    root_module: str,
    sources: dict[str, Path],
    local_roots: set[str],
    externals: dict[str, Path],
    external_roots: set[str],
) -> tuple[set[str], dict[str, list[str]]]:
    """Walk local imports from a root.

    Unresolvable imports are reported, not raised, so one bad module degrades
    to UNCLASSIFIED instead of blinding the whole inventory — except a missing
    proof-wire *root*, which is escalated by the caller to ReachError (rc=2).
    """
    closure: set[str] = set()
    visited: set[str] = set()
    problems: dict[str, list[str]] = {}
    if root_module not in sources:
        return closure, {root_module: [f"cannot resolve build root {root_module}"]}
    queue = [root_module]
    while queue:
        module = queue.pop()
        if module in visited:
            continue
        visited.add(module)
        path = sources.get(module)
        if path is None:
            # Non-local: either known external (stop walking) or already
            # reported when the importer was checked.
            continue
        imports, messages = checked_imports(
            path, sources, local_roots, externals, external_roots
        )
        if imports is None:
            problems[module] = messages
            continue
        # A module is evidence for reachability only after its own imports have
        # parsed and every direct import has resolved.
        closure.add(module)
        queue.extend(imp for imp in imports if imp in sources)
    return closure, problems


def count_declarations(path: Path) -> tuple[int, int, int] | str:
    try:
        source = strip_lean_comments(path.read_text(encoding="utf-8"))
    except (InventoryError, OSError, UnicodeDecodeError) as exc:
        return f"cannot read declarations: {exc}"
    return (
        len(THEOREM_DECL.findall(source)),
        len(EXAMPLE_DECL.findall(source)),
        len(INSTANCE_DECL.findall(source)),
    )


def evaluate(root: Path = ROOT, predicate: str = "core") -> dict:
    sources = lean_sources(root)
    targets = read_targets(root)
    local_roots = {module.split(".", 1)[0] for module in sources}
    externals, scan_notes = external_modules(root)
    external_roots = {module.split(".", 1)[0] for module in externals}

    proof_wire_root = targets.exe_roots.get(PROOF_WIRE_EXE)
    if proof_wire_root is None:
        raise ReachError(f"lakefile.toml declares no {PROOF_WIRE_EXE} executable")

    default_exes = [name for name in targets.default if name in targets.exe_roots]
    nondefault_exes = [
        name for name in sorted(targets.exe_roots) if name not in targets.default
    ]
    unknown_defaults = [
        name
        for name in targets.default
        if name not in targets.exe_roots and name not in targets.lib_globs
    ]

    closures: dict[str, set[str]] = {}
    closure_problems: dict[str, list[str]] = {}
    for exe in sorted(targets.exe_roots):
        closure, problems = import_closure(
            targets.exe_roots[exe], sources, local_roots, externals, external_roots
        )
        closures[exe] = closure
        for module, messages in problems.items():
            closure_problems.setdefault(module, []).extend(
                f"{exe}: {message}" for message in messages
            )

    # Missing proof-wire root is unanswerable: the central question has no
    # subject. Escalate to rc=2 rather than emit REACHED=0 with a green-looking
    # ORPHANED=0 (frisk F3 / §2b).
    if proof_wire_root not in sources:
        raise ReachError(
            f"proof wire root {proof_wire_root!r} ({PROOF_WIRE_EXE}) is not a "
            f"tracked source module; cannot measure reachability"
        )
    if proof_wire_root in closure_problems and not closures.get(PROOF_WIRE_EXE):
        # Root exists but could not enter the closure (e.g. its own imports
        # blow up so hard the root never joins). Still produce an inventory of
        # the rest — that is rc=1 uncertainty, not rc=2 blindness — unless the
        # only problem is "cannot resolve build root", already handled above.
        pass

    # Default library entries in defaultTargets elaborate every matching module.
    default_lib_modules: set[str] = set()
    for name in targets.default:
        for glob in targets.lib_globs.get(name, ()):
            default_lib_modules |= {m for m in sources if glob_matches(glob, m)}

    reached = closures[PROOF_WIRE_EXE]
    built_only: set[str] = set()
    if default_exes:
        built_only = set().union(*(closures[e] for e in default_exes))
    built_only |= default_lib_modules
    on_demand: set[str] = set()
    if nondefault_exes:
        on_demand = set().union(*(closures[e] for e in nondefault_exes))
    # Intentionally NOT unioning non-default lib globs into on_demand (F2).

    rows: list[Row] = []
    errors = [
        message
        for messages in closure_problems.values()
        for message in messages
    ]
    for module, path in sources.items():
        counts = count_declarations(path)
        if isinstance(counts, str):
            errors.append(f"{path}: {counts}")
            rows.append(
                Row(
                    module,
                    str(path.relative_to(root)),
                    "UNCLASSIFIED",
                    counts,
                    -1,
                    -1,
                    -1,
                    "unknown",
                )
            )
            continue
        theorems, examples, instances = counts
        bearing = {
            "core": theorems > 0,
            "wide": theorems + examples > 0,
            "widest": theorems + examples + instances > 0,
        }[predicate]
        if not bearing:
            continue

        _, direct_problems = checked_imports(
            path, sources, local_roots, externals, external_roots
        )
        if direct_problems and module not in closure_problems:
            closure_problems[module] = direct_problems
            errors.extend(direct_problems)

        where = addressable_by(module, targets)
        via = sorted(exe for exe, closure in closures.items() if module in closure)
        if module in default_lib_modules:
            via.append("lib-glob(default)")

        if where is None:
            bucket, reason = (
                "UNCLASSIFIED",
                "no lakefile.toml library glob covers it and it is no executable "
                "root: Lake cannot name this file as a module, so reachability "
                "is not defined for it",
            )
        elif module in closure_problems:
            bucket, reason = "UNCLASSIFIED", "imports could not be resolved"
        elif module in reached:
            bucket, reason = (
                "REACHED",
                f"in the {PROOF_WIRE_EXE} ({proof_wire_root}) closure",
            )
        elif module in built_only:
            bucket, reason = (
                "BUILT_ONLY",
                "in a defaultTargets closure but not the proof wire",
            )
        elif module in on_demand:
            bucket, reason = (
                "ON_DEMAND",
                "only in a declared non-default executable closure",
            )
        elif module in PERMANENT_EXCLUSIONS:
            bucket, reason = "EXCLUDED", PERMANENT_EXCLUSIONS[module]
        else:
            bucket, reason = (
                "ORPHANED",
                "addressable but in no executable closure any declared target walks",
            )

        rows.append(
            Row(
                module,
                str(path.relative_to(root)),
                bucket,
                reason,
                theorems,
                examples,
                instances,
                where or "NONE",
                via,
            )
        )

    rows.sort(key=lambda row: (row.bucket, row.module))
    summary = {
        bucket: sum(row.bucket == bucket for row in rows)
        for bucket in (
            "REACHED",
            "BUILT_ONLY",
            "ON_DEMAND",
            "ORPHANED",
            "EXCLUDED",
            "UNCLASSIFIED",
        )
    }
    return {
        "predicate": predicate,
        "proof_wire": {"exe": PROOF_WIRE_EXE, "root": proof_wire_root},
        "default_targets": list(targets.default),
        "nondefault_exes": nondefault_exes,
        "unknown_default_targets": unknown_defaults,
        "permanent_exclusions": dict(PERMANENT_EXCLUSIONS),
        "external_scan": scan_notes,
        "external_module_count": len(externals),
        "summary": summary,
        "theorem_bearing_total": len(rows),
        "lean_files_scanned": len(sources),
        "rows": [asdict(row) for row in rows],
        "errors": errors,
    }


def gate_ok(result: dict) -> bool:
    """G1 stop condition: zero unexpected orphans, zero uncertainty."""
    summary = result["summary"]
    return (
        not result["errors"]
        and summary.get("ORPHANED", 0) == 0
        and summary.get("UNCLASSIFIED", 0) == 0
    )


def print_report(result: dict) -> None:
    summary = result["summary"]
    print(
        f"predicate={result['predicate']}  scanned={result['lean_files_scanned']} "
        f"theorem-bearing={result['theorem_bearing_total']}"
    )
    print("  ".join(f"{bucket}={count}" for bucket, count in summary.items()))
    print()
    print("bucket\tmodule\ttheorems\texamples\tinstances\treached-via")
    for row in result["rows"]:
        print(
            f"{row['bucket']}\t{row['module']}\t{row['theorems']}\t"
            f"{row['examples']}\t{row['instances']}\t"
            f"{','.join(row['reached_via']) or '-'}"
        )
    for error in result["errors"]:
        print(f"note: {error}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--predicate",
        choices=("core", "wide", "widest"),
        default="core",
        help="core=theorem|lemma; wide=+example; widest=+instance",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--bucket",
        choices=(
            "REACHED",
            "BUILT_ONLY",
            "ON_DEMAND",
            "ORPHANED",
            "EXCLUDED",
            "UNCLASSIFIED",
        ),
        help="print only the modules in this bucket, one per line",
    )
    args = parser.parse_args()
    try:
        result = evaluate(args.root.resolve(), args.predicate)
    except (ReachError, OSError, tomllib.TOMLDecodeError) as exc:
        print(f"proof_reach: cannot produce an inventory: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — any uncaught failure is rc=2
        print(
            f"proof_reach: cannot produce an inventory: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2

    if args.bucket:
        for row in result["rows"]:
            if row["bucket"] == args.bucket:
                print(row["module"])
        # --bucket still surfaces notes so a silent empty list cannot hide
        # the reason a gate-shaped consumer got no rows (frisk §2e.3).
        for error in result["errors"]:
            print(f"note: {error}", file=sys.stderr)
    elif args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)

    return 0 if gate_ok(result) else 1


if __name__ == "__main__":
    raise SystemExit(main())
