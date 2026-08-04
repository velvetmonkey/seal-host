#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Classify every theorem-bearing Lean module in the tree by build reachability.

This is a MEASUREMENT INSTRUMENT, not a gate. It always exits 0 unless it
cannot produce an answer at all. Nothing here is wired into CI; whether any of
these buckets should fail a build is gate G1's question and Ben's ruling.

It differs from the CI-wired `scripts/proof_inventory.py` (control_18) in scope:
that gate scans `Host/*.lean` only and asks one question (in the `Test.Axioms`
closure or not). This walks EVERY `*.lean` in the tree, derives the build roots
from `lakefile.toml` rather than a hand-maintained list, and separates the
"a build elaborates it but the proof wire does not pin it" band from true
orphans. It reuses `proof_inventory`'s Lean comment/string stripper and import
parser rather than duplicating them; it does not modify that file.

Buckets, in the order a module is tested against:

  UNCLASSIFIED   the generator cannot decide: the file is not addressable as a
                 Lake module (no `[[lean_lib]]` glob covers it and it is no
                 executable root), or its imports cannot be parsed. Reported
                 honestly rather than folded into a neighbouring bucket.
  REACHED        in the import closure of `Test.Axioms`, the documented proof
                 wire (WAVE2-STATEMENTS.md:30-37). Its theorems are elaborated
                 by the build that `axiom_check` runs over.
  BUILT_ONLY     in the closure of some other `defaultTargets` entry, so a bare
                 `lake build` elaborates it, but NOT in the proof wire, so no
                 `#print axioms` pin covers it.
  ON_DEMAND      in the closure of a declared `[[lean_exe]]` that is not in
                 `defaultTargets`. A build walks it only if someone names it.
  ORPHANED       theorem-bearing and in no closure any declared target walks.
                 Its proofs are not maintained assurance; they are files.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import argparse
import json
import re
import subprocess
import sys
import tomllib

from proof_inventory import InventoryError, parse_imports, strip_lean_comments

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {".git", ".lake", "node_modules", "target"}

# The proof wire named by WAVE2-STATEMENTS.md:30-37 and by the release claim
# scoping note at docs/LIMITATIONS.md:13. Derived from lakefile.toml below as
# the root of the `axiom_check` executable; this constant only names which
# executable is the proof wire, which is a documented fact, not an inventory.
PROOF_WIRE_EXE = "axiom_check"

# Same declaration prefix as scripts/proof_inventory.py:25-29, deliberately, so
# the two tools' counts are comparable on the Host/ files they both scan.
THEOREM_DECL = re.compile(
    r"^[^\S\n]*(?:@\[[^\n]*\][^\S\n]*)*(?:[^\s]+[^\S\n]+)*?"
    r"(?:theorem|lemma)[^\S\n]+(«[^»\n]+»|[^\s:([{]+)",
    re.MULTILINE,
)
# The widening predicates use an explicit modifier list rather than the
# permissive `(?:[^\s]+[^\S\n]+)*?` above: `example` and `instance` are far
# commoner substrings than `theorem`, so a permissive prefix would over-match.
_MODIFIERS = r"(?:(?:private|protected|noncomputable|nonrec|unsafe|partial|scoped|local)[^\S\n]+)*"
EXAMPLE_DECL = re.compile(
    r"^[^\S\n]*(?:@\[[^\n]*\][^\S\n]*)*" + _MODIFIERS + r"example\b",
    re.MULTILINE,
)
INSTANCE_DECL = re.compile(
    r"^[^\S\n]*(?:@\[[^\n]*\][^\S\n]*)*" + _MODIFIERS + r"instance\b",
    re.MULTILINE,
)


class ReachError(RuntimeError):
    """The inventory could not be produced at all."""


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
    """Every *.lean the repository TRACKS, keyed by the module name its path
    implies.

    Scope is `git ls-files`, not a filesystem walk: `wasm-spike/lean4-src/`
    vendors an entire untracked Lean 4 source tree (6000+ `.lean` files, with
    its own theorems) that is not this project's proof surface, and a bare
    rglob silently swallows it. Tracked-ness is the repository's own statement
    about what is its source, so it is the honest scope boundary — and it is
    still derived, never a hand-maintained list.
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
    """Derive the build roots from lakefile.toml. Never a hand-maintained list."""
    with (root / "lakefile.toml").open("rb") as handle:
        config = tomllib.load(handle)
    exe_roots: dict[str, str] = {}
    for exe in config.get("lean_exe", []):
        name = exe["name"]
        # Lake defaults an executable's root to its name when `root` is absent.
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
        tail = module[len(base) + 1 :]
        return module.startswith(f"{base}.") and "." not in tail
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


def import_closure(
    root_module: str, sources: dict[str, Path], local_roots: set[str]
) -> tuple[set[str], list[str]]:
    """Walk local imports from a root. Unresolvable local imports are reported,
    not raised, so one bad module degrades to UNCLASSIFIED instead of blinding
    the whole inventory."""
    closure: set[str] = set()
    problems: list[str] = []
    if root_module not in sources:
        return closure, [f"cannot resolve build root {root_module}"]
    queue = [root_module]
    while queue:
        module = queue.pop()
        if module in closure:
            continue
        path = sources.get(module)
        if path is None:
            # Imports into the package deps (Mathlib, SealV2, Crdt, ...) leave
            # the local tree; only a missing LOCAL module is a problem.
            if module.split(".", 1)[0] in local_roots:
                problems.append(f"cannot resolve local import {module}")
            continue
        closure.add(module)
        try:
            queue.extend(parse_imports(path))
        except (InventoryError, OSError) as exc:
            problems.append(f"{path}: {exc}")
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
    closure_problems: list[str] = []
    for exe in sorted(targets.exe_roots):
        closure, problems = import_closure(targets.exe_roots[exe], sources, local_roots)
        closures[exe] = closure
        closure_problems.extend(f"{exe}: {problem}" for problem in problems)
    # A defaultTargets entry naming a LIBRARY builds every module its globs
    # match, so those modules are elaborated by a bare `lake build` too.
    default_lib_modules: set[str] = set()
    for name in targets.default:
        for glob in targets.lib_globs.get(name, ()):
            default_lib_modules |= {m for m in sources if glob_matches(glob, m)}

    reached = closures[PROOF_WIRE_EXE]
    built_only = set().union(*(closures[e] for e in default_exes)) if default_exes else set()
    built_only |= default_lib_modules
    on_demand = set().union(*(closures[e] for e in nondefault_exes)) if nondefault_exes else set()

    rows: list[Row] = []
    errors: list[str] = list(closure_problems)
    for module, path in sources.items():
        counts = count_declarations(path)
        if isinstance(counts, str):
            errors.append(f"{path}: {counts}")
            rows.append(
                Row(module, str(path.relative_to(root)), "UNCLASSIFIED", counts,
                    -1, -1, -1, "unknown")
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
        elif any(problem.endswith(module) for problem in closure_problems):
            bucket, reason = "UNCLASSIFIED", "imports could not be resolved"
        elif module in reached:
            bucket, reason = "REACHED", f"in the {PROOF_WIRE_EXE} ({proof_wire_root}) closure"
        elif module in built_only:
            bucket, reason = "BUILT_ONLY", "in a defaultTargets closure but not the proof wire"
        elif module in on_demand:
            bucket, reason = "ON_DEMAND", "only in a declared non-default executable closure"
        else:
            bucket, reason = "ORPHANED", "in no closure any declared target walks"

        rows.append(
            Row(module, str(path.relative_to(root)), bucket, reason,
                theorems, examples, instances, where or "NONE", via)
        )

    rows.sort(key=lambda row: (row.bucket, row.module))
    summary = {
        bucket: sum(row.bucket == bucket for row in rows)
        for bucket in ("REACHED", "BUILT_ONLY", "ON_DEMAND", "ORPHANED", "UNCLASSIFIED")
    }
    return {
        "predicate": predicate,
        "proof_wire": {"exe": PROOF_WIRE_EXE, "root": proof_wire_root},
        "default_targets": list(targets.default),
        "nondefault_exes": nondefault_exes,
        "unknown_default_targets": unknown_defaults,
        "summary": summary,
        "theorem_bearing_total": len(rows),
        "lean_files_scanned": len(sources),
        "rows": [asdict(row) for row in rows],
        "errors": errors,
    }


def print_report(result: dict) -> None:
    summary = result["summary"]
    print(
        f"predicate={result['predicate']}  scanned={result['lean_files_scanned']} "
        f"theorem-bearing={result['theorem_bearing_total']}"
    )
    print(
        "  ".join(f"{bucket}={count}" for bucket, count in summary.items())
    )
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
        "--bucket", help="print only the modules in this bucket, one per line"
    )
    args = parser.parse_args()
    try:
        result = evaluate(args.root.resolve(), args.predicate)
    except (ReachError, OSError, tomllib.TOMLDecodeError) as exc:
        print(f"proof_reach: cannot produce an inventory: {exc}", file=sys.stderr)
        return 2
    if args.bucket:
        for row in result["rows"]:
            if row["bucket"] == args.bucket:
                print(row["module"])
    elif args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
