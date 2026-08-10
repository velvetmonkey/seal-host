#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail closed when the hand-maintained export surfaces drift from Ffi.lean.

The source of truth is the PROJECT root `Ffi.lean` (never the mcp-seal package's
own root `Ffi.lean`, which carries the separate `seal_v2_*` surface): its
`@[export ...]` attributes declare what the kernel offers, and its transitive
import closure declares what must link. Four hand-maintained lists follow from
that set today:

  1. scripts/build_ffi_so.sh   PROJECT_MODULES + MCP_MODULES (native .so roster)
  2. wasm-spike/build_core.sh  MODULES + SEAL_MODULES        (wasm object roster)
  3. wasm-spike/seal_wrapper.c extern decl + C wrapper per wasm-destined Lean fn
  4. wasm-spike/build_wasm.sh  emscripten EXPORTED_FUNCTIONS allow-list

Lists 1 and 2 are root sets: different roots are equivalent when their
transitive source closures cover Ffi's closure. Lists 3 and 4 fail SILENTLY:
a wasm-destined symbol absent from the wrapper or the allow-list is dropped at
link with no diagnostic, and the wasm ships doing less than the source
declares. This gate checks all four surfaces against the source of truth.

The project half of list 2 is already gated by wasm_module_closure_gate.py
(missing direction only); this gate additionally covers the mcp-seal rosters,
the native roster, the wrapper and the allow-list, and the stale direction.

mcp-seal sources are required to walk the Seal/SealCore/SealV2 import closure.
Resolution order: $SEAL_MCP_SRC, then <root>/.lake/packages/mcp-seal, then the
manifest path-type dir. A git-checkout source whose HEAD differs from the
lake-manifest pin is refused (fail closed) unless SEAL_MCP_SRC_ALLOW_MISMATCH=1.
Unavailable sources are a RED finding, not a silent skip.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
import os
import re
import shlex
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wasm_module_closure_gate import (  # noqa: E402
    GateError,
    parse_imports,
    strip_lean_comments,
)

ROOT = Path(__file__).resolve().parents[1]
FFI_SOURCE = ROOT / "Ffi.lean"
BUILD_FFI_SO = ROOT / "scripts" / "build_ffi_so.sh"
BUILD_CORE = ROOT / "wasm-spike" / "build_core.sh"
SEAL_WRAPPER = ROOT / "wasm-spike" / "seal_wrapper.c"
BUILD_WASM = ROOT / "wasm-spike" / "build_wasm.sh"
MANIFEST = ROOT / "lake-manifest.json"

MCP_ROOTS = {"Seal", "SealCore", "SealV2"}
# Roots satisfied by other dependency packages (native: whole-package thin
# archives; wasm: build-pkg/build-stdlib object trees). No per-module roster
# names them, so they are outside this gate's roster checks BY DESIGN.
OTHER_PACKAGE_ROOTS = {
    # Aesop/Batteries/Mathlib are the external proof libs build_wasm.sh covers
    # with no-op init stubs (build-core/stubs.o) and the native link covers via
    # whole-package archives. Batteries IS reached by the runtime closure today:
    # SealV2.Validation -> Seal.EncodingInjective -> Batteries.Data.Nat.Digits.
    "Aesop", "Batteries", "Calibration", "Consensus", "Crdt", "Init", "Lean",
    "Mathlib", "Std", "Temporal", "UnicodeBasic",
}
EXCLUDED_SOURCE_ROOTS = {".git", ".lake", "node_modules", "rust", "target", "wasm-spike"}

EXPORT_ATTR = re.compile(r"@\[\s*export\s+([A-Za-z_][A-Za-z0-9_]*)\s*\]")
# The Lean-facing symbols the wrapper may extern: exactly the shapes Ffi.lean
# exports today. seal_ffi_initialize / seal_lean_io_result_is_ok come from the
# hand-written shim, not from @[export], and are excluded by this prefix pair.
LEAN_EXPORT_SHAPE = re.compile(r"^seal_(host|policy)_")
KEEPALIVE_FN = re.compile(
    r"EMSCRIPTEN_KEEPALIVE\s+[A-Za-z_][A-Za-z0-9_ \t\*]*?\*?\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
EXTERN_DECL = re.compile(
    r"^\s*extern\s+[^;]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE
)
EXPORTED_FUNCTIONS = re.compile(r"EXPORTED_FUNCTIONS\s*=\s*'(\[[^']*\])'")
# emscripten runtime symbols legitimately in the allow-list without a wrapper.
RUNTIME_EXPORTS = {"_malloc", "_free"}

# Ffi.lean is the shared native/CLI and wasm export source. New exports are
# wasm-destined by default; only these source-documented native observation,
# classification, and CLI seams are deliberately outside the wasm bridge.
NATIVE_OR_CLI_ONLY_EXPORTS = {
    "seal_host_classify",
    "seal_host_mcp_revision_observe",
    "seal_host_first_agreement_unsafe_number",
    "seal_host_canonical_effect",
    "seal_policy_schema",
    "seal_policy_validate",
}

# These are membership pins, not closure approximations. The closure checks
# below establish that every module Ffi needs is reached; these pins establish
# the reverse direction, so an off-path module cannot silently join either
# build just because the required closure remains covered.
PINNED_PROJECT_MODULES = frozenset({
    "Ffi",
    "Host/Action", "Host/Audit", "Host/Canonical", "Host/Config",
    "Host/Evidence", "Host/JsonWire", "Host/Kernel", "Host/NestingDepth",
    "Host/Principal", "Host/Provenance", "Host/Registry", "Host/Sha256",
    "Host/Step", "Host/SurrogateEscapes", "Host/UnicodeKeys",
    "Kernels", "Kernels/Budget", "Kernels/BudgetCore", "Kernels/Calibration",
    "Kernels/Consensus", "Kernels/Convergence", "Kernels/Linear",
    "Kernels/LinearCore", "Kernels/PrincipalBudget", "Kernels/Safety",
    "Kernels/Temporal",
})
PINNED_MCP_MODULES = frozenset({
    "SealCore", "SealCore.Automaton", "SealCore.Event", "SealCore.Safety",
    "SealCore.Sha256", "Seal.Block", "Seal.Channel", "Seal.Classify",
    "Seal.Hash", "Seal.JsonUtil", "Seal.Policy", "Seal.PolicyBundle",
    "SealV2.Canonical", "SealV2.Crypto", "SealV2.Decide",
    "SealV2.EffectEnvelope", "SealV2.Escape", "SealV2.McpVersionGate",
    "SealV2.Parser", "SealV2.Serialization", "SealV2.Validation",
})
PINNED_WASM_MODULES = PINNED_PROJECT_MODULES
PINNED_SEAL_MODULES = frozenset({
    "SealCore", "SealCore/Automaton", "SealCore/Event", "SealCore/Safety",
    "SealCore/Sha256", "Seal/Block", "Seal/Channel", "Seal/Classify",
    "Seal/EffectCommitment", "Seal/EncodingInjective", "Seal/Hash",
    "Seal/JsonUtil", "Seal/Policy", "Seal/PolicyBundle", "Seal/PolicyWire",
    "SealV2/Canonical", "SealV2/Crypto", "SealV2/Decide",
    "SealV2/EffectEnvelope", "SealV2/Escape", "SealV2/McpVersionGate",
    "SealV2/Parser", "SealV2/Serialization", "SealV2/Validation",
})


@dataclass
class Findings:
    """Named drift, grouped by the list it was found in."""

    sections: dict[str, list[str]] = field(default_factory=dict)

    def add(self, section: str, message: str) -> None:
        self.sections.setdefault(section, []).append(message)

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.sections.values())


def parse_bash_array(path: Path, name: str) -> list[str]:
    """Parse `NAME=( ... )` from a bash script, comments stripped."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise GateError(f"cannot read {path}: {exc}") from exc
    starts = [
        (n, line) for n, line in enumerate(lines, start=1)
        if re.match(rf"^\s*{re.escape(name)}\s*=\s*\(", line)
    ]
    if len(starts) != 1:
        raise GateError(
            f"expected exactly one {name}=( assignment in {path}, found {len(starts)}"
        )
    line_number, line = starts[0]
    body: list[str] = []
    remainder = line.split("=(", 1)[1]
    terminated = False
    for current_number in range(line_number, len(lines) + 1):
        current = remainder if current_number == line_number else lines[current_number - 1]
        # Roster entries never contain '#' or ')', so cut trailing comments
        # before scanning for the terminator.
        effective = current.split("#", 1)[0]
        if ")" in effective:
            before, after = effective.split(")", 1)
            if after.strip():
                raise GateError(f"unexpected text after {name} array at {path}:{current_number}")
            body.append(before)
            terminated = True
            break
        body.append(effective)
    if not terminated:
        raise GateError(f"unterminated {name} array beginning at {path}:{line_number}")
    try:
        entries = shlex.split("\n".join(body), comments=True, posix=True)
    except ValueError as exc:
        raise GateError(f"cannot parse {name} array from {path}: {exc}") from exc
    if not entries:
        raise GateError(f"{name} array in {path} is empty; refusing vacuous check")
    duplicates = sorted({e for e in entries if entries.count(e) > 1})
    if duplicates:
        raise GateError(f"duplicate {name} entries in {path}: {', '.join(duplicates)}")
    return entries


def require_exact_roster(
    findings: Findings,
    section: str,
    path: Path,
    name: str,
    expected: frozenset[str],
) -> list[str]:
    """Read one roster and require exact declared membership both ways."""
    entries = parse_bash_array(path, name)
    actual = set(entries)
    missing = sorted(expected - actual)
    undeclared = sorted(actual - expected)
    if missing or undeclared:
        findings.add(
            section,
            f"{name} membership differs from its review pin; "
            f"missing={missing!r}; undeclared={undeclared!r}",
        )
    return entries


def dotted(module: str) -> str:
    return module.replace("/", ".")


def parse_exports(source: Path = FFI_SOURCE) -> list[str]:
    try:
        text = strip_lean_comments(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GateError(f"cannot read {source}: {exc}") from exc
    exports = EXPORT_ATTR.findall(text)
    if not exports:
        raise GateError(f"no @[export] attributes found in {source}; refusing vacuous check")
    duplicates = sorted({e for e in exports if exports.count(e) > 1})
    if duplicates:
        raise GateError(f"duplicate @[export] names in {source}: {', '.join(duplicates)}")
    return exports


def project_sources(root: Path = ROOT) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    for path in root.rglob("*.lean"):
        relative = path.relative_to(root)
        if relative.parts[0] in EXCLUDED_SOURCE_ROOTS:
            continue
        module = ".".join(relative.with_suffix("").parts)
        sources[module] = path
    return sources


def mcp_source_root() -> Path | None:
    env = os.environ.get("SEAL_MCP_SRC")
    candidates = [Path(env)] if env else []
    candidates.append(ROOT / ".lake" / "packages" / "mcp-seal")
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot read {MANIFEST}: {exc}") from exc
    package = next(
        (p for p in manifest.get("packages", []) if "mcp-seal" in p.get("name", "")), None
    )
    if package is None:
        raise GateError(f"no mcp-seal package in {MANIFEST}")
    if package.get("type") == "path":
        candidates.append((ROOT / package["dir"]).resolve())
    for candidate in candidates:
        if candidate.is_dir() and (candidate / "SealV2.lean").is_file():
            if package.get("type") == "git" and (candidate / ".git").exists():
                head = subprocess.run(
                    ["git", "-C", str(candidate), "rev-parse", "HEAD"],
                    capture_output=True, text=True,
                ).stdout.strip()
                pin = package.get("rev", "")
                if head != pin and os.environ.get("SEAL_MCP_SRC_ALLOW_MISMATCH") != "1":
                    raise GateError(
                        f"mcp-seal source at {candidate} is at {head[:12]} but the "
                        f"manifest pins {pin[:12]}; refusing to derive the closure "
                        "from unpinned sources (SEAL_MCP_SRC_ALLOW_MISMATCH=1 overrides)"
                    )
            return candidate
    return None


def mcp_sources(mcp_root: Path) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    for path in mcp_root.rglob("*.lean"):
        relative = path.relative_to(mcp_root)
        if relative.parts[0] in {".git", ".lake", "c", "demo", "docs", "config"}:
            continue
        module = ".".join(relative.with_suffix("").parts)
        if module.split(".", 1)[0] in MCP_ROOTS:
            sources[module] = path
    if not sources:
        raise GateError(f"no Seal/SealCore/SealV2 sources under {mcp_root}")
    return sources


def import_closure(
    sources: dict[str, Path], start: str
) -> tuple[set[str], set[tuple[str, str]]]:
    """Walk imports from `start` over `sources`; return (closure, unresolved)."""
    known_roots = MCP_ROOTS | OTHER_PACKAGE_ROOTS | {
        m.split(".", 1)[0] for m in sources
    }
    queue = [start]
    closure: set[str] = set()
    unresolved: set[tuple[str, str]] = set()
    while queue:
        module = queue.pop()
        if module in closure:
            continue
        path = sources.get(module)
        if path is None:
            continue
        closure.add(module)
        for imported in parse_imports(path):
            if imported in sources:
                queue.append(imported)
            elif imported.split(".", 1)[0] not in known_roots:
                unresolved.add((imported, module))
    return closure, unresolved


def roster_closure_check(
    findings: Findings, section: str, listed: list[str], expected: set[str],
    sources: dict[str, Path], scope: str,
) -> None:
    """Require a roster's transitive closure to cover the Ffi closure.

    Build rosters are root sets, so spelling an already-transitive module is
    cosmetic. Extra roots are harmless; missing effective closure is not.
    """
    listed_set = {dotted(m) for m in listed}
    effective: set[str] = set()
    for root in sorted(listed_set):
        if root not in sources:
            findings.add(section, f"cannot resolve {scope} root: {root}")
            continue
        closure, _ = import_closure(sources, root)
        effective |= closure
    for module in sorted(expected - effective):
        findings.add(section, f"not reached by transitive closure of {scope}: {module}")


def main() -> int:
    findings = Findings()
    exports = parse_exports()
    export_set = set(exports)
    for export in sorted(NATIVE_OR_CLI_ONLY_EXPORTS - export_set):
        findings.add(
            "export ownership",
            f"native/CLI-only declaration has no matching @[export]: {export}",
        )
    wasm_exports = [e for e in exports if e not in NATIVE_OR_CLI_ONLY_EXPORTS]
    if not wasm_exports:
        raise GateError("no wasm-destined exports remain; refusing vacuous wrapper check")

    # --- source of truth: the Ffi import closure --------------------------
    proj = project_sources()
    proj_closure, unresolved = import_closure(proj, "Ffi")
    if "Ffi" not in proj_closure:
        raise GateError("cannot resolve the project root module Ffi")
    direct_mcp = {
        imported
        for module in proj_closure
        for imported in parse_imports(proj[module])
        if imported.split(".", 1)[0] in MCP_ROOTS
    }
    mcp_root = mcp_source_root()
    if mcp_root is None:
        findings.add(
            "source-of-truth",
            "mcp-seal sources unavailable (no .lake checkout; set SEAL_MCP_SRC): "
            "the Seal/SealCore/SealV2 closure is UNVERIFIED beyond direct imports",
        )
        mcp_closure = set(direct_mcp)
    else:
        mcp_srcs = mcp_sources(mcp_root)
        mcp_closure = set()
        for entry in sorted(direct_mcp):
            sub, sub_unresolved = import_closure(mcp_srcs, entry)
            if not sub:
                findings.add(
                    "source-of-truth",
                    f"direct import {entry} not found in mcp-seal sources at {mcp_root}",
                )
            mcp_closure |= sub
            unresolved |= sub_unresolved
    for imported, importer in sorted(unresolved):
        findings.add("source-of-truth", f"unresolvable import {imported} (from {importer})")

    project_part = {
        m for m in proj_closure if m.split(".", 1)[0] not in MCP_ROOTS | OTHER_PACKAGE_ROOTS
    }

    # --- list 1: scripts/build_ffi_so.sh ----------------------------------
    project_modules = require_exact_roster(
        findings, "build_ffi_so.sh", BUILD_FFI_SO, "PROJECT_MODULES",
        PINNED_PROJECT_MODULES,
    )
    mcp_modules = require_exact_roster(
        findings, "build_ffi_so.sh", BUILD_FFI_SO, "MCP_MODULES",
        PINNED_MCP_MODULES,
    )
    roster_closure_check(
        findings, "build_ffi_so.sh",
        project_modules,
        project_part, proj, "PROJECT_MODULES",
    )
    if mcp_root is not None:
        roster_closure_check(
            findings, "build_ffi_so.sh",
            mcp_modules,
            mcp_closure, mcp_srcs, "MCP_MODULES",
        )

    # --- list 2: wasm-spike/build_core.sh ---------------------------------
    wasm_modules = require_exact_roster(
        findings, "build_core.sh", BUILD_CORE, "MODULES", PINNED_WASM_MODULES,
    )
    seal_modules = require_exact_roster(
        findings, "build_core.sh", BUILD_CORE, "SEAL_MODULES",
        PINNED_SEAL_MODULES,
    )
    roster_closure_check(
        findings, "build_core.sh",
        wasm_modules,
        project_part, proj, "MODULES",
    )
    if mcp_root is not None:
        roster_closure_check(
            findings, "build_core.sh",
            seal_modules,
            mcp_closure, mcp_srcs, "SEAL_MODULES",
        )

    # --- list 3: wasm-spike/seal_wrapper.c --------------------------------
    try:
        wrapper_text = SEAL_WRAPPER.read_text(encoding="utf-8")
    except OSError as exc:
        raise GateError(f"cannot read {SEAL_WRAPPER}: {exc}") from exc
    externs = set(EXTERN_DECL.findall(wrapper_text))
    wrappers = KEEPALIVE_FN.findall(wrapper_text)
    if not wrappers:
        raise GateError(f"no EMSCRIPTEN_KEEPALIVE wrappers found in {SEAL_WRAPPER}")
    # Which exports each wrapper body calls: a call site is the symbol followed
    # by '(' somewhere after the extern declaration block.
    decl_free = re.sub(r"^\s*extern[^;]*;", "", wrapper_text, flags=re.MULTILINE)
    called = {
        e for e in wasm_exports
        if re.search(rf"\b{re.escape(e)}\s*\(", decl_free)
    }
    for export in wasm_exports:
        if export not in externs:
            findings.add("seal_wrapper.c", f"no extern declaration for export: {export}")
        if export not in called:
            findings.add("seal_wrapper.c", f"no C wrapper calls export: {export}")
    for name in sorted(externs):
        if LEAN_EXPORT_SHAPE.match(name) and name not in exports:
            findings.add("seal_wrapper.c", f"stale extern (no such @[export] in Ffi.lean): {name}")

    # --- list 4: wasm-spike/build_wasm.sh ---------------------------------
    try:
        wasm_text = BUILD_WASM.read_text(encoding="utf-8")
    except OSError as exc:
        raise GateError(f"cannot read {BUILD_WASM}: {exc}") from exc
    match = EXPORTED_FUNCTIONS.search(wasm_text)
    if not match:
        raise GateError(f"cannot parse EXPORTED_FUNCTIONS from {BUILD_WASM}")
    try:
        allow_list = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        raise GateError(f"EXPORTED_FUNCTIONS in {BUILD_WASM} is not valid JSON: {exc}") from exc
    allow = set(allow_list)
    for wrapper in wrappers:
        if f"_{wrapper}" not in allow:
            findings.add(
                "build_wasm.sh",
                f"wrapper {wrapper} missing from EXPORTED_FUNCTIONS (_{wrapper}): "
                "the symbol is silently dropped at link",
            )
    wrapper_symbols = {f"_{w}" for w in wrappers} | RUNTIME_EXPORTS
    for symbol in sorted(allow - wrapper_symbols):
        findings.add(
            "build_wasm.sh",
            f"EXPORTED_FUNCTIONS entry with no EMSCRIPTEN_KEEPALIVE wrapper: {symbol}",
        )

    # --- verdict ----------------------------------------------------------
    print(
        f"export surface: {len(exports)} @[export] names in Ffi.lean "
        f"({len(wasm_exports)} wasm, {len(exports) - len(wasm_exports)} native/CLI); "
        f"closure: {len(project_part)} project + {len(mcp_closure)} mcp-seal modules "
        f"({len(proj_closure - project_part)} other-package refs out of roster scope)"
    )
    sections = [
        "export ownership", "source-of-truth", "build_ffi_so.sh", "build_core.sh",
        "seal_wrapper.c", "build_wasm.sh",
    ]
    for section in sections:
        rows = findings.sections.get(section, [])
        status = "PASS" if not rows else f"RED ({len(rows)})"
        print(f"  [{status:>8}] {section}")
        for row in rows:
            print(f"      - {row}")
    if findings.total:
        print(f"EXPORT SURFACE RED: {findings.total} finding(s)", file=sys.stderr)
        return 1
    print("EXPORT SURFACE PASS: all four lists agree with Ffi.lean")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as exc:
        print(f"EXPORT SURFACE RED: {exc}", file=sys.stderr)
        raise SystemExit(1)
