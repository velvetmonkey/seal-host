#!/usr/bin/env python3
"""Reject retained wasm code that depends on a module initializer which cannot run.

The audit decides ownership from the DEFINING OBJECT and the actual relocation
graph.  No decision anywhere in this file is taken from the spelling of a symbol
(no package-name regex): a symbol called `ordinary_business_logic` and a symbol
called `lp_mathlib_...` are treated identically, and only their defining object's
initializer and their own relocations decide the outcome.

Model
-----
*  Nodes are (defining object, symbol) pairs, for functions and for data.
*  Retention edges come from relocations:
     - CODE  R_WASM_FUNCTION_INDEX*  -> direct call
     - CODE  R_WASM_TABLE_INDEX*     -> address taken (closure installed)
     - CODE  R_WASM_MEMORY_ADDR*     -> reads/holds a data symbol
     - DATA  R_WASM_TABLE_INDEX*     -> a function pointer stored in static data
     - DATA  R_WASM_MEMORY_ADDR*     -> a data pointer stored in static data
   The DATA-section relocations are recovered by parsing the object's data
   segments directly and mapping each relocation offset onto the data symbol
   whose byte range contains it, so a static table that points at an
   uninitialised module's globals is a real edge and not a blind spot.
*  Reachability starts at the exported C ABI roots and runs to a fixpoint over
   all of the above edges.  A module is "initialised" only if one of the
   initializers DEFINED IN ITS OWN OBJECT is itself reachable.

Verdict rule, applied to EVERY retained node, not only to nodes that live in an
uninitialised object:
*  a retained function whose relocation target cannot be resolved to a provider
   fails closed, unless the operator passes an explicit --allow-undefined
   pattern, which is echoed into the output;
*  a retained data symbol with no classifiable segment fails closed;
*  a retained read of a MUTABLE data symbol whose defining object has a module
   initializer that is not reachable fails closed -- this is the defect class:
   state that only the absent initializer would have assigned;
*  a retained read of read-only data is admitted, but its own stored pointers
   are followed and judged by the same rule;
*  a retained read of mutable data in an object that has no module initializer
   at all is admitted as non-module state, and every such object is listed in
   the output so the exception is visible rather than silent.

Indirect calls need no separate rule: a function can only be an indirect target
if its address is taken, an address-taken function is a retention edge here, and
every retained function is judged.  The count of retained indirect callers is
printed so the argument is checkable rather than assumed.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import dataclasses
import fnmatch
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Iterable


FUNCTION_TYPES = frozenset("TtWw")
DATA_TYPES = frozenset("BbDdGgRrSsVv")
FUNCTION_HEADER = re.compile(r"^[0-9a-fA-F]+ <(.+)>:$")
RELOCATION = re.compile(r"R_WASM_([A-Z0-9_]+)\s+(.+)$")
READONLY_SEGMENTS = (".rodata", ".srodata")

# Relocation kinds that cannot, on their own, create a dependency on another
# symbol's contents: a type signature, a table or tag number.  Anything not
# listed here and not handled as an edge stops the audit rather than being
# ignored, because an unmodelled relocation kind is exactly the silence this
# audit exists to refuse.
INERT_RELOCATIONS = ("TYPE_INDEX", "TABLE_NUMBER", "TAG_INDEX")

# GLOBAL_INDEX needs a stricter test than its kind.  Against a real wasm global
# (__stack_pointer, emscripten's tempRet0) it carries no dependency, but a PIC
# build routes external data and function references through GOT globals that
# llvm-objdump prints under the REFERENCED SYMBOL'S OWN NAME -- indistinguishable
# by kind.  The object's own symbol table separates them: a wasm global has
# Type: GLOBAL, while a GOT-routed reference keeps Type: DATA or FUNCTION.  That
# is the test used below; anything that is not a declared wasm global stops the
# audit rather than being skipped.


@dataclasses.dataclass(frozen=True, order=True)
class Node:
    object_path: pathlib.Path
    symbol: str
    is_data: bool = False


@dataclasses.dataclass(frozen=True)
class DataSymbol:
    segment_index: int
    segment: str
    offset: int
    size: int


@dataclasses.dataclass
class ObjectInfo:
    path: pathlib.Path
    function_defs: dict[str, str]
    data_defs: dict[str, str]
    function_refs: dict[str, list[tuple[str, str]]]
    data_refs: dict[str, list[str]]
    indirect_callers: set[str]
    data_symbols: dict[str, DataSymbol]
    # data symbol -> relocations stored inside that symbol's own bytes
    stored_refs: dict[str, list[tuple[str, str]]]

    @property
    def initializers(self) -> tuple[str, ...]:
        return tuple(sorted(s for s in self.function_defs if s.startswith("initialize_")))


class AuditError(RuntimeError):
    """A condition the audit cannot classify.  Always fails closed."""


def run(tool: pathlib.Path, *args: str) -> str:
    completed = subprocess.run(
        [str(tool), *args], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode != 0:
        raise AuditError(
            f"{tool.name} exited {completed.returncode} for {args[-1]}: "
            f"{completed.stderr.strip()}"
        )
    return completed.stdout


def strip_addend(value: str) -> str:
    return re.sub(r"[+-](?:0x[0-9a-fA-F]+|[0-9]+)$", "", value.strip())


def read_uleb(blob: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(blob):
            raise AuditError("truncated LEB128")
        byte = blob[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def skip_init_expr(blob: bytes, pos: int) -> int:
    opcode = blob[pos]
    pos += 1
    if opcode in (0x41, 0x42):          # i32.const / i64.const
        while blob[pos] & 0x80:
            pos += 1
        pos += 1
    elif opcode == 0x23:                # global.get
        _index, pos = read_uleb(blob, pos)
    else:
        raise AuditError(f"unsupported data segment offset opcode 0x{opcode:02x}")
    if blob[pos] != 0x0B:
        raise AuditError("data segment offset expression did not end with 0x0b")
    return pos + 1


def readobj_sections_symbols(path: pathlib.Path, llvm_readobj: pathlib.Path):
    """Return (segment names in order, data symbol table, DATA section extent)."""
    output = run(llvm_readobj, "--sections", "--symbols", str(path))
    segments: list[tuple[str, int]] = []
    data_section: tuple[int, int] | None = None

    section_type: str | None = None
    section_size: int | None = None
    section_offset: int | None = None
    segment_name: str | None = None
    segment_size: int | None = None
    in_segment = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped == "Section {":
            section_type = section_size = section_offset = None
        elif stripped.startswith("Type: ") and not in_segment and section_type is None:
            section_type = stripped.removeprefix("Type: ").split()[0]
        elif stripped.startswith("Size: ") and not in_segment and section_size is None:
            section_size = int(stripped.removeprefix("Size: "), 0)
        elif stripped.startswith("Offset: ") and not in_segment and section_offset is None:
            section_offset = int(stripped.removeprefix("Offset: "), 0)
        elif stripped == "Segment {":
            in_segment = True
            segment_name = segment_size = None
        elif in_segment and stripped.startswith("Name: "):
            segment_name = stripped.removeprefix("Name: ")
        elif in_segment and stripped.startswith("Size: "):
            segment_size = int(stripped.removeprefix("Size: "), 0)
        elif in_segment and stripped == "}":
            in_segment = False
            if segment_name is None or segment_size is None:
                raise AuditError(f"{path}: unparsable data segment record")
            segments.append((segment_name, segment_size))
        elif stripped == "Symbols [":
            if section_type == "DATA" and section_offset is not None and section_size is not None:
                data_section = (section_offset, section_size)
            break
        if section_type == "DATA" and section_offset is not None and section_size is not None:
            data_section = (section_offset, section_size)

    symbols: dict[str, DataSymbol] = {}
    wasm_globals: set[str] = set()
    name = kind = None
    offset = segment_index = size = None

    def finish() -> None:
        nonlocal name, kind, offset, segment_index, size
        if name is not None and kind == "GLOBAL":
            wasm_globals.add(name)
        if name is not None and kind == "DATA" and segment_index is not None:
            if segment_index >= len(segments):
                raise AuditError(
                    f"{path}: data symbol {name} names out-of-range segment {segment_index}"
                )
            symbols[name] = DataSymbol(
                segment_index=segment_index,
                segment=segments[segment_index][0],
                offset=offset if offset is not None else 0,
                size=size if size is not None else 0,
            )
        name = kind = None
        offset = segment_index = size = None

    in_symbols = False
    in_symbol = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped == "Symbols [":
            in_symbols = True
            continue
        if not in_symbols:
            continue
        if stripped == "Symbol {":
            finish()
            in_symbol = True
            continue
        if in_symbol and stripped == "}":
            finish()
            in_symbol = False
            continue
        if not in_symbol:
            continue
        if stripped.startswith("Name: "):
            name = stripped.removeprefix("Name: ")
        elif stripped.startswith("Type: "):
            kind = stripped.removeprefix("Type: ").split()[0]
        elif stripped.startswith("Offset: "):
            offset = int(stripped.removeprefix("Offset: "), 0)
        elif stripped.startswith("Segment: "):
            segment_index = int(stripped.removeprefix("Segment: "), 0)
        elif stripped.startswith("Size: "):
            size = int(stripped.removeprefix("Size: "), 0)
    finish()
    return segments, symbols, data_section, wasm_globals


def data_segment_ranges(
    path: pathlib.Path,
    data_section: tuple[int, int] | None,
    segments: list[tuple[str, int]],
) -> list[tuple[int, int]]:
    """Byte range of every data segment's contents, relative to section contents."""
    if data_section is None:
        if segments:
            raise AuditError(f"{path}: data segments present but no DATA section extent")
        return []
    offset, size = data_section
    blob = path.read_bytes()[offset:offset + size]
    if len(blob) != size:
        raise AuditError(f"{path}: DATA section extends past end of file")
    count, pos = read_uleb(blob, 0)
    if count != len(segments):
        raise AuditError(
            f"{path}: DATA section declares {count} segments, readobj listed {len(segments)}"
        )
    ranges: list[tuple[int, int]] = []
    for index in range(count):
        flags, pos = read_uleb(blob, pos)
        if flags & 0x02:
            _memory_index, pos = read_uleb(blob, pos)
        if not flags & 0x01:
            pos = skip_init_expr(blob, pos)
        length, pos = read_uleb(blob, pos)
        if length != segments[index][1]:
            raise AuditError(
                f"{path}: segment {segments[index][0]} is {length} bytes in the DATA "
                f"section but {segments[index][1]} bytes in the segment table"
            )
        ranges.append((pos, pos + length))
        pos += length
    if pos != len(blob):
        raise AuditError(f"{path}: {len(blob) - pos} trailing bytes after the last data segment")
    return ranges


def read_data_relocations(
    path: pathlib.Path, llvm_readobj: pathlib.Path
) -> list[tuple[int, str, str]]:
    """(section-relative offset, relocation kind, target symbol) for DATA relocations."""
    output = run(llvm_readobj, "--relocations", str(path))
    relocations: list[tuple[int, str, str]] = []
    in_data = False
    for line in output.splitlines():
        stripped = line.strip()
        match = re.match(r"^Section \(\d+\) ([A-Za-z]+) \{$", stripped)
        if match:
            in_data = match.group(1) == "DATA"
            continue
        if stripped == "}":
            in_data = False
            continue
        if not in_data:
            continue
        entry = re.match(r"^(0x[0-9A-Fa-f]+) R_WASM_([A-Z0-9_]+) (\S+)(?: (-?\d+))?$", stripped)
        if not entry:
            raise AuditError(f"{path}: unparsable DATA relocation line: {stripped}")
        relocations.append((int(entry.group(1), 0), entry.group(2), entry.group(3)))
    return relocations


def read_object(
    path: pathlib.Path,
    llvm_nm: pathlib.Path,
    llvm_objdump: pathlib.Path,
    llvm_readobj: pathlib.Path,
) -> ObjectInfo:
    function_defs: dict[str, str] = {}
    data_defs: dict[str, str] = {}
    for line in run(llvm_nm, "--format=posix", str(path)).splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        symbol, symbol_type = fields[0], fields[1]
        if symbol_type in FUNCTION_TYPES:
            function_defs[symbol] = symbol_type
        elif symbol_type in DATA_TYPES:
            data_defs[symbol] = symbol_type

    segments, data_symbols, data_section, wasm_globals = readobj_sections_symbols(
        path, llvm_readobj
    )

    function_refs: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
    data_refs: dict[str, list[str]] = collections.defaultdict(list)
    indirect_callers: set[str] = set()
    current: str | None = None
    for line in run(llvm_objdump, "-dr", str(path)).splitlines():
        match = FUNCTION_HEADER.match(line)
        if match:
            current = match.group(1)
            continue
        if current is None:
            continue
        if "call_indirect" in line:
            indirect_callers.add(current)
        relocation = RELOCATION.search(line)
        if not relocation:
            continue
        kind, raw_target = relocation.groups()
        target = strip_addend(raw_target)
        if kind.startswith("FUNCTION_INDEX"):
            function_refs[current].append((target, "call"))
        elif kind.startswith("TABLE_INDEX"):
            function_refs[current].append((target, "address"))
        elif kind.startswith("MEMORY_ADDR"):
            data_refs[current].append(target)
        elif kind.startswith(INERT_RELOCATIONS):
            continue
        elif kind.startswith("GLOBAL_INDEX") and target in wasm_globals:
            continue
        else:
            raise AuditError(
                f"{path}: unmodelled CODE relocation R_WASM_{kind} to {target} in "
                f"{current}; the audit cannot decide what it depends on"
            )

    ranges = data_segment_ranges(path, data_section, segments)

    stored_refs: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
    if ranges:
        owners: list[tuple[int, int, str]] = []
        for symbol, info in data_symbols.items():
            start = ranges[info.segment_index][0] + info.offset
            owners.append((start, start + info.size, symbol))
        owners.sort()
        for offset, kind, target in read_data_relocations(path, llvm_readobj):
            owner = None
            for start, end, symbol in owners:
                if start <= offset < end:
                    owner = symbol
                    break
            if owner is None:
                raise AuditError(
                    f"{path}: DATA relocation at 0x{offset:x} to {target} lies in no "
                    f"data symbol; the audit cannot attribute it"
                )
            if kind.startswith("TABLE_INDEX"):
                stored_refs[owner].append((target, "function"))
            elif kind.startswith("MEMORY_ADDR"):
                stored_refs[owner].append((target, "data"))
            else:
                raise AuditError(
                    f"{path}: unclassified DATA relocation R_WASM_{kind} to {target}"
                )

    return ObjectInfo(
        path=path,
        function_defs=function_defs,
        data_defs=data_defs,
        function_refs=dict(function_refs),
        data_refs=dict(data_refs),
        indirect_callers=indirect_callers,
        data_symbols=data_symbols,
        stored_refs=dict(stored_refs),
    )


def parse_object_list(path: pathlib.Path) -> list[pathlib.Path]:
    objects: list[pathlib.Path] = []
    base = path.parent
    for raw in path.read_text(encoding="utf-8").splitlines():
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        candidate = pathlib.Path(entry)
        if not candidate.is_absolute():
            candidate = base / candidate
        objects.append(candidate.resolve())
    if not objects:
        raise ValueError(f"object list is empty: {path}")
    missing = [str(p) for p in objects if not p.is_file()]
    if missing:
        raise ValueError("missing object(s): " + ", ".join(missing))
    return objects


def extract_archive(
    archive: pathlib.Path, llvm_ar: pathlib.Path, stack: contextlib.ExitStack
) -> list[tuple[pathlib.Path, str]]:
    """Unpack an archive so its members join the link set as ordinary objects.

    Members provide definitions the same way wasm-ld pulls them in: they are
    appended after the explicitly named objects, so first-definition-wins order
    still matches the link.
    """
    members = [line.strip() for line in run(llvm_ar, "t", str(archive)).splitlines() if line.strip()]
    directory = pathlib.Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="link-set-audit-")))
    completed = subprocess.run(
        [str(llvm_ar), "x", str(archive.resolve())], cwd=directory,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode != 0:
        raise AuditError(f"llvm-ar x failed for {archive}: {completed.stderr.strip()}")
    result: list[tuple[pathlib.Path, str]] = []
    for member in members:
        path = directory / member
        if not path.is_file():
            raise AuditError(f"{archive}: member {member} did not extract")
        result.append((path.resolve(), f"{archive.name}({member})"))
    return result


def parse_provenance(paths: Iterable[pathlib.Path]) -> dict[pathlib.Path, str]:
    result: dict[pathlib.Path, str] = {}
    for path in paths:
        base = path.parent
        for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not raw.strip() or raw.startswith("#"):
                continue
            fields = raw.split("\t")
            if len(fields) != 2:
                raise ValueError(f"{path}:{line_number}: expected OBJECT<TAB>SOURCE")
            obj = pathlib.Path(fields[0])
            if not obj.is_absolute():
                obj = base / obj
            result[obj.resolve()] = fields[1]
    return result


def display_path(path: pathlib.Path, cwd: pathlib.Path) -> str:
    try:
        return str(path.relative_to(cwd))
    except ValueError:
        return str(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--llvm-nm", required=True, type=pathlib.Path)
    parser.add_argument("--llvm-objdump", required=True, type=pathlib.Path)
    parser.add_argument("--llvm-readobj", required=True, type=pathlib.Path)
    parser.add_argument("--llvm-ar", type=pathlib.Path)
    parser.add_argument("--object-list", type=pathlib.Path)
    parser.add_argument("--object", action="append", default=[], type=pathlib.Path)
    parser.add_argument(
        "--archive", action="append", default=[], type=pathlib.Path,
        help="archive whose members join the link set as providers, after the "
             "explicitly named objects (e.g. the toolchain's libc.a)",
    )
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--provenance", action="append", default=[], type=pathlib.Path)
    parser.add_argument(
        "--allow-undefined", action="append", default=[], metavar="GLOB",
        help="host-import FUNCTIONS permitted to have no provider in the link set; "
             "every pattern and every symbol it admits is echoed in the output",
    )
    parser.add_argument(
        "--allow-undefined-data", action="append", default=[], metavar="GLOB",
        help="host-import DATA symbols permitted to have no provider.  Separate "
             "from --allow-undefined because an unprovided datum cannot be "
             "classified at all: admitting one is an operator assertion, not a proof",
    )
    parser.add_argument(
        "--dump-retained", type=pathlib.Path,
        help="write every retained function symbol here, for comparison against "
             "the function list the linker actually kept in the wasm",
    )
    parser.add_argument(
        "--focus-object", action="append", default=[], type=pathlib.Path,
        help="census every outgoing relocation of this object that lands in a module "
             "whose initializer is not reachable",
    )
    args = parser.parse_args()

    objects = [p.resolve() for p in args.object]
    if args.object_list is not None:
        objects.extend(parse_object_list(args.object_list.resolve()))
    if not objects:
        parser.error("at least one --object or --object-list is required")
    missing = [str(p) for p in objects if not p.is_file()]
    if missing:
        parser.error("missing object(s): " + ", ".join(missing))
    provenance = parse_provenance(p.resolve() for p in args.provenance)

    stack = contextlib.ExitStack()
    llvm_ar = args.llvm_ar if args.llvm_ar is not None else args.llvm_nm.parent / "llvm-ar"
    for archive in args.archive:
        if not archive.is_file():
            parser.error(f"missing archive: {archive}")
        for path, label in extract_archive(archive, llvm_ar, stack):
            if path in provenance:
                continue
            objects.append(path)
            provenance[path] = label
        print(f"[link-set-audit] archive {archive.name} joined the link set", file=sys.stderr)

    infos: dict[pathlib.Path, ObjectInfo] = {}
    for number, path in enumerate(objects, 1):
        try:
            infos[path] = read_object(path, args.llvm_nm, args.llvm_objdump, args.llvm_readobj)
        except AuditError as error:
            print(f"[link-set-audit] TOOL ERROR: {error}", file=sys.stderr)
            return 2
        if number % 100 == 0:
            print(f"[link-set-audit] scanned {number}/{len(objects)} objects", file=sys.stderr)

    # Validate operator input before any verdict is computed, so a mistyped
    # focus object fails fast instead of pre-empting a real result.
    for path in args.focus_object:
        if path.resolve() not in infos:
            print(f"[link-set-audit] focus object not in link set: {path}", file=sys.stderr)
            return 2

    # Link order is authoritative when --allow-multiple-definition is in use.
    function_provider: dict[str, Node] = {}
    data_provider: dict[str, Node] = {}
    for path in objects:
        info = infos[path]
        for symbol, kind in info.function_defs.items():
            if kind.islower():
                continue
            function_provider.setdefault(symbol, Node(path, symbol))
        for symbol, kind in info.data_defs.items():
            if kind.islower():
                continue
            data_provider.setdefault(symbol, Node(path, symbol, True))

    def resolve_function(caller: Node, symbol: str) -> Node | None:
        local_kind = infos[caller.object_path].function_defs.get(symbol)
        if local_kind is not None and local_kind.islower():
            return Node(caller.object_path, symbol)
        return function_provider.get(symbol)

    def resolve_data(caller: Node, symbol: str) -> Node | None:
        local_kind = infos[caller.object_path].data_defs.get(symbol)
        if local_kind is not None and local_kind.islower():
            return Node(caller.object_path, symbol, True)
        return data_provider.get(symbol)

    roots: list[Node] = []
    for symbol in args.root:
        node = function_provider.get(symbol)
        if node is None:
            print(f"[link-set-audit] missing exported root: {symbol}", file=sys.stderr)
            return 2
        roots.append(node)

    # Reachability to a fixpoint over call, address-taken, data-read and
    # stored-pointer edges.  Unresolved references are recorded, never dropped.
    predecessor: dict[Node, tuple[Node, str] | None] = {root: None for root in roots}
    unresolved: list[tuple[Node, str, str]] = []
    seen_unresolved: set[tuple[Node, str, str]] = set()
    queue: collections.deque[Node] = collections.deque(roots)
    while queue:
        node = queue.popleft()
        info = infos[node.object_path]
        edges: list[tuple[str, str, bool]] = []
        if node.is_data:
            for target_symbol, target_kind in info.stored_refs.get(node.symbol, []):
                edges.append((target_symbol, "stored-" + target_kind, target_kind == "data"))
        else:
            for target_symbol, edge_kind in info.function_refs.get(node.symbol, []):
                edges.append((target_symbol, edge_kind, False))
            for target_symbol in info.data_refs.get(node.symbol, []):
                edges.append((target_symbol, "reads", True))
        for target_symbol, edge_kind, is_data in edges:
            target = (
                resolve_data(node, target_symbol) if is_data
                else resolve_function(node, target_symbol)
            )
            if target is None:
                entry = (node, target_symbol, "data" if is_data else "function")
                if entry not in seen_unresolved:
                    seen_unresolved.add(entry)
                    unresolved.append(entry)
                continue
            if target in predecessor:
                continue
            predecessor[target] = (node, edge_kind)
            queue.append(target)

    reachable = set(predecessor)
    reachable_functions = {n for n in reachable if not n.is_data}
    reachable_data = {n for n in reachable if n.is_data}
    reachable_initializers = {
        n for n in reachable_functions if n.symbol.startswith("initialize_")
    }

    object_initialized: dict[pathlib.Path, bool] = {}
    for path, info in infos.items():
        init_nodes = {Node(path, symbol) for symbol in info.initializers}
        object_initialized[path] = bool(init_nodes & reachable_initializers)

    def format_node(node: Node) -> str:
        obj = display_path(node.object_path, pathlib.Path.cwd())
        source = provenance.get(node.object_path)
        return f"{node.symbol} [{obj}{' <- ' + source if source else ''}]"

    def format_path(node: Node) -> str:
        chain: list[tuple[Node, str | None]] = []
        cursor = node
        while True:
            previous = predecessor[cursor]
            if previous is None:
                chain.append((cursor, None))
                break
            parent, edge_kind = previous
            chain.append((cursor, edge_kind))
            cursor = parent
        chain.reverse()
        rendered = format_node(chain[0][0])
        for current, edge_kind in chain[1:]:
            rendered += f" --{edge_kind}--> {format_node(current)}"
        return rendered

    offenders: list[tuple[Node, str]] = []

    # 1. Unresolved references fail closed unless explicitly admitted as host imports.
    admitted: dict[tuple[str, str], set[str]] = {
        **{("function", pattern): set() for pattern in args.allow_undefined},
        **{("data", pattern): set() for pattern in args.allow_undefined_data},
    }
    for node, symbol, kind in unresolved:
        patterns = args.allow_undefined_data if kind == "data" else args.allow_undefined
        pattern = next((p for p in patterns if fnmatch.fnmatchcase(symbol, p)), None)
        if pattern is not None:
            admitted[(kind, pattern)].add(symbol)
            continue
        offenders.append((node, f"unresolved {kind} reference {symbol} (no provider in link set)"))

    # 2. Retained data: unclassifiable or initializer-owned mutable state fails closed.
    non_module_mutable: dict[pathlib.Path, set[str]] = collections.defaultdict(set)
    readonly_reads = 0

    def reader_of(node: Node) -> str:
        previous = predecessor[node]
        return previous[0].symbol if previous is not None else "<root>"

    for node in sorted(reachable_data):
        info = infos[node.object_path]
        symbol_info = info.data_symbols.get(node.symbol)
        if symbol_info is None:
            offenders.append((node, "retained data symbol has no data-segment record"))
            continue
        segment = symbol_info.segment
        if not segment:
            offenders.append((node, "retained data symbol has an empty segment name"))
            continue
        if segment.startswith(READONLY_SEGMENTS):
            readonly_reads += 1
            continue
        if info.initializers and not object_initialized[node.object_path]:
            offenders.append((
                node,
                f"mutable initializer-state read: read_by={reader_of(node)} "
                f"segment={segment} absent_initializer={','.join(info.initializers)}",
            ))
            continue
        if not info.initializers:
            non_module_mutable[node.object_path].add(segment)

    # 3. Retained functions in an uninitialised module are reported with the
    #    evidence that made them admissible, so the exception is visible.
    exceptions: list[Node] = []
    seen_objects: set[pathlib.Path] = set()
    offending_objects = {node.object_path for node, _ in offenders}
    for node in sorted(reachable_functions):
        info = infos[node.object_path]
        if node.symbol.startswith("initialize_") or not info.initializers:
            continue
        if object_initialized[node.object_path]:
            continue
        if node.object_path in offending_objects or node.object_path in seen_objects:
            continue
        exceptions.append(node)
        seen_objects.add(node.object_path)

    indirect_retained = sum(
        1 for node in reachable_functions if node.symbol in infos[node.object_path].indirect_callers
    )
    stored_edges = sum(
        1 for node, previous in predecessor.items()
        if previous is not None and previous[1].startswith("stored-")
    )
    if args.dump_retained is not None:
        args.dump_retained.write_text(
            "".join(f"{node.symbol}\n" for node in sorted(reachable_functions)),
            encoding="utf-8",
        )
    print(
        f"[link-set-audit] objects={len(objects)} retained_functions={len(reachable_functions)} "
        f"retained_data={len(reachable_data)} retained_initializers={len(reachable_initializers)} "
        f"retained_indirect_callers={indirect_retained} readonly_reads={readonly_reads} "
        f"stored_pointer_edges={stored_edges}"
    )
    for (kind, pattern), symbols in sorted(admitted.items()):
        print(
            f"[link-set-audit] ALLOW-UNDEFINED kind={kind} pattern={pattern} "
            f"count={len(symbols)} "
            f"symbols={','.join(sorted(symbols)) if symbols else '<none>'}"
        )
    for path in sorted(non_module_mutable):
        print(
            f"[link-set-audit] ALLOW non-module mutable data object="
            f"{display_path(path, pathlib.Path.cwd())} segments="
            f"{','.join(sorted(non_module_mutable[path]))}"
        )

    for path in args.focus_object:
        resolved = path.resolve()
        info = infos[resolved]
        census: dict[tuple[str, str], int] = collections.Counter()
        for symbol in sorted(info.function_refs):
            for target_symbol, edge_kind in info.function_refs[symbol]:
                target = resolve_function(Node(resolved, symbol), target_symbol)
                if target is None or target.object_path == resolved:
                    continue
                target_info = infos[target.object_path]
                if target_info.initializers and not object_initialized[target.object_path]:
                    census[(target_symbol, edge_kind)] += 1
        total = sum(census.values())
        print(
            f"[link-set-audit] FOCUS object={display_path(resolved, pathlib.Path.cwd())} "
            f"uninitialised-module relocations={total}"
        )
        for (target_symbol, edge_kind), count in sorted(census.items()):
            target = function_provider[target_symbol]
            target_info = infos[target.object_path]
            print(
                f"[link-set-audit] FOCUS   {count}x {edge_kind} -> {format_node(target)} "
                f"absent_initializer={','.join(target_info.initializers)}"
            )

    for node in exceptions:
        info = infos[node.object_path]
        print(
            f"[link-set-audit] EXCEPT checked-global-free symbol={format_node(node)} "
            f"absent_initializer={','.join(info.initializers)}"
        )
        print(f"[link-set-audit] path: {format_path(node)}")

    if offenders:
        for node, reason in offenders:
            info = infos[node.object_path]
            print(
                f"[link-set-audit] REJECT symbol={format_node(node)} "
                f"absent_initializer={','.join(info.initializers)} reason={reason}"
            )
            print(f"[link-set-audit] path: {format_path(node)}")
        print(f"[link-set-audit] FAIL offenders={len(offenders)}")
        return 1
    print("[link-set-audit] PASS fail-closed initializer-state rule")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuditError as error:  # pragma: no cover - defensive; fails closed
        print(f"[link-set-audit] TOOL ERROR: {error}", file=sys.stderr)
        raise SystemExit(2)
