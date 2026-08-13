#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail closed unless every explicit theorem/lemma module is built by CI.

REACHED means that a local module is in the transitive source-import closure of
a lake invocation DECLARED in ``proof-build-targets.toml``. That manifest is the
sole authority for which commands CI runs. Lake declarations that no manifest
row invokes confer nothing, and neither does any text found in a workflow.

Workflow text is still read, but only in REFUTING positions. For every declared
row the workflow must still contain the corresponding command in shell command
position, at the declared job and step, under the declared guard; if it does
not, the gate fails. Any live command-position lake invocation that no row
accounts for also fails the gate. Neither check can make the gate pass.

That asymmetry is deliberate. Whether a line of shell will actually run is not
a function of its text -- it depends on runner secrets, event payloads, matrix
expansion and files the workflow shells out to -- so a predicate over the text
that GRANTS reachability must guess on an undecidable middle, and guessing
"yes" is invisible when wrong. Predicates here may only ever take reachability
away. Trigger evaluation is a closed world: every event, field, and value shape
must be implemented, or every row in that workflow loses credit and the gate
exits non-zero. See docs/LIMITATIONS.md.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
import argparse
import fnmatch
import json
import re
import subprocess
import sys
import tomllib

try:
    import yaml
except ModuleNotFoundError as error:  # pragma: no cover - provisioning failure
    raise SystemExit(
        "PROOF INVENTORY: PyYAML is required to read workflow triggers as YAML "
        "(apt-get install python3-yaml, or pip install pyyaml). Refusing to "
        "run: a gate that cannot read the trigger must not report coverage."
    ) from error


ROOT = Path(__file__).resolve().parents[1]
THEOREM_DECL = re.compile(
    r"^[^\S\n]*(?:@\[[^\n]*\][^\S\n]*)*(?:[^\s]+[^\S\n]+)*?"
    r"(?:theorem|lemma)[^\S\n]+(«[^»\n]+»|[^\s:([{]+)",
    re.MULTILINE,
)
IMPORT_TOKEN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$"
)
EXCLUDED_PARTS = {".git", ".lake", "node_modules", "target", "wasm-spike"}
EXTERNAL_LAKE_EXES = {"cache"}
MANIFEST_NAME = "proof-build-targets.toml"
JUDGED_EVENT = "push"
JUDGED_BRANCH = "main"

JOBS_KEY = re.compile(r"^jobs:\s*$")
JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
STEP_START = re.compile(r"^      -\s+(\S.*)$")
STEP_KEY = re.compile(r"^        ([A-Za-z0-9_-]+):\s*(.*?)\s*$")
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=", re.S)
FD_REDIRECT = re.compile(r"\d+(?:>>|>&|<&|>|<)")
# Closed, reviewable wrapper vocabulary.  Each entry is an exact repository
# path, so enrolling another wrapper is a one-line diff rather than teaching
# the parser to trust arbitrary arguments containing ``--``.
APPROVED_WRAPPER_SCRIPTS = (
    "scripts/lean_fetch_outcome.py",
    "scripts/release_performance_telemetry.py",
)
PIPEFAIL_SHELL = ("bash", "-o", "pipefail", "-c")

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
    """One lake command, located by workflow/job/step rather than by line.

    Declared rows carry ``line=0`` until the cross-check finds them; discovered
    commands carry the line they were found on. ``guard`` records the condition
    under which the command runs, verbatim, so a conditional invocation is
    visible in the manifest diff instead of being silently counted or dropped.
    """

    workflow: str
    job: str
    step: str
    kind: str
    target: str
    guard: str = ""
    line: int = 0
    dead: bool = False
    dead_reason: str = ""
    push_main: bool = False

    @property
    def coordinate(self) -> tuple[str, str, str, str, str]:
        return (self.workflow, self.job, self.step, self.kind, self.target)

    @property
    def label(self) -> str:
        rendered = f"lake {self.kind}"
        if self.target:
            rendered += f" {self.target}"
        where = f"{self.workflow}:{self.job}:{self.step}"
        if self.line:
            where += f"@{self.line}"
        return f"{where} ({rendered})"


@dataclass(frozen=True)
class WorkflowStep:
    workflow: str
    job: str
    step: str
    if_expr: str
    script: str
    script_line: int

    @property
    def label(self) -> str:
        return f"{self.workflow}:{self.job}:{self.step}"


@dataclass(frozen=True)
class ShellToken:
    kind: str
    text: str
    line: int


@dataclass(frozen=True)
class ShellCommand:
    words: tuple[str, ...]
    line: int
    conditional: bool
    dead: bool
    dead_reason: str


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
class TriggerException:
    invocation: BuildInvocation
    reason: str


@dataclass(frozen=True)
class TriggerUnclassified:
    invocation: BuildInvocation
    reason: str


class TriggerDisposition(Enum):
    FIRES = "FIRES"
    DOES_NOT_FIRE = "DOES NOT FIRE"
    NOT_UNDERSTOOD = "NOT UNDERSTOOD"


@dataclass(frozen=True)
class TriggerEvaluation:
    disposition: TriggerDisposition
    reason: str = ""


@dataclass(frozen=True)
class Inventory:
    rows: tuple[InventoryRow, ...]
    invocations: tuple[BuildInvocation, ...]
    roots: tuple[str, ...]
    scanned: int
    errors: tuple[str, ...]
    discovered: tuple[BuildInvocation, ...] = ()
    notes: tuple[str, ...] = ()
    verified: int = 0
    credited: int = 0
    trigger_exceptions: tuple[TriggerException, ...] = ()
    trigger_unclassified: tuple[TriggerUnclassified, ...] = ()

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


def skip_heredoc_body(script: str, index: int, delimiter: str) -> tuple[int, int]:
    """Consume a heredoc body. Its contents are data, never commands."""
    consumed = 0
    while index < len(script):
        end = script.find("\n", index)
        text = script[index:] if end == -1 else script[index:end]
        index = len(script) if end == -1 else end + 1
        consumed += 1
        if text.strip() == delimiter:
            return index, consumed
    raise InventoryError(f"unterminated heredoc {delimiter!r}")


def consume_substitution(script: str, index: int) -> tuple[int, int]:
    """Consume a ``$(...)``/``<(...)`` region from its ``(``, respecting quotes.

    Parenthesis counting alone is not enough: a substitution routinely contains
    quoted text with unbalanced parentheses in it, as release.yml:73 does.
    """
    depth = 0
    newlines = 0
    length = len(script)
    while index < length:
        char = script[index]
        if char == "\\" and index + 1 < length:
            newlines += script[index + 1] == "\n"
            index += 2
            continue
        if char == "'":
            end = script.find("'", index + 1)
            if end == -1:
                raise InventoryError("unterminated single quote")
            newlines += script.count("\n", index, end)
            index = end + 1
            continue
        if char == '"':
            index += 1
            while index < length and script[index] != '"':
                if script[index] == "\\" and index + 1 < length:
                    newlines += script[index + 1] == "\n"
                    index += 2
                    continue
                if script.startswith("$(", index):
                    index, extra = consume_substitution(script, index + 1)
                    newlines += extra
                    continue
                newlines += script[index] == "\n"
                index += 1
            if index >= length:
                raise InventoryError("unterminated double quote")
            index += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index + 1, newlines
        elif char == "\n":
            newlines += 1
        index += 1
    raise InventoryError("unterminated command substitution")


def scan_shell_word(script: str, index: int) -> tuple[str, int, int]:
    """Return (text, next_index, newlines) for one shell word.

    Quotes, backslash escapes, command substitutions and process substitutions
    are consumed whole. Commands nested inside a substitution are deliberately
    not analysed: missing them under-extracts, which is the safe direction.
    """
    start = index
    out: list[str] = []
    newlines = 0
    length = len(script)
    while index < length:
        char = script[index]
        if char == "\\":
            if index + 1 >= length:
                raise InventoryError("trailing backslash in shell word")
            if script[index + 1] == "\n":
                newlines += 1
                index += 2
                continue
            out.append(script[index + 1])
            index += 2
            continue
        if char == "'":
            end = script.find("'", index + 1)
            if end == -1:
                raise InventoryError("unterminated single quote")
            chunk = script[index + 1 : end]
            newlines += chunk.count("\n")
            out.append(chunk)
            index = end + 1
            continue
        if char == '"':
            index += 1
            while index < length and script[index] != '"':
                if script[index] == "\\" and index + 1 < length:
                    if script[index + 1] == "\n":
                        newlines += 1
                    out.append(script[index + 1])
                    index += 2
                    continue
                if script.startswith("$(", index):
                    end, extra = consume_substitution(script, index + 1)
                    out.append(script[index:end])
                    newlines += extra
                    index = end
                    continue
                if script[index] == "\n":
                    newlines += 1
                out.append(script[index])
                index += 1
            if index >= length:
                raise InventoryError("unterminated double quote")
            index += 1
            continue
        if char == "`":
            end = script.find("`", index + 1)
            if end == -1:
                raise InventoryError("unterminated backquote")
            chunk = script[index : end + 1]
            newlines += chunk.count("\n")
            out.append(chunk)
            index = end + 1
            continue
        if script.startswith(("$(", "<(", ">("), index):
            end, extra = consume_substitution(script, index + 1)
            out.append(script[index:end])
            newlines += extra
            index = end
            continue
        if char in " \t\n;|&<>()":
            break
        out.append(char)
        index += 1
    if index == start:
        raise InventoryError(f"cannot tokenise shell text at {script[start:start + 20]!r}")
    return "".join(out), index, newlines


def tokenize_shell(script: str) -> list[ShellToken]:
    """Tokenise a shell script, keeping operator structure and line numbers.

    ``shlex`` cannot do this job: it discards the operators that decide command
    position, and it raises on ordinary input such as a trailing ``\\`` line
    continuation, which previously destroyed the whole inventory.
    """
    tokens: list[ShellToken] = []
    index = 0
    line = 1
    length = len(script)
    pending_heredocs: list[str] = []
    redirect_pending = False
    while index < length:
        char = script[index]
        if char == "\n":
            tokens.append(ShellToken("newline", "\n", line))
            index += 1
            line += 1
            while pending_heredocs:
                index, consumed = skip_heredoc_body(script, index, pending_heredocs.pop(0))
                line += consumed
            continue
        if char in " \t":
            index += 1
            continue
        if char == "\\" and index + 1 < length and script[index + 1] == "\n":
            index += 2
            line += 1
            continue
        if char == "#":
            end = script.find("\n", index)
            index = length if end == -1 else end
            continue
        if script.startswith(("<<-", "<<"), index):
            index += 3 if script.startswith("<<-", index) else 2
            while index < length and script[index] in " \t":
                index += 1
            delimiter, index, extra = scan_shell_word(script, index)
            line += extra
            pending_heredocs.append(delimiter)
            continue
        if script.startswith(("<(", ">("), index):
            word, index, extra = scan_shell_word(script, index)
            tokens.append(ShellToken("word", word, line))
            line += extra
            continue
        fd_redirect = FD_REDIRECT.match(script, index)
        if fd_redirect:
            tokens.append(ShellToken("op", fd_redirect.group(0), line))
            index = fd_redirect.end()
            redirect_pending = True
            continue
        operator = next(
            (
                candidate
                for candidate in (";;", "&&", "||", ">>", ">&", "<&", ";", "|", "&", "(", ")", "<", ">")
                if script.startswith(candidate, index)
            ),
            None,
        )
        if operator is not None:
            tokens.append(ShellToken("op", operator, line))
            index += len(operator)
            redirect_pending = operator in {">>", ">&", "<&", "<", ">"}
            continue
        word, index, extra = scan_shell_word(script, index)
        tokens.append(ShellToken("redirect-target" if redirect_pending else "word", word, line))
        redirect_pending = False
        line += extra
    return tokens


BLOCK_OPENERS = {"if": "fi", "while": "done", "until": "done", "for": "done", "case": "esac"}
BLOCK_CLOSERS = {"fi": "if", "done": ("while", "until", "for"), "esac": "case"}
STATIC_FALSE = {"false", "/bin/false", "/usr/bin/false"}

DEAD_AFTER_EXIT = "it follows an unconditional exit in the same block"
DEAD_CONSTANT_BRANCH = "it is inside a branch whose condition is the constant false"
DEAD_STEP_IF = "the step's if: expression is the constant false"


def analyze_shell(script: str) -> list[ShellCommand]:
    """Split a script into commands, recording command position and reachability.

    A word is a command only in command position, so ``echo lake build X`` is a
    call to ``echo``. Conditional context is RECORDED rather than decided: a
    command inside ``if``/``while``/``case``/``&&`` is marked conditional, not
    dropped, because whether it runs is a runtime fact. Only statically dead
    positions -- after an unconditional ``exit``, or under a literal ``false``
    condition -- are marked dead, and dead commands can never be declared.
    """
    tokens = tokenize_shell(script)
    commands: list[ShellCommand] = []
    stack: list[dict[str, object]] = [
        {"kind": "top", "conditional": False, "dead": False, "reason": "", "escaped": False}
    ]
    words: list[str] = []
    start_line = 0
    last_command: list[str] = []
    next_conditional = False

    def flush() -> None:
        nonlocal words, start_line, next_conditional, last_command
        if not words:
            return
        top = stack[-1]
        conditional = bool(top["conditional"]) or next_conditional or bool(top["escaped"])
        payload = list(words)
        while payload and ASSIGNMENT.match(payload[0]):
            payload.pop(0)
        words = []
        next_conditional = False
        if not payload:
            return
        last_command = payload
        commands.append(
            ShellCommand(
                tuple(payload),
                start_line,
                conditional,
                bool(top["dead"]),
                str(top["reason"]),
            )
        )
        if payload[0] in {"exit", "return"} and not top["dead"]:
            if conditional:
                # An early exit that may or may not fire makes everything after
                # it in this block conditional too -- golden-path.yml:92-94.
                top["escaped"] = True
            else:
                top["dead"] = True
                top["reason"] = DEAD_AFTER_EXIT

    def pop_block(expected: object) -> None:
        if len(stack) <= 1:
            return
        kinds = expected if isinstance(expected, tuple) else (expected,)
        if stack[-1]["kind"] not in kinds:
            return
        popped = stack.pop()
        if popped["dead"] and not popped["conditional"]:
            stack[-1]["dead"] = True
            stack[-1]["reason"] = popped["reason"]
        if popped["escaped"] or (popped["conditional"] and popped["dead"]):
            # A conditional exit inside the block can skip everything after it.
            stack[-1]["escaped"] = True

    for token in tokens:
        if token.kind == "redirect-target":
            continue
        if token.kind == "newline":
            flush()
            continue
        if token.kind == "op":
            if token.text in {";", ";;", "&", "|"}:
                flush()
            elif token.text in {"&&", "||"}:
                flush()
                next_conditional = True
            elif token.text == "(":
                flush()
                stack.append({**stack[-1], "kind": "subshell"})
            elif token.text == ")":
                flush()
                pop_block("subshell")
            continue
        word = token.text
        if not words:
            if word == "{":
                stack.append({**stack[-1], "kind": "group"})
                continue
            if word == "}":
                pop_block("group")
                continue
            if word in BLOCK_OPENERS:
                stack.append({**stack[-1], "kind": word})
                continue
            if word in {"then", "do"}:
                top = stack[-1]
                if top["kind"] in BLOCK_OPENERS:
                    top["conditional"] = True
                    if last_command and last_command[0] in STATIC_FALSE and len(last_command) == 1:
                        top["dead"] = True
                        top["reason"] = DEAD_CONSTANT_BRANCH
                continue
            if word in {"else", "elif"}:
                top = stack[-1]
                top["conditional"] = True
                top["dead"] = stack[-2]["dead"] if len(stack) > 1 else False
                top["reason"] = stack[-2]["reason"] if len(stack) > 1 else ""
                continue
            if word in BLOCK_CLOSERS:
                pop_block(BLOCK_CLOSERS[word])
                continue
            if word in {"!", "time"}:
                continue
        words.append(word)
        if len(words) == 1:
            start_line = token.line
    flush()
    return commands


def unquote_scalar(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def build_step(workflow: str, job: str, lines: list[tuple[int, str]]) -> WorkflowStep:
    step_id = ""
    if_expr = ""
    script = ""
    script_line = lines[0][0]
    index = 0
    while index < len(lines):
        line_number, text = lines[index]
        index += 1
        match = STEP_KEY.match(text)
        if match is None:
            continue
        key, value = match.group(1), match.group(2)
        if key == "id":
            step_id = unquote_scalar(value)
        elif key == "if":
            if_expr = unquote_scalar(value)
        elif key == "run":
            if not value.startswith(("|", ">")):
                script = unquote_scalar(value)
                script_line = line_number
                continue
            body: list[tuple[int, str]] = []
            while index < len(lines):
                body_number, body_text = lines[index]
                if body_text.strip() and not body_text.startswith("         "):
                    break
                body.append((body_number, body_text))
                index += 1
            widths = [len(text) - len(text.lstrip()) for _, text in body if text.strip()]
            pad = min(widths) if widths else 0
            script = "\n".join(text[pad:] if text.strip() else "" for _, text in body)
            script_line = body[0][0] if body else line_number
    return WorkflowStep(workflow, job, step_id or f"line{lines[0][0]}", if_expr, script, script_line)


def read_workflow_steps(root: Path) -> tuple[WorkflowStep, ...]:
    """Read workflow/job/step coordinates and run blocks for refuting checks.

    The CI aggregate separately parses workflow YAML to census control IDs.
    This reader tokenizes command-position text to refute declared invocations;
    neither reader grants proof-inventory reachability.
    """
    workflow_dir = root / ".github" / "workflows"
    paths = sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
    if not paths:
        raise InventoryError(f"no GitHub Actions workflows found under {workflow_dir}")
    steps: list[WorkflowStep] = []
    for path in paths:
        lines = path.read_text(encoding="utf-8").splitlines()
        name = path.name
        job = ""
        in_jobs = False
        index = 0
        while index < len(lines):
            line = lines[index]
            if JOBS_KEY.match(line):
                in_jobs = True
                index += 1
                continue
            if line and not line[0].isspace() and not JOBS_KEY.match(line):
                in_jobs = False
            job_match = JOB_KEY.match(line)
            if in_jobs and job_match:
                job = job_match.group(1)
                index += 1
                continue
            step_match = STEP_START.match(line)
            if step_match is None or not job:
                index += 1
                continue
            collected = [(index + 1, "        " + step_match.group(1))]
            index += 1
            while index < len(lines):
                text = lines[index]
                if text.strip() and not text.startswith("        "):
                    break
                collected.append((index + 1, text))
                index += 1
            steps.append(build_step(name, job, collected))
    return tuple(steps)


# The `on:` block is read as YAML, because it is YAML. An earlier revision
# pinned indentation as literal string prefixes -- `^  ` for event keys,
# `^    ` for filter keys, `^      -` for list items -- which made the gate
# reject valid workflows over whitespace. A branch list written as a block
# sequence at four spaces instead of six matched no prefix, so the filter
# collected nothing and was reported as *empty*: a reason a maintainer can
# see with their own eyes is false. Quoting the top-level key as `"on":` --
# the standard answer to yamllint's `truthy` warning -- read as no trigger at
# all. Neither is a defect GitHub recognises, and a gate that red-lines
# honest syntax with a false reason gets routed around rather than obeyed.
#
# Reading real YAML widens what parses, so the closed world is re-established
# above the parser rather than inside it: every event name must be in
# GitHub's documented vocabulary, every event's configuration keys must be in
# that event's documented key set, and anything else -- an unknown key, an
# explicit tag, a duplicate key, an unresolvable alias, a construct this gate
# does not implement -- is NOT UNDERSTOOD, which removes credit and fails the
# gate. Silence is never credit.
TRIGGER_ATOM = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")

YAML_STR_TAG = "tag:yaml.org,2002:str"
YAML_NULL_TAG = "tag:yaml.org,2002:null"
YAML_SEQ_TAG = "tag:yaml.org,2002:seq"
YAML_MAP_TAG = "tag:yaml.org,2002:map"

# GitHub's documented `on:` vocabulary and each event's documented
# configuration keys, transcribed from the machine-readable workflow schema
# (json.schemastore.org/github-workflow.json, 113286 bytes, retrieved
# 2026-08-04), whose `on:` mapping is `additionalProperties: false` over
# exactly these thirty-five names. The distinction this table draws is the
# load-bearing one: a key that is *not* an event name -- `defaults`, say --
# makes the workflow file invalid, so it runs on nothing and refusing it is
# correct; an event name this gate does not interpret is merely another way
# for the workflow to start, which cannot take away the push being judged.
EVENT_CONFIG_KEYS: dict[str, frozenset[str]] = {
    "branch_protection_rule": frozenset({"types"}),
    "check_run": frozenset({"types"}),
    "check_suite": frozenset({"types"}),
    "create": frozenset(),
    "delete": frozenset(),
    "deployment": frozenset(),
    "deployment_status": frozenset(),
    "discussion": frozenset({"types"}),
    "discussion_comment": frozenset({"types"}),
    "fork": frozenset(),
    "gollum": frozenset(),
    "issue_comment": frozenset({"types"}),
    "issues": frozenset({"types"}),
    "label": frozenset({"types"}),
    "merge_group": frozenset({"types"}),
    "milestone": frozenset({"types"}),
    "page_build": frozenset(),
    "project": frozenset({"types"}),
    "project_card": frozenset({"types"}),
    "project_column": frozenset({"types"}),
    "public": frozenset(),
    "pull_request": frozenset(
        {"branches", "branches-ignore", "paths", "paths-ignore", "tags",
         "tags-ignore", "types"}
    ),
    "pull_request_review": frozenset({"types"}),
    "pull_request_review_comment": frozenset({"types"}),
    "pull_request_target": frozenset(
        {"branches", "branches-ignore", "paths", "paths-ignore", "tags",
         "tags-ignore", "types"}
    ),
    "push": frozenset(
        {"branches", "branches-ignore", "paths", "paths-ignore", "tags",
         "tags-ignore"}
    ),
    "registry_package": frozenset({"types"}),
    "release": frozenset({"types"}),
    "repository_dispatch": frozenset(),
    "schedule": frozenset(),
    "status": frozenset(),
    "watch": frozenset(),
    "workflow_call": frozenset({"inputs", "outputs", "secrets"}),
    "workflow_dispatch": frozenset({"inputs"}),
    "workflow_run": frozenset({"types", "workflows"}),
}
PUSH_FILTERS = set(EVENT_CONFIG_KEYS["push"])
# Of the configuration keys above, these carry a sequence of pattern strings;
# the remainder (`inputs`, `outputs`, `secrets`) carry a mapping.
EVENT_FILTER_KEYS = frozenset(
    {"branches", "branches-ignore", "paths", "paths-ignore", "tags",
     "tags-ignore", "types", "workflows"}
)

# An alias graph can be made to expand without bound, and a cyclic one would
# not terminate at all. Neither belongs in a workflow trigger.
MAX_TRIGGER_NODES = 10_000


TriggerNode = str | None | list["TriggerNode"] | dict[str, "TriggerNode"]


class _TriggerResolver(yaml.resolver.BaseResolver):
    """Resolve plain scalars as text, with YAML 1.2 core ``null`` the exception.

    PyYAML implements YAML 1.1, in which ``on``, ``yes`` and ``no`` are
    booleans -- ``yaml.safe_load`` on a workflow returns the key ``True``,
    not ``"on"``, so the 1.1 schema would hide the very key this gate looks
    for, and would silently retype a branch honestly named ``on``. GitHub
    reads workflows with a 1.2-style core schema. Keeping plain scalars as
    text is therefore both closer to GitHub and the conservative choice: a
    value that stays a string is checked by the filter validators, whereas a
    value quietly retyped to a bool is checked by nothing.
    """


_TriggerResolver.add_implicit_resolver(
    YAML_NULL_TAG, re.compile(r"^(?:~|null|Null|NULL|)$"), ["~", "n", "N", ""]
)


class _TriggerComposer(yaml.composer.Composer):
    """Record explicit YAML tags rather than letting them resolve away.

    An explicit tag is indistinguishable from an implicit one once composed,
    and this gate refuses explicit tags: whether GitHub honours them is not
    documented anywhere we could find, and accepting a construct on an
    unverified premise is how a gate starts granting credit for a workflow
    that never runs.
    """

    def compose_node(self, parent, index):  # type: ignore[override]
        tag = getattr(self.peek_event(), "tag", None)
        node = super().compose_node(parent, index)
        if tag is not None and getattr(node, "explicit_tag", None) is None:
            node.explicit_tag = tag
        return node


class _TriggerLoader(
    yaml.reader.Reader,
    yaml.scanner.Scanner,
    yaml.parser.Parser,
    _TriggerComposer,
    _TriggerResolver,
):
    """Compose-only loader: a node graph, never constructed Python objects."""

    def __init__(self, stream):
        yaml.reader.Reader.__init__(self, stream)
        yaml.scanner.Scanner.__init__(self)
        yaml.parser.Parser.__init__(self)
        _TriggerComposer.__init__(self)
        _TriggerResolver.__init__(self)


class _TriggerBuilder:
    """Turn a composed node graph into the trigger shapes this gate reads.

    PyYAML's own constructor is deliberately not used. It resolves duplicate
    mapping keys by keeping the last -- so ``push:`` written twice would be
    silently reduced to whichever copy came second, which is a laundering
    route -- and it honours merge keys and tags whose GitHub behaviour is
    unverified. Every one of those is refused here instead.
    """

    def __init__(self, context: str):
        self.context = context
        self.budget = MAX_TRIGGER_NODES
        self.active: set[int] = set()

    def fail(self, node, detail: str) -> InventoryError:
        mark = node.start_mark
        return InventoryError(
            f"cannot parse {self.context} at line {mark.line + 1} "
            f"column {mark.column + 1}: {detail}"
        )

    def build(self, node) -> TriggerNode:
        self.budget -= 1
        if self.budget < 0:
            raise InventoryError(
                f"cannot parse {self.context}: trigger expands past "
                f"{MAX_TRIGGER_NODES} nodes"
            )
        explicit = getattr(node, "explicit_tag", None)
        if explicit is not None:
            raise self.fail(node, f"explicit YAML tag {explicit!r} is unsupported")
        if isinstance(node, yaml.nodes.ScalarNode):
            if node.tag == YAML_NULL_TAG:
                return None
            if node.tag != YAML_STR_TAG:
                raise self.fail(node, f"unsupported scalar type {node.tag!r}")
            return node.value
        if id(node) in self.active:
            raise self.fail(node, "alias refers to itself")
        self.active.add(id(node))
        try:
            if isinstance(node, yaml.nodes.SequenceNode):
                if node.tag != YAML_SEQ_TAG:
                    raise self.fail(node, f"unsupported sequence type {node.tag!r}")
                return [self.build(item) for item in node.value]
            if isinstance(node, yaml.nodes.MappingNode):
                if node.tag != YAML_MAP_TAG:
                    raise self.fail(node, f"unsupported mapping type {node.tag!r}")
                mapping: dict[str, TriggerNode] = {}
                for key_node, value_node in node.value:
                    key = self.build(key_node)
                    if not isinstance(key, str):
                        raise self.fail(key_node, "mapping keys must be strings")
                    if key in mapping:
                        raise self.fail(key_node, f"duplicate key {key!r}")
                    mapping[key] = self.build(value_node)
                return mapping
            raise self.fail(node, "unsupported YAML construct")
        finally:
            self.active.discard(id(node))


def _yaml_detail(error: yaml.YAMLError) -> str:
    problem = getattr(error, "problem", None) or "invalid YAML"
    mark = getattr(error, "problem_mark", None)
    if mark is None:
        return problem
    return f"{problem} at line {mark.line + 1} column {mark.column + 1}"


def read_trigger_node(path: Path, workflow: str) -> TriggerNode:
    """Return the value of the workflow's single top-level ``on:`` key.

    The key is matched as a composed YAML key, so a quoted ``"on":`` is the
    same key as a bare ``on:``. Only the ``on:`` subtree is built; the rest
    of the file is left as nodes, so a construct this gate refuses inside
    ``jobs:`` is not this gate's business.
    """
    try:
        text = path.read_text(encoding="utf-8")
        document = yaml.compose(text, Loader=_TriggerLoader)
    except yaml.YAMLError as error:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: "
            f"cannot read {workflow} as YAML: {_yaml_detail(error)}"
        ) from error
    except RecursionError as error:
        # PyYAML parses by recursive descent, so nesting deep enough to
        # exhaust the interpreter stack raises here rather than returning a
        # document. Left uncaught it would abort the whole run part-way
        # through, which reports nothing at all; one unreadable workflow must
        # cost that workflow its credit, not the report.
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: "
            f"{workflow} nests deeper than this gate reads"
        ) from error
    if document is None:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: no top-level on: block"
        )
    if not isinstance(document, yaml.nodes.MappingNode) or document.tag != YAML_MAP_TAG:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: "
            f"{workflow} is not a YAML mapping"
        )
    found = [
        value_node
        for key_node, value_node in document.value
        if isinstance(key_node, yaml.nodes.ScalarNode)
        and key_node.tag == YAML_STR_TAG
        and getattr(key_node, "explicit_tag", None) is None
        and key_node.value == "on"
    ]
    if len(found) != 1:
        detail = "no top-level on: block" if not found else "multiple top-level on: blocks"
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: {detail}"
        )
    return _TriggerBuilder(f"{workflow} on").build(found[0])


def require_trigger_atom(value: TriggerNode, context: str) -> str:
    if not isinstance(value, str) or not value or not TRIGGER_ATOM.fullmatch(value):
        raise InventoryError(f"cannot parse {context}: expected an event name, got {value!r}")
    return value


def require_string_sequence(value: TriggerNode, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise InventoryError(f"cannot parse {context}: expected a non-empty sequence")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise InventoryError(f"cannot parse {context}: expected non-empty string values")
        result.append(item)
    return tuple(result)


def push_filters_from_node(
    node: TriggerNode, workflow: str
) -> dict[str, tuple[str, ...]]:
    if node is None or node == {}:
        return {}
    if not isinstance(node, dict):
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: unsupported push value {node!r}"
        )
    unknown = sorted(set(node) - PUSH_FILTERS)
    if unknown:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: "
            f"unsupported push filter {unknown[0]!r}"
        )
    filters = {
        key: require_string_sequence(value, f"{workflow} push.{key}")
        for key, value in node.items()
    }
    if "branches" in filters and "branches-ignore" in filters:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: push has both branches and branches-ignore"
        )
    if "tags" in filters and "tags-ignore" in filters:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: push has both tags and tags-ignore"
        )
    return filters


def validate_ref_patterns(
    patterns: tuple[str, ...], context: str, allow_negative: bool
) -> None:
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-*"
    )
    for pattern in patterns:
        candidate = pattern
        if pattern.startswith("!"):
            if not allow_negative:
                raise InventoryError(f"negative patterns are unsupported in {context}")
            candidate = pattern[1:]
        if not candidate:
            raise InventoryError(f"empty pattern in {context}")
        invalid = sorted(set(candidate) - allowed)
        if invalid:
            raise InventoryError(
                f"unsupported {context} pattern characters {''.join(invalid)!r}"
            )


def branch_matches(patterns: tuple[str, ...], branch: str) -> bool:
    """Apply the supported subset of ordered GitHub branch filters.

    ``*`` has the same meaning for the judged branch ``main`` under both
    Python and GitHub matching. Extended GitHub metacharacters are rejected;
    approximating them could turn an exclusion into accidental credit.
    """
    matched = False
    for pattern in patterns:
        negative = pattern.startswith("!")
        candidate = pattern[1:] if negative else pattern
        if fnmatch.fnmatchcase(branch, candidate):
            matched = not negative
    return matched


def validate_schedule(node: TriggerNode, workflow: str) -> None:
    if not isinstance(node, list) or not node:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: "
            "schedule must be a non-empty sequence of cron mappings"
        )
    for item in node:
        if not isinstance(item, dict) or set(item) != {"cron"}:
            raise InventoryError(
                f"{workflow}: cannot classify workflow trigger: "
                "schedule entries must contain only cron"
            )
        cron = item["cron"]
        if not isinstance(cron, str) or not cron:
            raise InventoryError(
                f"{workflow}: cannot classify workflow trigger: schedule cron must be a string"
            )
        fields = cron.split()
        ranges = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6))
        if len(fields) != len(ranges) or any(
            field != "*"
            and (not field.isdigit() or not low <= int(field) <= high)
            for field, (low, high) in zip(fields, ranges)
        ):
            raise InventoryError(
                f"{workflow}: cannot classify workflow trigger: "
                f"schedule cron {cron!r} is outside the implemented simple five-field subset"
            )


def validate_non_push_event(event: str, node: TriggerNode, workflow: str) -> None:
    """Refuse configuration that cannot be read; tolerate what cannot matter.

    ``on:`` is a disjunction. A second event is another way for the workflow
    to start and can never withdraw the push-to-main being judged, so an
    event this gate does not interpret needs no interpretation to leave the
    push verdict sound. What is *not* tolerated is a key GitHub does not
    recognise: the ``on:`` mapping is closed, so an unrecognised key makes
    the workflow file invalid, and an invalid workflow runs on nothing at
    all -- which is exactly the state a declared-but-dead build wants to be
    mistaken for.
    """
    if node is None:
        return
    if event == "schedule":
        validate_schedule(node, workflow)
        return
    if not isinstance(node, dict):
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: "
            f"unsupported configuration for event {event!r}"
        )
    unknown = sorted(set(node) - EVENT_CONFIG_KEYS[event])
    if unknown:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: "
            f"unsupported configuration key {unknown[0]!r} for event {event!r}"
        )
    # Tolerating an event is not tolerating any shape written under it. A
    # value GitHub's schema rejects invalidates the whole workflow file just
    # as an unknown key does, and an invalid workflow runs on nothing -- so
    # the shapes are checked even though the values are never interpreted.
    for key, value in node.items():
        if key in EVENT_FILTER_KEYS:
            require_string_sequence(value, f"{workflow} {event}.{key}")
        elif not isinstance(value, dict):
            raise InventoryError(
                f"{workflow}: cannot classify workflow trigger: "
                f"{event}.{key} must be a mapping"
            )


def parse_workflow_trigger(path: Path) -> dict[str, TriggerNode]:
    workflow = path.name
    node = read_trigger_node(path, workflow)
    events: dict[str, TriggerNode] = {}
    if isinstance(node, str):
        events[require_trigger_atom(node, f"{workflow} on")] = None
    elif isinstance(node, list):
        if not node:
            raise InventoryError(
                f"{workflow}: cannot classify workflow trigger: on: sequence is empty"
            )
        for item in node:
            event = require_trigger_atom(item, f"{workflow} on")
            if event in events:
                raise InventoryError(
                    f"{workflow}: cannot classify workflow trigger: duplicate event {event!r}"
                )
            events[event] = None
    elif isinstance(node, dict):
        for event, value in node.items():
            require_trigger_atom(event, f"{workflow} on")
            events[event] = value
    elif node is not None:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: on: has unsupported value {node!r}"
        )
    if not events:
        raise InventoryError(f"{workflow}: cannot classify workflow trigger: on: is empty")
    unknown = sorted(set(events) - set(EVENT_CONFIG_KEYS))
    if unknown:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: unsupported event {unknown[0]!r}"
        )
    for event, value in events.items():
        if event != JUDGED_EVENT:
            validate_non_push_event(event, value, workflow)
    return events


def workflow_trigger_evaluation(path: Path) -> TriggerEvaluation:
    """Classify the complete ``on:`` specification against push-to-main.

    FIRES means every present construct was implemented and the combined
    trigger admits an unconditional push to ``refs/heads/main``. A path filter
    is therefore DOES NOT FIRE: without a changed-file set it is conditional,
    not an unconditional coverage witness. Any other syntax or construct is
    NOT UNDERSTOOD, which removes all rows in the workflow and fails the gate.
    """
    workflow = path.name
    try:
        events = parse_workflow_trigger(path)
    except (InventoryError, OSError, UnicodeDecodeError, RecursionError) as error:
        return TriggerEvaluation(TriggerDisposition.NOT_UNDERSTOOD, str(error))
    if JUDGED_EVENT not in events:
        named = ", ".join(sorted(events))
        return TriggerEvaluation(
            TriggerDisposition.DOES_NOT_FIRE,
            f"workflow declares only {named}; does not admit {JUDGED_EVENT} "
            f"to refs/heads/{JUDGED_BRANCH}",
        )
    try:
        filters = push_filters_from_node(events[JUDGED_EVENT], workflow)
        for key in ("branches", "branches-ignore", "tags", "tags-ignore"):
            if key in filters:
                validate_ref_patterns(
                    filters[key],
                    f"push.{key}",
                    allow_negative=key in {"branches", "tags"},
                )
        if "tags" in filters and not {"branches", "branches-ignore"} & filters.keys():
            return TriggerEvaluation(
                TriggerDisposition.DOES_NOT_FIRE,
                f"push trigger is tag-only; does not admit {JUDGED_EVENT} "
                f"to refs/heads/{JUDGED_BRANCH}",
            )
        if "branches" in filters and not branch_matches(filters["branches"], JUDGED_BRANCH):
            return TriggerEvaluation(
                TriggerDisposition.DOES_NOT_FIRE,
                f"push.branches excludes refs/heads/{JUDGED_BRANCH}",
            )
        if "branches-ignore" in filters and branch_matches(
            filters["branches-ignore"], JUDGED_BRANCH
        ):
            return TriggerEvaluation(
                TriggerDisposition.DOES_NOT_FIRE,
                f"push.branches-ignore excludes refs/heads/{JUDGED_BRANCH}",
            )
        path_filters = sorted({"paths", "paths-ignore"} & filters.keys())
        if path_filters:
            return TriggerEvaluation(
                TriggerDisposition.DOES_NOT_FIRE,
                f"push.{path_filters[0]} makes the main-branch push file-dependent; "
                "it is not an unconditional trigger",
            )
    except InventoryError as error:
        reason = str(error)
        if "cannot classify workflow trigger" not in reason:
            reason = f"{workflow}: cannot classify workflow trigger: {reason}"
        return TriggerEvaluation(TriggerDisposition.NOT_UNDERSTOOD, reason)
    return TriggerEvaluation(TriggerDisposition.FIRES)


def refute_triggers(
    root: Path, invocations: tuple[BuildInvocation, ...]
) -> tuple[
    tuple[TriggerException, ...],
    tuple[TriggerUnclassified, ...],
    tuple[str, ...],
    set[tuple[str, ...]],
]:
    """Apply trigger text only in the direction that removes manifest credit."""
    evaluations: dict[str, TriggerEvaluation] = {}
    errors: list[str] = []
    for workflow in sorted({entry.workflow for entry in invocations}):
        evaluation = workflow_trigger_evaluation(
            root / ".github" / "workflows" / workflow
        )
        evaluations[workflow] = evaluation
        if evaluation.disposition is TriggerDisposition.NOT_UNDERSTOOD:
            errors.append(f"NOT UNDERSTOOD: {evaluation.reason}")
    exceptions: list[TriggerException] = []
    unclassified: list[TriggerUnclassified] = []
    rejected: set[tuple[str, ...]] = set()
    for entry in invocations:
        evaluation = evaluations[entry.workflow]
        if evaluation.disposition is TriggerDisposition.NOT_UNDERSTOOD:
            reason = f"NOT UNDERSTOOD: {evaluation.reason}"
            unclassified.append(TriggerUnclassified(entry, reason))
            rejected.add(entry.coordinate)
            continue
        if evaluation.disposition is TriggerDisposition.DOES_NOT_FIRE:
            exceptions.append(TriggerException(entry, evaluation.reason))
            rejected.add(entry.coordinate)
            continue
        if not entry.push_main:
            exceptions.append(
                TriggerException(
                    entry,
                    "manifest does not assert unconditional push-to-main credit; "
                    "workflow text cannot upgrade it",
                )
            )
            rejected.add(entry.coordinate)
    return tuple(exceptions), tuple(unclassified), tuple(errors), rejected


def is_statically_false(expression: str) -> bool:
    text = expression.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    return text.strip() == "false"


def lake_invocations_in(command: ShellCommand, step: WorkflowStep, step_dead: bool) -> list[BuildInvocation]:
    if len(command.words) < 2 or command.words[0] != "lake":
        return []
    kind = command.words[1]
    if kind not in {"test", "build", "exe"}:
        return []
    arguments = [word for word in command.words[2:] if not word.startswith("-")]
    guard_parts: list[str] = []
    if step.if_expr:
        guard_parts.append(f"step-if: {step.if_expr}")
    if command.conditional:
        guard_parts.append("shell-conditional")
    dead = command.dead or step_dead
    reason = DEAD_STEP_IF if step_dead else command.dead_reason
    line = step.script_line + command.line - 1

    def make(target: str) -> BuildInvocation:
        return BuildInvocation(
            step.workflow,
            step.job,
            step.step,
            kind,
            target,
            "; ".join(guard_parts),
            line,
            dead,
            reason,
        )

    if kind == "test":
        return [make("")]
    if kind == "exe":
        return [make(arguments[0])] if arguments else [make("")]
    return [make(target) for target in arguments] if arguments else [make("")]


def wrapper_refusal_reason(command: ShellCommand) -> str | None:
    """Return the first closed-vocabulary reason a wrapper is not admitted."""
    words = command.words
    if len(words) < 4:
        return "wrapper has fewer than four words"
    if words[0] != "python3":
        return "wrapper executable is not python3"
    if words[1] not in APPROVED_WRAPPER_SCRIPTS:
        return "wrapper script is not enrolled"
    separators = [index for index, word in enumerate(words[2:], start=2) if word == "--"]
    if len(separators) != 1:
        return "wrapper does not have exactly one literal -- separator"
    return None


def wrapped_lake_commands(command: ShellCommand) -> tuple[ShellCommand, ...]:
    """Expose Lake commands behind an enrolled wrapper and literal separator.

    ``--`` is load-bearing: options belong before it and exactly one inner
    command follows it.  We never search arbitrary arguments for ``lake``;
    an unenrolled wrapper or malformed inner command stays invisible to the
    refuting census and therefore cannot accidentally gain credit.
    """
    words = command.words
    if wrapper_refusal_reason(command) is not None:
        return ()
    separators = [index for index, word in enumerate(words[2:], start=2) if word == "--"]
    inner = words[separators[0] + 1 :]
    if inner and inner[0] == "lake":
        return (
            ShellCommand(tuple(inner), command.line, command.conditional, command.dead, command.dead_reason),
        )
    if inner[: len(PIPEFAIL_SHELL)] == PIPEFAIL_SHELL and len(inner) == len(PIPEFAIL_SHELL) + 1:
        nested = analyze_shell(inner[-1])
        return tuple(
            ShellCommand(item.words, command.line, command.conditional or item.conditional,
                          command.dead or item.dead, item.dead_reason or command.dead_reason)
            for item in nested
        )
    return ()


def validate_wrapper_registry(root: Path) -> tuple[str, ...]:
    """Reject unusable registry state before it can silently credit nothing."""
    errors: list[str] = []
    try:
        Path(__file__).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        errors.append(f"cannot read proof_inventory.py: {error}")
    if not APPROVED_WRAPPER_SCRIPTS:
        errors.append("approved wrapper registry is empty")
    repository = root.resolve()
    for script in APPROVED_WRAPPER_SCRIPTS:
        path = root / script
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            errors.append(f"approved wrapper registry entry does not name a file: {script}")
            continue
        if path.is_symlink():
            errors.append(f"approved wrapper registry entry is a symlink, not a regular file: {script}")
        elif not resolved.is_relative_to(repository):
            errors.append(f"approved wrapper registry entry escapes repository root: {script}")
        elif not path.is_file():
            errors.append(f"approved wrapper registry entry does not name a regular file: {script}")
    return tuple(errors)


def discover_lake_commands(
    steps: tuple[WorkflowStep, ...]
) -> tuple[tuple[BuildInvocation, ...], list[str]]:
    """Find every command-position lake invocation. Used ONLY to refute."""
    found: list[BuildInvocation] = []
    errors: list[str] = []
    for step in steps:
        if not step.script:
            continue
        try:
            commands = analyze_shell(step.script)
        except InventoryError as error:
            errors.append(f"{step.label}: cannot parse the run block: {error}")
            continue
        step_dead = is_statically_false(step.if_expr)
        for command in commands:
            found.extend(lake_invocations_in(command, step, step_dead))
            for wrapped in wrapped_lake_commands(command):
                found.extend(lake_invocations_in(wrapped, step, step_dead))
    return tuple(found), errors


def read_manifest(root: Path) -> tuple[BuildInvocation, ...]:
    path = root / MANIFEST_NAME
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InventoryError(f"cannot read {MANIFEST_NAME}: {error}") from error
    rows = data.get("invocation")
    if not isinstance(rows, list) or not rows:
        raise InventoryError(f"{MANIFEST_NAME} declares no [[invocation]] entries")
    declared: list[BuildInvocation] = []
    seen: set[tuple[str, ...]] = set()
    for position, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise InventoryError(f"{MANIFEST_NAME} invocation {position} is not a table")
        fields: dict[str, str] = {}
        for key in ("workflow", "job", "step", "kind", "target", "guard"):
            value = row.get(key)
            if not isinstance(value, str):
                raise InventoryError(
                    f"{MANIFEST_NAME} invocation {position} has no string {key}"
                )
            fields[key] = value
        push_main = row.get("push_main")
        if not isinstance(push_main, bool):
            raise InventoryError(
                f"{MANIFEST_NAME} invocation {position} has no boolean push_main"
            )
        if fields["kind"] not in {"test", "build", "exe"}:
            raise InventoryError(
                f"{MANIFEST_NAME} invocation {position} has kind {fields['kind']!r}, "
                "expected test, build or exe"
            )
        entry = BuildInvocation(**fields, push_main=push_main)
        if entry.coordinate in seen:
            raise InventoryError(f"{MANIFEST_NAME} declares {entry.label} twice")
        seen.add(entry.coordinate)
        declared.append(entry)
    return tuple(declared)


def cross_check(
    declared: tuple[BuildInvocation, ...],
    discovered: tuple[BuildInvocation, ...],
    steps: tuple[WorkflowStep, ...],
) -> tuple[list[str], list[str], set[tuple[str, ...]]]:
    """Refute declarations against the tree. Never grants anything.

    Returns the coordinates that survived. A row that fails here confers no
    reachability at all: it is not enough for the process to exit non-zero
    while the row still prints REACHED, because a reader believes the row.
    """
    errors: list[str] = []
    notes: list[str] = []
    verified: set[tuple[str, ...]] = set()
    known = {(step.workflow, step.job, step.step) for step in steps}
    live: dict[tuple[str, ...], list[BuildInvocation]] = {}
    dead: dict[tuple[str, ...], list[BuildInvocation]] = {}
    for item in discovered:
        if item.dead:
            dead.setdefault(item.coordinate, []).append(item)
            notes.append(
                f"{item.label}: present but statically cannot run "
                f"({item.dead_reason}); it confers no reachability"
            )
            continue
        live.setdefault(item.coordinate, []).append(item)
    for entry in declared:
        if (entry.workflow, entry.job, entry.step) not in known:
            errors.append(f"{entry.label}: declared workflow/job/step does not exist")
            continue
        matches = live.get(entry.coordinate)
        if not matches:
            buried = dead.get(entry.coordinate)
            if buried:
                errors.append(
                    f"{entry.label}: declared, but the command at that step "
                    f"statically cannot run ({buried[0].dead_reason}); "
                    "a dead command may not be declared"
                )
            else:
                errors.append(
                    f"{entry.label}: declared command is not in shell command "
                    "position at that step"
                )
            continue
        guards = sorted({match.guard for match in matches})
        if entry.guard not in guards:
            errors.append(
                f"{entry.label}: declared guard {entry.guard!r} but the tree has {guards}"
            )
            continue
        verified.add(entry.coordinate)
    declared_coordinates = {entry.coordinate for entry in declared}
    for coordinate, matches in sorted(live.items()):
        if coordinate not in declared_coordinates:
            errors.append(
                f"{matches[0].label}: undeclared lake invocation; "
                f"add it to {MANIFEST_NAME} or remove it"
            )
    return errors, notes, verified


def locate_declared(
    declared: tuple[BuildInvocation, ...], discovered: tuple[BuildInvocation, ...]
) -> tuple[BuildInvocation, ...]:
    """Stamp declared rows with the line the cross-check found them on."""
    lines = {item.coordinate: item.line for item in discovered if not item.dead}
    return tuple(
        BuildInvocation(
            entry.workflow,
            entry.job,
            entry.step,
            entry.kind,
            entry.target,
            entry.guard,
            lines.get(entry.coordinate, 0),
            push_main=entry.push_main,
        )
        for entry in declared
    )


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
    errors = list(source_errors) + list(validate_wrapper_registry(root))
    try:
        steps = read_workflow_steps(root)
        declared = read_manifest(root)
        package = read_lakefile(root)
    except (InventoryError, OSError, UnicodeDecodeError) as error:
        return Inventory((), (), (), len(sources) + len(unreadable), (str(error),))

    discovered, discovery_errors = discover_lake_commands(steps)
    errors.extend(discovery_errors)
    check_errors, notes, verified = cross_check(declared, discovered, steps)
    errors.extend(check_errors)
    invocations = locate_declared(declared, discovered)
    (
        trigger_exceptions,
        trigger_unclassified,
        trigger_errors,
        trigger_rejected,
    ) = refute_triggers(root, invocations)
    errors.extend(trigger_errors)
    # Only rows confirmed by both refuting checks may confer reachability.
    confirmed = tuple(
        entry
        for entry in invocations
        if entry.coordinate in verified and entry.coordinate not in trigger_rejected
    )

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
        package, confirmed, set(sources), upstream
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
        discovered,
        tuple(sorted(set(notes))),
        len(verified),
        len(confirmed),
        trigger_exceptions,
        trigger_unclassified,
    )


def print_report(inventory: Inventory) -> None:
    counts = {
        status: sum(row.status == status for row in inventory.rows)
        for status in ("REACHED", "EXCEPTED", "ORPHANED", "UNCLASSIFIED")
    }
    dead = sum(item.dead for item in inventory.discovered)
    print(
        f"scanned={inventory.scanned} theorem-bearing={len(inventory.rows)} "
        f"declared-invocations={len(inventory.invocations)} "
        f"verified-invocations={inventory.verified} "
        f"credited-invocations={inventory.credited} "
        f"trigger-excepted={len(inventory.trigger_exceptions)} "
        f"discovered-live={inventory.credited} "
        f"discovered-trigger-excepted={len(inventory.trigger_exceptions)} "
        f"discovered-trigger-unclassified={len(inventory.trigger_unclassified)} "
        f"discovered-dead={dead} "
        f"build-roots={len(inventory.roots)}"
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
    print("trigger-status\tdeclaration\treason")
    for item in inventory.trigger_exceptions:
        print(f"TRIGGER-EXCEPTED\t{item.invocation.label}\t{item.reason}")
    for item in inventory.trigger_unclassified:
        print(f"TRIGGER-NOT-UNDERSTOOD\t{item.invocation.label}\t{item.reason}")


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
                    "declared": [asdict(item) for item in inventory.invocations],
                    "verified": inventory.verified,
                    "credited": inventory.credited,
                    "trigger_exceptions": [asdict(item) for item in inventory.trigger_exceptions],
                    "trigger_unclassified": [
                        asdict(item) for item in inventory.trigger_unclassified
                    ],
                    "discovered": [asdict(item) for item in inventory.discovered],
                    "rows": [asdict(row) for row in inventory.rows],
                    "errors": inventory.errors,
                    "notes": inventory.notes,
                },
                indent=2,
            )
        )
    else:
        print_report(inventory)
    sys.stdout.flush()
    for note in inventory.notes:
        print(f"PROOF INVENTORY NOTE: {note}", file=sys.stderr)
    for error in inventory.errors:
        print(f"PROOF INVENTORY UNCLASSIFIED: {error}", file=sys.stderr)
    for row in inventory.rows:
        if row.status == "ORPHANED":
            print(f"ORPHAN PROOF MODULE: {row.module}: {row.reason}", file=sys.stderr)
    return 0 if inventory.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
