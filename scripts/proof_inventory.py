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
away. See docs/LIMITATIONS.md.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
import argparse
import fnmatch
import json
import re
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
    """Read workflow/job/step coordinates and run blocks without a YAML package.

    No tracked script in this repository imports a YAML library; the same
    line-structural convention is used by scripts/ci_control_aggregate.py.
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


TRIGGER_KEY = re.compile(r"^on:\s*(.*?)\s*$")
TRIGGER_EVENT_KEY = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\s*(.*?)\s*$")
TRIGGER_FILTER_KEY = re.compile(r"^    ([A-Za-z_][A-Za-z0-9_-]*):\s*(.*?)\s*$")
TRIGGER_LIST_ITEM = re.compile(r"^      -\s+(.+?)\s*$")
TRIGGER_ATOM = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
PUSH_FILTERS = {
    "branches",
    "branches-ignore",
    "tags",
    "tags-ignore",
    "paths",
    "paths-ignore",
}


def parse_trigger_atom(value: str, context: str) -> str:
    atom = unquote_scalar(value.strip())
    if not atom or any(character in atom for character in "{}[]"):
        raise InventoryError(f"cannot parse {context}: {value!r}")
    return atom


def parse_trigger_values(value: str, context: str) -> tuple[str, ...]:
    text = value.strip()
    if text.startswith("["):
        if not text.endswith("]"):
            raise InventoryError(f"cannot parse {context}: unterminated flow sequence")
        body = text[1:-1].strip()
        if not body:
            raise InventoryError(f"cannot parse {context}: empty sequence")
        return tuple(parse_trigger_atom(item, context) for item in body.split(","))
    return (parse_trigger_atom(text, context),)


def parse_push_filters(lines: list[str], workflow: str) -> dict[str, tuple[str, ...]]:
    filters: dict[str, tuple[str, ...]] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            index += 1
            continue
        match = TRIGGER_FILTER_KEY.match(line)
        if match is None:
            raise InventoryError(
                f"{workflow}: cannot classify workflow trigger: "
                f"cannot parse push filter line {line.strip()!r}"
            )
        key, value = match.groups()
        if key not in PUSH_FILTERS:
            raise InventoryError(
                f"{workflow}: cannot classify workflow trigger: unsupported push filter {key!r}"
            )
        if key in filters:
            raise InventoryError(
                f"{workflow}: cannot classify workflow trigger: duplicate push filter {key!r}"
            )
        index += 1
        if value:
            filters[key] = parse_trigger_values(value, f"{workflow} push.{key}")
            continue
        items: list[str] = []
        while index < len(lines):
            nested = lines[index]
            if not nested.strip() or nested.lstrip().startswith("#"):
                index += 1
                continue
            item = TRIGGER_LIST_ITEM.match(nested)
            if item is None:
                break
            items.append(parse_trigger_atom(item.group(1), f"{workflow} push.{key}"))
            index += 1
        if not items:
            raise InventoryError(
                f"{workflow}: cannot classify workflow trigger: push filter {key!r} is empty"
            )
        filters[key] = tuple(items)
    if "branches" in filters and "branches-ignore" in filters:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: push has both branches and branches-ignore"
        )
    if "tags" in filters and "tags-ignore" in filters:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: push has both tags and tags-ignore"
        )
    return filters


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
        if not candidate:
            raise InventoryError("empty negative branch pattern")
        unsupported = sorted(set(candidate) & set("?+()|@\\"))
        if unsupported:
            raise InventoryError(
                f"unsupported branch-pattern metacharacters {''.join(unsupported)!r}"
            )
        if fnmatch.fnmatchcase(branch, candidate):
            matched = not negative
    return matched


def workflow_trigger_refutation(path: Path) -> str | None:
    """Return why this workflow cannot fire for the judged event, or ``None``.

    ``None`` is never an independent grant of coverage. It only means this
    text-derived predicate did not refute the manifest assertion. Unsupported
    trigger syntax raises, so silence cannot be interpreted as liveness.
    """
    workflow = path.name
    lines = path.read_text(encoding="utf-8").splitlines()
    starts = [index for index, line in enumerate(lines) if TRIGGER_KEY.match(line)]
    if len(starts) != 1:
        detail = "no top-level on: block" if not starts else "multiple top-level on: blocks"
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: {detail}"
        )
    start = starts[0]
    header = TRIGGER_KEY.match(lines[start])
    assert header is not None
    inline = header.group(1)
    events: dict[str, tuple[str, list[str]]] = {}
    if inline:
        if inline.startswith("{"):
            raise InventoryError(
                f"{workflow}: cannot classify workflow trigger: flow mappings are unsupported"
            )
        for event in parse_trigger_values(inline, f"{workflow} on"):
            if not TRIGGER_ATOM.fullmatch(event):
                raise InventoryError(
                    f"{workflow}: cannot classify workflow trigger: invalid event {event!r}"
                )
            events[event] = ("", [])
    else:
        index = start + 1
        current = ""
        while index < len(lines):
            line = lines[index]
            if line and not line[0].isspace() and not line.lstrip().startswith("#"):
                break
            index += 1
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            event_match = TRIGGER_EVENT_KEY.match(line)
            if event_match:
                current, value = event_match.groups()
                if current in events:
                    raise InventoryError(
                        f"{workflow}: cannot classify workflow trigger: duplicate event {current!r}"
                    )
                events[current] = (value, [])
                continue
            if not current or not line.startswith("    "):
                raise InventoryError(
                    f"{workflow}: cannot classify workflow trigger: "
                    f"cannot parse on: line {line.strip()!r}"
                )
            events[current][1].append(line)
    if not events:
        raise InventoryError(f"{workflow}: cannot classify workflow trigger: on: is empty")
    if JUDGED_EVENT not in events:
        named = ", ".join(sorted(events))
        return (
            f"workflow declares only {named}; does not admit {JUDGED_EVENT} "
            f"to refs/heads/{JUDGED_BRANCH}"
        )
    push_value, push_lines = events[JUDGED_EVENT]
    if push_value not in {"", "{}", "null", "~"}:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: unsupported push value {push_value!r}"
        )
    filters = parse_push_filters(push_lines, workflow)
    if (
        {"tags", "tags-ignore"} & filters.keys()
        and not {"branches", "branches-ignore"} & filters.keys()
    ):
        return (
            f"push trigger is tag-only; does not admit {JUDGED_EVENT} "
            f"to refs/heads/{JUDGED_BRANCH}"
        )
    try:
        if "branches" in filters and not branch_matches(filters["branches"], JUDGED_BRANCH):
            return f"push.branches excludes refs/heads/{JUDGED_BRANCH}"
        if "branches-ignore" in filters and branch_matches(
            filters["branches-ignore"], JUDGED_BRANCH
        ):
            return f"push.branches-ignore excludes refs/heads/{JUDGED_BRANCH}"
    except InventoryError as error:
        raise InventoryError(
            f"{workflow}: cannot classify workflow trigger: {error}"
        ) from error
    return None


def refute_triggers(
    root: Path, invocations: tuple[BuildInvocation, ...]
) -> tuple[tuple[TriggerException, ...], tuple[str, ...], set[tuple[str, ...]]]:
    """Apply trigger text only in the direction that removes manifest credit."""
    reasons: dict[str, str] = {}
    blocked: set[str] = set()
    errors: list[str] = []
    for workflow in sorted({entry.workflow for entry in invocations}):
        try:
            reason = workflow_trigger_refutation(root / ".github" / "workflows" / workflow)
        except (InventoryError, OSError, UnicodeDecodeError) as error:
            errors.append(str(error))
            blocked.add(workflow)
            continue
        if reason is not None:
            reasons[workflow] = reason
    exceptions = tuple(
        TriggerException(entry, reasons[entry.workflow])
        for entry in invocations
        if entry.workflow in reasons
    )
    rejected = {
        entry.coordinate
        for entry in invocations
        if entry.workflow in reasons or entry.workflow in blocked
    }
    return exceptions, tuple(errors), rejected


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
        if fields["kind"] not in {"test", "build", "exe"}:
            raise InventoryError(
                f"{MANIFEST_NAME} invocation {position} has kind {fields['kind']!r}, "
                "expected test, build or exe"
            )
        entry = BuildInvocation(**fields)
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
    errors = list(source_errors)
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
    trigger_exceptions, trigger_errors, trigger_rejected = refute_triggers(root, invocations)
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
    )


def print_report(inventory: Inventory) -> None:
    counts = {
        status: sum(row.status == status for row in inventory.rows)
        for status in ("REACHED", "EXCEPTED", "ORPHANED", "UNCLASSIFIED")
    }
    dead = sum(item.dead for item in inventory.discovered)
    trigger_unclassified = (
        inventory.verified - inventory.credited - len(inventory.trigger_exceptions)
    )
    print(
        f"scanned={inventory.scanned} theorem-bearing={len(inventory.rows)} "
        f"declared-invocations={len(inventory.invocations)} "
        f"verified-invocations={inventory.verified} "
        f"credited-invocations={inventory.credited} "
        f"trigger-excepted={len(inventory.trigger_exceptions)} "
        f"discovered-live={inventory.credited} "
        f"discovered-trigger-excepted={len(inventory.trigger_exceptions)} "
        f"discovered-trigger-unclassified={trigger_unclassified} "
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
