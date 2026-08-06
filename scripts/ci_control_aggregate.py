#!/usr/bin/env python3
"""Fail a CI job when any isolated workflow step lacks a passing outcome."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOWLIST = ROOT / ".github" / "ci-control-skip-allowlist.json"
WORKFLOWS = ROOT / ".github" / "workflows"
CONTROL_ID = re.compile(r"control_[A-Za-z0-9_-]+|attest")
JOB_ID = re.compile(r"[A-Za-z0-9_-]+")


class Control(NamedTuple):
    workflow: str
    job: str
    control_id: str

    def label(self) -> str:
        return ":".join(self)


def workflow_controls() -> set[Control]:
    """Read workflow/job/control coordinates without requiring a YAML package."""
    controls: set[Control] = set()
    for workflow in sorted((*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml"))):
        current_job: str | None = None
        for line in workflow.read_text(encoding="utf-8").splitlines():
            job = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
            if job:
                current_job = job.group(1)
                continue
            control = re.fullmatch(
                r"      - id: (control_[A-Za-z0-9_-]+|attest)", line
            )
            if control and current_job is not None:
                controls.add(Control(workflow.name, current_job, control.group(1)))
    return controls


def declared_control_ids(workflow: str, job: str) -> set[str] | None:
    """Control ids declared for one job, derived from workflow YAML.

    Returns None when the workflow tree cannot be inspected.
    """
    try:
        known = workflow_controls()
    except OSError as error:
        print(f"::error::CI workflow controls cannot be inspected: {error}")
        return None
    return {
        control.control_id
        for control in known
        if control.workflow == workflow and control.job == job
    }


def load_allowlist(path: Path) -> dict[Control, str] | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"::error::CI control skip allowlist is missing: {path}")
        return None
    except OSError as error:
        print(f"::error::CI control skip allowlist cannot be read: {path}: {error}")
        return None

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as error:
        print(f"::error::CI control skip allowlist is not valid JSON: {error}")
        return None

    if (
        not isinstance(document, dict)
        or set(document) != {"version", "controls"}
        or type(document.get("version")) is not int
        or document.get("version") != 1
        or not isinstance(document.get("controls"), list)
    ):
        print(
            "::error::CI control skip allowlist must contain exactly version 1 "
            "and a controls array"
        )
        return None

    try:
        known = workflow_controls()
    except OSError as error:
        print(f"::error::CI workflow controls cannot be inspected: {error}")
        return None
    allowed: dict[Control, str] = {}
    for index, entry in enumerate(document["controls"]):
        if not isinstance(entry, dict):
            print(f"::error::CI control skip allowlist entry {index} must be an object")
            return None
        if set(entry) != {"workflow", "job", "id", "reason"}:
            print(
                f"::error::CI control skip allowlist entry {index} must contain exactly "
                "workflow, job, id, and reason"
            )
            return None
        workflow = entry["workflow"]
        job = entry["job"]
        control_id = entry["id"]
        reason = entry["reason"]
        if (
            not isinstance(workflow, str)
            or Path(workflow).name != workflow
            or not workflow.endswith((".yml", ".yaml"))
            or not isinstance(job, str)
            or JOB_ID.fullmatch(job) is None
            or not isinstance(control_id, str)
            or CONTROL_ID.fullmatch(control_id) is None
            or not isinstance(reason, str)
            or not reason.strip()
            or "\n" in reason
            or "\r" in reason
        ):
            print(
                f"::error::CI control skip allowlist entry {index} has invalid fields; "
                "the reason must be one non-empty line"
            )
            return None
        control = Control(workflow, job, control_id)
        if control in allowed:
            print(f"::error::duplicate CI control skip allowlist entry: {control.label()}")
            return None
        if control not in known:
            print(
                "::error::allowlisted control does not exist in any workflow: "
                f"{control.label()}"
            )
            return None
        allowed[control] = reason
    return allowed


def parse_workflow_ref(workflow_ref: str | None) -> tuple[str, str] | str:
    """Strictly parse GITHUB_WORKFLOW_REF.

    Documented shape: owner/repo/.github/workflows/<file>@<ref>

    Returns (workflow_file_name, ref) on success, or a rejection reason string
    that names which part of the identity failed. Missing and malformed are
    distinct; every structural defect is named, not collapsed into a single
    "invalid" bucket.
    """
    if workflow_ref is None or workflow_ref == "":
        return (
            "GITHUB_WORKFLOW_REF is missing; expected "
            "owner/repo/.github/workflows/<file>@<ref>"
        )
    if workflow_ref.strip() == "":
        return "GITHUB_WORKFLOW_REF is empty or whitespace-only"

    # Path and ref are separated by the first @. The path side must not
    # contain @; the ref is everything after that separator and must be
    # non-empty. A lone presence check for "@" is not enough — each
    # subsequent field is validated on its own. Do not strip the whole
    # string first: trailing spaces belong to @ref and must be reported
    # as an @ref defect, not as a blank variable.
    path, separator, ref = workflow_ref.partition("@")
    if separator == "":
        return (
            "GITHUB_WORKFLOW_REF rejected: missing @ref "
            "(required format owner/repo/.github/workflows/<file>@<ref>); "
            f"got {workflow_ref!r}"
        )
    if path == "":
        return (
            "GITHUB_WORKFLOW_REF rejected: empty path before @ref; "
            f"got {workflow_ref!r}"
        )
    if path != path.strip():
        return (
            "GITHUB_WORKFLOW_REF rejected: path has leading or trailing "
            f"whitespace; got path {path!r}"
        )
    if ref == "":
        return (
            "GITHUB_WORKFLOW_REF rejected: empty @ref "
            "(required non-empty ref after @); "
            f"got {workflow_ref!r}"
        )
    if ref.strip() == "":
        return (
            "GITHUB_WORKFLOW_REF rejected: @ref is empty or whitespace-only; "
            f"got {workflow_ref!r}"
        )
    if ref != ref.strip():
        return (
            "GITHUB_WORKFLOW_REF rejected: @ref has leading or trailing "
            f"whitespace; got {workflow_ref!r}"
        )

    marker = "/.github/workflows/"
    if marker not in path:
        return (
            "GITHUB_WORKFLOW_REF rejected: path is not under .github/workflows/; "
            f"got path {path!r}"
        )
    head, file_part = path.split(marker, 1)
    owner_repo = head.split("/")
    if (
        len(owner_repo) != 2
        or not owner_repo[0]
        or not owner_repo[1]
        or any(
            part in (".", "..") or re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None
            for part in owner_repo
        )
    ):
        return (
            "GITHUB_WORKFLOW_REF rejected: expected owner/repo before "
            f".github/workflows/; got {head!r}"
        )
    if (
        not file_part
        or "/" in file_part
        or "\\" in file_part
        or Path(file_part).name != file_part
    ):
        return (
            "GITHUB_WORKFLOW_REF rejected: workflow file must be a single path "
            f"segment under .github/workflows/; got {file_part!r}"
        )
    if not file_part.endswith((".yml", ".yaml")):
        return (
            "GITHUB_WORKFLOW_REF rejected: workflow file must end with .yml or .yaml; "
            f"got {file_part!r}"
        )
    if re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", file_part) is None:
        return (
            "GITHUB_WORKFLOW_REF rejected: workflow file name has invalid characters; "
            f"got {file_part!r}"
        )
    return file_part, ref


def job_ids_in_workflow(workflow_path: Path) -> set[str]:
    """Job ids declared under the workflow's top-level jobs: mapping."""
    jobs: set[str] = set()
    in_jobs = False
    for line in workflow_path.read_text(encoding="utf-8").splitlines():
        if re.fullmatch(r"jobs:\s*(?:#.*)?", line):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if line and not line[0].isspace() and not line.lstrip().startswith("#"):
            # Next top-level key ends the jobs mapping.
            in_jobs = False
            continue
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*(?:#.*)?", line)
        if match:
            jobs.add(match.group(1))
    return jobs


def resolve_identity(
    *,
    workflow_ref: str | None = None,
    job: str | None = None,
) -> tuple[str, str] | str:
    """Resolve (workflow file name, job id) or a named rejection reason.

    Identity is taken from GitHub Actions ambient environment variables:

    - GITHUB_WORKFLOW_REF: owner/repo/.github/workflows/<file>@ref
    - GITHUB_JOB: the job id in that workflow

    Malformed values fail hard with a message that names the rejected field.
    The named workflow file must exist under .github/workflows/, and the job
    id must exist in that file. Callers must fail closed on any rejection.
    """
    if workflow_ref is None:
        workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF")
    if job is None:
        job = os.environ.get("GITHUB_JOB")

    parsed_ref = parse_workflow_ref(workflow_ref)
    if isinstance(parsed_ref, str):
        return parsed_ref
    workflow, _ref = parsed_ref

    if job is None or job == "":
        return "GITHUB_JOB is missing"
    if job.strip() == "" or job != job.strip():
        return f"GITHUB_JOB is empty or whitespace-only; got {job!r}"
    if JOB_ID.fullmatch(job) is None:
        return f"GITHUB_JOB is not a valid job id; got {job!r}"

    workflow_path = WORKFLOWS / workflow
    if not workflow_path.is_file():
        return (
            "GITHUB_WORKFLOW_REF rejected: workflow file "
            f"{workflow!r} is not present under .github/workflows/"
        )

    try:
        known_jobs = job_ids_in_workflow(workflow_path)
    except OSError as error:
        return f"workflow file {workflow!r} cannot be read: {error}"

    if job not in known_jobs:
        return (
            f"GITHUB_JOB rejected: job {job!r} does not exist in "
            f"workflow {workflow!r}"
        )
    return workflow, job


def current_context() -> tuple[str, str] | None:
    """Backward-compatible wrapper around resolve_identity()."""
    resolved = resolve_identity()
    if isinstance(resolved, str):
        return None
    return resolved


def main(allowlist_path: Path = DEFAULT_ALLOWLIST) -> int:
    allowed = load_allowlist(allowlist_path)
    if allowed is None:
        return 1

    # Completeness needs identity first. Missing or malformed identity must
    # fail the job rather than silently disable the census check.
    resolved = resolve_identity()
    if isinstance(resolved, str):
        print(f"::error::{resolved}")
        return 1
    workflow, job = resolved

    declared = declared_control_ids(workflow, job)
    if declared is None:
        return 1
    if not declared:
        print(
            f"::error::no controls declared for {workflow}:{job}; "
            "refusing to pass without a measurement census"
        )
        return 1

    raw = os.environ.get("SEAL_CONTROL_STEPS")
    if raw is None:
        print("::error::SEAL_CONTROL_STEPS is missing; refusing to pass without control results")
        return 1

    try:
        steps = json.loads(raw)
    except json.JSONDecodeError as error:
        print(f"::error::SEAL_CONTROL_STEPS is not valid JSON: {error}")
        return 1

    if not isinstance(steps, dict):
        print("::error::SEAL_CONTROL_STEPS must be a JSON object")
        return 1

    controls = {
        name: value
        for name, value in steps.items()
        if name.startswith("control_") or name == "attest"
    }

    missing = sorted(declared - set(controls))
    if missing:
        for name in missing:
            print(
                f"::error::declared CI control missing from measurement: "
                f"{workflow}:{job}:{name}"
            )
        print(
            f"FAIL: {len(missing)} missing, {len(controls)} reported, "
            f"{len(declared)} declared"
        )
        return 1

    if not controls:
        print("::error::no control results were reported; refusing to pass vacuously")
        return 1

    failed: list[str] = []
    skipped: list[str] = []
    malformed: list[str] = []
    passed: list[str] = []
    for name, result in controls.items():
        if not isinstance(result, dict) or not isinstance(result.get("outcome"), str):
            malformed.append(name)
            continue
        outcome = result["outcome"]
        if outcome == "failure":
            failed.append(name)
        elif outcome == "skipped":
            skipped.append(name)
        elif outcome == "success":
            passed.append(name)
        else:
            malformed.append(f"{name} ({outcome})")

    unallowed_skips: list[str] = []
    for name in skipped:
        control = Control(workflow, job, name)
        reason = allowed.get(control)
        if reason is None:
            print(
                "::error::isolated CI step skipped without allowlist entry: "
                f"{control.label()}"
            )
            unallowed_skips.append(name)
        else:
            print(
                f"::notice::isolated CI step allowed to skip: {control.label()} — "
                f"{reason}"
            )

    for name in failed:
        print(f"::error::isolated CI step failed: {name}")
    for name in malformed:
        print(f"::error::isolated CI step has no passing terminal outcome: {name}")

    # Floor: at least one successful observation is required. An all-skipped
    # payload (even when every skip is allowlisted) measures nothing and must
    # not pass. This is the same defect class as a missing control — green
    # that did not observe the system under test.
    empty_success = not passed and not failed and not malformed and not unallowed_skips
    if empty_success and skipped:
        print(
            "::error::no successful control observations; every reported control "
            "was skipped (allowlisted or otherwise). A measurement with zero "
            "successes is not a pass."
        )

    if failed or malformed or unallowed_skips or empty_success:
        print(
            f"FAIL: {len(failed)} failed, {len(malformed)} invalid, "
            f"{len(unallowed_skips)} unallowed skips, {len(skipped)} skipped, "
            f"{len(passed)} passed, {len(controls)} reported, "
            f"{len(declared)} declared"
        )
        return 1

    print(
        f"PASS: {len(passed)} passed, "
        f"{len(skipped)} skipped, {len(controls)} reported, "
        f"{len(declared)} declared"
    )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    arguments = parser.parse_args()
    sys.exit(main(arguments.allowlist))
