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


def current_context() -> tuple[str, str] | None:
    """Resolve the (workflow file name, job id) this aggregate is measuring.

    Identity is taken from GitHub Actions ambient environment variables that
    are always present on hosted runners for a job step:

    - GITHUB_WORKFLOW_REF: owner/repo/.github/workflows/<file>@ref
    - GITHUB_JOB: the job id in that workflow

    No extra workflow input is required. Returning None means identity cannot
    be resolved; callers must fail closed rather than skip completeness.
    """
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    job = os.environ.get("GITHUB_JOB", "")
    marker = "/.github/workflows/"
    before_ref = workflow_ref.rsplit("@", 1)[0]
    if marker not in before_ref or JOB_ID.fullmatch(job) is None:
        return None
    workflow = before_ref.split(marker, 1)[1]
    if Path(workflow).name != workflow or not workflow.endswith((".yml", ".yaml")):
        return None
    return workflow, job


def main(allowlist_path: Path = DEFAULT_ALLOWLIST) -> int:
    allowed = load_allowlist(allowlist_path)
    if allowed is None:
        return 1

    # Completeness needs identity first. Missing identity must fail the job
    # rather than silently disable the census check.
    context = current_context()
    if context is None:
        print(
            "::error::cannot identify workflow and job for control completeness; "
            "GITHUB_WORKFLOW_REF or GITHUB_JOB is missing or invalid"
        )
        return 1
    workflow, job = context

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
