#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail closed when a job that needs PyYAML does not provision it.

Two scripts in this tree -- scripts/ci_control_aggregate.py and
scripts/proof_inventory.py -- parse workflow YAML and refuse to run without
PyYAML rather than degrade to text scanning. Nineteen of their twenty call
sites used to be green only because the ubuntu-latest image ships
python3-yaml for /usr/bin/python3. contract-freeze added
actions/setup-python, which puts a hostedtoolcache interpreter with no PyYAML
ahead of the system one on PATH, and main went red.

This gate removes the possibility of that recurring. It does not read a
hand-maintained list of jobs: it derives the set of PyYAML-needing Python
files from the source tree by import closure, finds every workflow step that
invokes one of them, and requires the enclosing job to reference the shared
composite action .github/actions/pyyaml -- before the first such step, and
after any actions/setup-python step that would shadow the interpreter it
provisioned.

A new job that inspects workflow YAML therefore cannot silently lack the
dependency: the gate discovers it from the tree, not from a roster someone
has to remember to update. The residual hole is the exemption table below,
which is deliberately loud -- a stale exemption is a hard failure.
"""

from __future__ import annotations

import argparse
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
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION_REF = "./.github/actions/pyyaml"
SOURCE_DIRS = ("scripts", "test")
SETUP_PYTHON = "actions/setup-python"
YAML_IMPORT = re.compile(r"^\s*(?:import\s+yaml\b|from\s+yaml\b)", re.MULTILINE)

# workflow:job -> why it is allowed to omit the shared action.
#
# Every entry is a hole in the guarantee above and is stated as one. An entry
# whose job no longer exists, or whose job no longer needs PyYAML, is a hard
# failure -- the exemption cannot outlive its reason in silence.
EXEMPTIONS: dict[tuple[str, str], str] = {
    ("ci.yml", "rust-conformance-lean"): (
        "The lane on branch fix/dedupe-lean-execution deletes this job "
        "outright; adding a step to it would resurrect the job in a merge. "
        "Remove this exemption together with the job, or add the action if "
        "that lane is abandoned."
    ),
}


class WorkflowError(Exception):
    """A workflow file could be read but was not usable."""


def yaml_dependent_sources(root: Path) -> set[str]:
    """Basenames of Python files that need PyYAML, by import closure.

    Seeded with files that import ``yaml`` directly, then grown: a file that
    names a PyYAML-needing module -- by import, by path, or by the string a
    subprocess or importlib spec is built from -- inherits the requirement.
    The closure over-approximates rather than under-approximates, because a
    missed dependency is a red main and a spurious one is a no-op probe.
    """
    texts: dict[str, str] = {}
    for directory in SOURCE_DIRS:
        for path in sorted((root / directory).rglob("*.py")):
            try:
                texts[path.name] = path.read_text(encoding="utf-8")
            except OSError as error:
                raise WorkflowError(f"cannot read {path}: {error}") from error

    needed = {name for name, text in texts.items() if YAML_IMPORT.search(text)}
    if not needed:
        raise WorkflowError(
            "no Python file in this tree imports yaml; the gate would pass "
            "vacuously, which cannot be right while the aggregator exists"
        )

    changed = True
    while changed:
        changed = False
        stems = {name.removesuffix(".py") for name in needed}
        for name, text in texts.items():
            if name in needed:
                continue
            if any(re.search(rf"\b{re.escape(stem)}\b", text) for stem in stems):
                needed.add(name)
                changed = True
    return needed


def step_uses(step: object) -> str:
    if not isinstance(step, dict):
        return ""
    uses = step.get("uses")
    return uses if isinstance(uses, str) else ""


def step_run(step: object) -> str:
    if not isinstance(step, dict):
        return ""
    run = step.get("run")
    return run if isinstance(run, str) else ""


def check(
    root: Path, exemptions: dict[tuple[str, str], str] | None = None
) -> list[str]:
    exemptions = EXEMPTIONS if exemptions is None else exemptions
    failures: list[str] = []

    action_file = root / ACTION_REF.removeprefix("./") / "action.yml"
    if not action_file.is_file():
        return [
            f"the shared provisioning action is missing: {action_file}; "
            "every job below references it"
        ]

    try:
        needed_sources = yaml_dependent_sources(root)
    except WorkflowError as error:
        return [str(error)]

    workflow_dir = root / ".github" / "workflows"
    paths = sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))
    if not paths:
        return [f"no workflow files found under {workflow_dir}"]

    seen_jobs: set[tuple[str, str]] = set()
    needing_jobs: set[tuple[str, str]] = set()

    for path in paths:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            failures.append(f"{path.name} is not readable as YAML: {error}")
            continue
        jobs = document.get("jobs") if isinstance(document, dict) else None
        if not isinstance(jobs, dict):
            continue

        for job_name, job in jobs.items():
            if not isinstance(job_name, str) or not isinstance(job, dict):
                continue
            coordinate = (path.name, job_name)
            seen_jobs.add(coordinate)
            steps = job.get("steps")
            if not isinstance(steps, list):
                # A job that calls a reusable workflow has no steps of its
                # own; the called workflow is itself scanned when it lives in
                # this tree.
                continue

            consumers = [
                index
                for index, step in enumerate(steps)
                if any(source in step_run(step) for source in needed_sources)
            ]
            if not consumers:
                if any(step_uses(step) == ACTION_REF for step in steps):
                    print(
                        f"::notice::{path.name}:{job_name} provisions PyYAML but "
                        "runs nothing that needs it; harmless, but the step is "
                        "dead configuration"
                    )
                continue

            needing_jobs.add(coordinate)
            provisions = [
                index
                for index, step in enumerate(steps)
                if step_uses(step) == ACTION_REF
            ]
            label = f"{path.name}:{job_name}"

            if coordinate in exemptions:
                if provisions:
                    failures.append(
                        f"{label} is exempted from the shared action but uses it; "
                        "delete the exemption"
                    )
                continue

            if not provisions:
                failures.append(
                    f"{label} runs {sorted({s for s in needed_sources if any(s in step_run(steps[i]) for i in consumers)})} "
                    f"but never uses {ACTION_REF}"
                )
                continue
            if len(provisions) > 1:
                failures.append(
                    f"{label} uses {ACTION_REF} {len(provisions)} times; "
                    "one provisioning step per job"
                )
            if provisions[0] > consumers[0]:
                failures.append(
                    f"{label} uses {ACTION_REF} at step index {provisions[0]}, "
                    f"after the PyYAML consumer at step index {consumers[0]}"
                )
            shadowing = [
                index
                for index, step in enumerate(steps)
                if SETUP_PYTHON in step_uses(step) and index > provisions[0]
            ]
            if shadowing:
                failures.append(
                    f"{label} runs {SETUP_PYTHON} at step index "
                    f"{shadowing[0]}, after {ACTION_REF} at step index "
                    f"{provisions[0]}; setup-python puts a hostedtoolcache "
                    "interpreter ahead of the provisioned one on PATH, which "
                    "is the exact defect this gate exists to stop"
                )

    for coordinate, reason in exemptions.items():
        label = f"{coordinate[0]}:{coordinate[1]}"
        if coordinate not in seen_jobs:
            failures.append(
                f"exemption for {label} names a job that no longer exists; "
                f"remove it. Recorded reason: {reason}"
            )
        elif coordinate not in needing_jobs:
            failures.append(
                f"exemption for {label} is stale: the job no longer runs "
                f"anything that needs PyYAML; remove it. Recorded reason: {reason}"
            )

    if not needing_jobs:
        failures.append(
            "no job runs a PyYAML-dependent script; the gate would pass "
            "vacuously, which cannot be right while the aggregator is wired"
        )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--no-exemptions",
        action="store_true",
        help=(
            "ignore the exemption table entirely. Strictly stronger than the "
            "default, never weaker; used by the fixture tests, which build "
            "trees the live exemptions do not describe."
        ),
    )
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    failures = check(root, exemptions={} if arguments.no_exemptions else None)
    if failures:
        print("FAIL: PyYAML provisioning is not exhaustive:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(
        "PASS: every job running a PyYAML-dependent script uses "
        f"{ACTION_REF} before it and after any {SETUP_PYTHON}"
        + (f"; {len(EXEMPTIONS)} explicit exemption(s)" if EXEMPTIONS else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
