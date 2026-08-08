#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Require this tag push's full per-commit acceptance evidence to be green.

The tag being published points at exactly one commit. This gate refuses
publication unless, for that exact commit (GITHUB_SHA), every required
push-triggered evidence workflow of this same tag push has completed
successfully:

  * ci.yml           — additionally requiring its `release-evidence`
                       conjunction job, which is the only job that consumes
                       every security-relevant CI job's result
  * golden-path.yml  — the deterministic-shell / deploy / governor demos
  * security.yml     — dependency and fuzz scanning

Three distinct refusal states, never conflated:

  FAILED   — a run completed unsuccessfully: refuse, naming the commit and
             the failing checks.
  PENDING  — a run exists but has not completed: block, and on timeout
             refuse with a message that says IN PROGRESS, not failed.
  ABSENT   — no run exists for the commit: refuse. Silence must fail.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


EVIDENCE_JOB = "release-evidence"
CI_WORKFLOW = "ci.yml"
# Every push-triggered workflow whose result is release acceptance evidence.
# g2-mutation-ablation.yml is schedule-only and public-export.yml is
# dispatch-only; neither runs for a push, so neither can gate one.
REQUIRED_WORKFLOWS = (CI_WORKFLOW, "golden-path.yml", "security.yml")
MAX_CREATION_SKEW = timedelta(seconds=2)
# Job conclusions that do not indict a completed run. "skipped" covers jobs
# whose `if:` did not apply to this event (e.g. pull_request-only jobs on a
# push run); the RUN conclusion stays the truth for the whole workflow.
NON_FAILING_JOB_CONCLUSIONS = frozenset({"success", "skipped", "neutral"})


class GateError(RuntimeError):
    """A condition that must prevent publication."""


def object_field(value: Any, field: str, context: str) -> Any:
    if not isinstance(value, dict) or field not in value:
        raise GateError(f"{context} did not report {field}")
    return value[field]


def parse_timestamp(value: Any, context: str) -> datetime:
    if not isinstance(value, str):
        raise GateError(f"{context} reported an invalid created_at")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise GateError(f"{context} reported an invalid created_at: {value}") from error
    if parsed.tzinfo is None:
        raise GateError(f"{context} reported a timezone-free created_at: {value}")
    return parsed.astimezone(timezone.utc)


class GitHubActions:
    def __init__(self, repository: str, token: str) -> None:
        self.repository = quote(repository, safe="/")
        self.token = token

    def get(self, path: str, query: dict[str, str] | None = None) -> Any:
        url = f"https://api.github.com/repos/{self.repository}/{path}"
        if query:
            url = f"{url}?{urlencode(query)}"
        request = Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "seal-host-tag-release-gate",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                return json.load(response)
        except HTTPError as error:
            raise GateError(f"GitHub API {path} returned HTTP {error.code}") from error
        except URLError as error:
            raise GateError(f"GitHub API {path} was unreachable: {error.reason}") from error
        except (json.JSONDecodeError, TimeoutError) as error:
            raise GateError(f"GitHub API {path} returned no usable result: {error}") from error

    def release_run(self, run_id: str) -> Any:
        return self.get(f"actions/runs/{quote(run_id, safe='')}")

    def workflow_runs(self, workflow: str, sha: str) -> Any:
        return self.get(
            f"actions/workflows/{quote(workflow, safe='')}/runs",
            {"event": "push", "head_sha": sha, "per_page": "100"},
        )

    def jobs(self, run_id: int) -> Any:
        return self.get(
            f"actions/runs/{run_id}/jobs",
            {"filter": "latest", "per_page": "100"},
        )


class RecordedActions:
    """Offline API recording used to exercise the exact production evaluator."""

    def __init__(self, state: Any) -> None:
        if not isinstance(state, dict):
            raise GateError("recorded state must be a JSON object")
        self.state = state

    def release_run(self, run_id: str) -> Any:
        return object_field(self.state, "release_run", "recorded state")

    def workflow_runs(self, workflow: str, sha: str) -> Any:
        runs_by_workflow = object_field(self.state, "runs_by_workflow", "recorded state")
        if not isinstance(runs_by_workflow, dict):
            raise GateError("recorded runs_by_workflow must be a JSON object")
        return object_field(runs_by_workflow, workflow, "recorded runs_by_workflow")

    def jobs(self, run_id: int) -> Any:
        jobs_by_run = object_field(self.state, "jobs_by_run", "recorded state")
        if not isinstance(jobs_by_run, dict):
            raise GateError("recorded jobs_by_run must be a JSON object")
        return object_field(jobs_by_run, str(run_id), f"recorded run {run_id}")


def validate_release_run(release_run: Any, sha: str) -> datetime:
    context = "tag release run"
    if object_field(release_run, "event", context) != "push":
        raise GateError("tag release run was not triggered by a push")
    if object_field(release_run, "head_sha", context) != sha:
        raise GateError("tag release run SHA does not match GITHUB_SHA")
    path = object_field(release_run, "path", context)
    if not isinstance(path, str) or path.split("@", 1)[0] != ".github/workflows/release.yml":
        raise GateError(f"tag release run reported unexpected workflow path: {path}")
    return parse_timestamp(object_field(release_run, "created_at", context), context)


def matching_runs(
    payload: Any, workflow: str, sha: str, release_created: datetime
) -> list[dict[str, Any]]:
    runs = object_field(payload, "workflow_runs", f"{workflow} runs response")
    if not isinstance(runs, list):
        raise GateError(f"{workflow} runs response did not contain a workflow_runs list")

    earliest = release_created - MAX_CREATION_SKEW
    matches: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        if run.get("event") != "push" or run.get("head_sha") != sha:
            continue
        created = parse_timestamp(run.get("created_at"), f"{workflow} run")
        if created >= earliest:
            matches.append(run)
    return matches


def failing_job_names(actions: Any, run_id: int, workflow: str) -> list[str]:
    """Names of the completed run's unsuccessful jobs, best effort but honest.

    A failure to enumerate jobs must not soften the refusal that is already
    underway, so this reports what it can and never raises past the caller.
    """
    try:
        payload = actions.jobs(run_id)
        jobs = object_field(payload, "jobs", f"{workflow} run {run_id} jobs response")
        if not isinstance(jobs, list):
            return []
    except GateError:
        return []
    return sorted(
        str(job.get("name"))
        for job in jobs
        if isinstance(job, dict)
        and job.get("name")
        and job.get("conclusion") not in NON_FAILING_JOB_CONCLUSIONS
    )


def require_evidence(jobs_payload: Any, run_id: int, sha: str) -> None:
    jobs = object_field(jobs_payload, "jobs", f"CI run {run_id} jobs response")
    if not isinstance(jobs, list):
        raise GateError(f"CI run {run_id} jobs response did not contain a jobs list")
    evidence = [
        job
        for job in jobs
        if isinstance(job, dict) and job.get("name") == EVIDENCE_JOB
    ]
    if not evidence:
        raise GateError(
            f"refusing to publish commit {sha}: CI run {run_id} did not report "
            f"required job {EVIDENCE_JOB}; job data may be missing or expired"
        )
    if len(evidence) != 1:
        raise GateError(
            f"refusing to publish commit {sha}: CI run {run_id} reported "
            f"{len(evidence)} {EVIDENCE_JOB} jobs"
        )

    job = evidence[0]
    status = object_field(job, "status", EVIDENCE_JOB)
    conclusion = object_field(job, "conclusion", EVIDENCE_JOB)
    print(f"tag-release-gate: CI run {run_id} {EVIDENCE_JOB}={conclusion}")
    if status != "completed":
        raise GateError(
            f"refusing to publish commit {sha}: required CI job {EVIDENCE_JOB} "
            f"was not completed (status: {status})"
        )
    if conclusion != "success":
        raise GateError(
            f"refusing to publish commit {sha}: acceptance FAILED — required CI "
            f"job {EVIDENCE_JOB} concluded {conclusion}"
        )


def evaluate_workflows(
    actions: GitHubActions | RecordedActions, sha: str, release_created: datetime
) -> tuple[list[str], list[str]]:
    """One sweep over every required workflow for the exact commit.

    Returns (pending_descriptions, absent_workflows) when nothing has failed
    yet; raises GateError the moment any completed run is unsuccessful.
    """
    pending: list[str] = []
    absent: list[str] = []
    for workflow in REQUIRED_WORKFLOWS:
        matches = matching_runs(
            actions.workflow_runs(workflow, sha), workflow, sha, release_created
        )
        if len(matches) > 1:
            ids = ", ".join(str(run.get("id", "unknown")) for run in matches)
            raise GateError(
                f"tag push matched multiple {workflow} runs ({ids}); refusing ambiguity"
            )
        if not matches:
            absent.append(workflow)
            continue
        run = matches[0]
        run_id = object_field(run, "id", f"{workflow} run")
        if not isinstance(run_id, int):
            raise GateError(f"{workflow} run reported an invalid id")
        status = object_field(run, "status", f"{workflow} run {run_id}")
        conclusion = object_field(run, "conclusion", f"{workflow} run {run_id}")
        if status != "completed":
            pending.append(f"{workflow} run {run_id} (status: {status})")
            continue
        if conclusion != "success":
            failing = failing_job_names(actions, run_id, workflow)
            named = ", ".join(failing) if failing else "unreported by the jobs API"
            raise GateError(
                f"refusing to publish commit {sha}: acceptance FAILED — "
                f"{workflow} run {run_id} concluded {conclusion}; "
                f"failing checks: {named}"
            )
        if workflow == CI_WORKFLOW:
            require_evidence(actions.jobs(run_id), run_id, sha)
        print(f"tag-release-gate: {workflow} run {run_id} success for commit {sha}")
    return pending, absent


def refuse_incomplete(sha: str, pending: list[str], absent: list[str]) -> GateError:
    """Build the timeout refusal, keeping PENDING and ABSENT distinguishable."""
    reasons: list[str] = []
    if pending:
        reasons.append(
            "acceptance still IN PROGRESS (pending, not failed): "
            + "; ".join(pending)
            + " — a pending acceptance run is not success"
        )
    if absent:
        reasons.append(
            "NO acceptance run exists for: "
            + ", ".join(absent)
            + " — missing evidence is not success"
        )
    if not reasons:
        reasons.append("acceptance evidence could not be obtained")
    return GateError(f"refusing to publish commit {sha}: " + "; ".join(reasons))


def run_gate(
    actions: GitHubActions | RecordedActions,
    release_run_id: str,
    sha: str,
    timeout_seconds: int,
    poll_seconds: int,
) -> None:
    release_created = validate_release_run(actions.release_run(release_run_id), sha)
    deadline = time.monotonic() + timeout_seconds

    while True:
        pending, absent = evaluate_workflows(actions, sha, release_created)
        if not pending and not absent:
            print(
                "tag-release-gate: PASS (commit "
                f"{sha}: {', '.join(REQUIRED_WORKFLOWS)} all completed "
                f"successfully, including CI {EVIDENCE_JOB})"
            )
            return
        for description in pending:
            print(f"tag-release-gate: waiting for {description}")
        for workflow in absent:
            print(
                f"tag-release-gate: waiting for this tag push's {workflow} "
                "run to appear"
            )

        if time.monotonic() >= deadline:
            raise refuse_incomplete(sha, pending, absent)
        time.sleep(poll_seconds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-json", help="recorded Actions state for an offline gate test")
    parser.add_argument("--timeout-seconds", type=int, default=7200)
    parser.add_argument("--poll-seconds", type=int, default=30)
    return parser.parse_args()


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise GateError(f"{name} is not set")
    return value


def main() -> int:
    args = parse_args()
    try:
        if args.timeout_seconds < 0 or args.poll_seconds < 0:
            raise GateError("timeouts must not be negative")
        repository = required_env("GITHUB_REPOSITORY")
        sha = required_env("GITHUB_SHA")
        release_run_id = required_env("GITHUB_RUN_ID")
        if args.state_json is None:
            actions: GitHubActions | RecordedActions = GitHubActions(
                repository, required_env("GITHUB_TOKEN")
            )
        else:
            try:
                state = json.loads(args.state_json)
            except json.JSONDecodeError as error:
                raise GateError(f"recorded state is invalid JSON: {error}") from error
            actions = RecordedActions(state)
        run_gate(actions, release_run_id, sha, args.timeout_seconds, args.poll_seconds)
    except GateError as error:
        print(f"::error::tag-release-gate: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
