#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Require this tag push's CI release-evidence job to have succeeded."""

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
MAX_CREATION_SKEW = timedelta(seconds=2)


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

    def ci_runs(self, sha: str) -> Any:
        return self.get(
            f"actions/workflows/{CI_WORKFLOW}/runs",
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

    def ci_runs(self, sha: str) -> Any:
        return object_field(self.state, "ci_runs", "recorded state")

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


def matching_ci_runs(payload: Any, sha: str, release_created: datetime) -> list[dict[str, Any]]:
    runs = object_field(payload, "workflow_runs", "CI runs response")
    if not isinstance(runs, list):
        raise GateError("CI runs response did not contain a workflow_runs list")

    earliest = release_created - MAX_CREATION_SKEW
    matches: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        if run.get("event") != "push" or run.get("head_sha") != sha:
            continue
        created = parse_timestamp(run.get("created_at"), "CI run")
        if created >= earliest:
            matches.append(run)
    return matches


def require_evidence(jobs_payload: Any, run_id: int) -> None:
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
            f"CI run {run_id} did not report required job {EVIDENCE_JOB}; "
            "job data may be missing or expired"
        )
    if len(evidence) != 1:
        raise GateError(f"CI run {run_id} reported {len(evidence)} {EVIDENCE_JOB} jobs")

    job = evidence[0]
    status = object_field(job, "status", EVIDENCE_JOB)
    conclusion = object_field(job, "conclusion", EVIDENCE_JOB)
    print(f"tag-release-gate: CI run {run_id} {EVIDENCE_JOB}={conclusion}")
    if status != "completed":
        raise GateError(f"required CI job {EVIDENCE_JOB} was not completed (status: {status})")
    if conclusion != "success":
        unsuccessful = sorted(
            str(candidate.get("name"))
            for candidate in jobs
            if isinstance(candidate, dict)
            and candidate.get("name")
            and candidate.get("conclusion") != "success"
        )
        if unsuccessful:
            print(
                "tag-release-gate: CI run unsuccessful jobs: "
                + ", ".join(unsuccessful)
            )
        raise GateError(
            f"required CI job {EVIDENCE_JOB} was not successful "
            f"(conclusion: {conclusion})"
        )


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
        matches = matching_ci_runs(actions.ci_runs(sha), sha, release_created)
        if len(matches) > 1:
            ids = ", ".join(str(run.get("id", "unknown")) for run in matches)
            raise GateError(f"tag push matched multiple CI runs ({ids}); refusing ambiguity")
        if matches:
            run = matches[0]
            run_id = object_field(run, "id", "CI run")
            if not isinstance(run_id, int):
                raise GateError("CI run reported an invalid id")
            status = object_field(run, "status", f"CI run {run_id}")
            conclusion = object_field(run, "conclusion", f"CI run {run_id}")
            if status == "completed":
                require_evidence(actions.jobs(run_id), run_id)
                if conclusion != "success":
                    raise GateError(
                        f"CI run {run_id} was not successful despite successful "
                        f"{EVIDENCE_JOB} (conclusion: {conclusion})"
                    )
                print(
                    f"tag-release-gate: PASS (CI run {run_id} consumed "
                    f"{EVIDENCE_JOB}=success)"
                )
                return
            print(f"tag-release-gate: waiting for CI run {run_id} (status: {status})")
        else:
            print("tag-release-gate: waiting for this tag push's CI run to appear")

        if time.monotonic() >= deadline:
            raise GateError(
                f"could not obtain completed CI {EVIDENCE_JOB} within "
                f"{timeout_seconds} seconds"
            )
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
