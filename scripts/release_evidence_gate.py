#!/usr/bin/env python3
"""Fail unless every job required by the release-evidence gate succeeded."""

import json
import os
import sys
from typing import Any


INPUT_ENV = "RELEASE_EVIDENCE_NEEDS"


def load_results() -> dict[str, Any]:
    raw_results = os.environ.get(INPUT_ENV)
    if raw_results is None:
        raise ValueError(f"{INPUT_ENV} is not set")

    parsed = json.loads(raw_results)
    if not isinstance(parsed, dict) or not parsed:
        raise ValueError(f"{INPUT_ENV} must be a non-empty JSON object")
    return parsed


def main() -> int:
    try:
        jobs = load_results()
    except (json.JSONDecodeError, ValueError) as error:
        print(f"::error::release-evidence: invalid gate input: {error}")
        return 1

    failures = 0
    for job_name, job_data in jobs.items():
        result = job_data.get("result") if isinstance(job_data, dict) else None
        print(f"release-evidence: {job_name}={result}")
        if result != "success":
            failures += 1
            print(
                f"::error::release-evidence: {job_name} was not successful "
                f"(result: {result})"
            )

    if failures:
        noun = "job" if failures == 1 else "jobs"
        print(f"release-evidence: FAIL ({failures} {noun} not successful)")
        return 1

    print("release-evidence: PASS (all required jobs succeeded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
