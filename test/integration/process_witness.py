#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Small diagnostics for failed stdio exchanges with child processes."""

from __future__ import annotations

import subprocess
from typing import NoReturn


class ChildProcessExchangeError(RuntimeError):
    """An exchange failed after its child process exited."""


def raise_with_child_stderr(
    proc: subprocess.Popen[str], error: BaseException
) -> NoReturn:
    """Add exit/stderr evidence if the child is dead; never read a live pipe."""
    exit_code = proc.poll()
    if exit_code is None:
        raise error

    stderr = proc.stderr.read() if proc.stderr is not None else ""
    raise ChildProcessExchangeError(
        f"child exited during exchange: exit={exit_code}\n"
        f"child stderr follows verbatim:\n{stderr}"
    ) from error
