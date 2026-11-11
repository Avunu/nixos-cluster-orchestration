"""Subprocess helpers: one place that turns a failed command into an AvcError
carrying its stderr, instead of a CalledProcessError traceback."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

from avc.errors import AvcError


def run(
    cmd: Sequence[str],
    cwd: Path | None = None,
    check: bool = True,
    capture: bool = True,
    input: str | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        p = subprocess.run(
            list(cmd),
            cwd=cwd,
            text=True,
            input=input,
            capture_output=capture,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise AvcError(f"{cmd[0]}: not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise AvcError(f"{' '.join(cmd[:3])}…: timed out after {timeout}s") from e
    if check and p.returncode != 0:
        detail = (p.stderr or p.stdout or "").strip() if capture else ""
        raise AvcError(f"{' '.join(cmd[:4])}… failed ({p.returncode})" + (f":\n{detail}" if detail else ""))
    return p


def out(cmd: Sequence[str], cwd: Path | None = None, timeout: float | None = None) -> str:
    return run(cmd, cwd=cwd, timeout=timeout).stdout.strip()
