"""Read a wraith findings.json and pick out what can be turned into a foothold.

This is the bridge: wraith holds the aces (it finds and proves the way in),
hickok brings the eights (it acts on them). A finding that means code execution
is a door to a shell — hickok's whole reason to exist.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# Finding titles that imply server-side code execution -> a reverse shell.
_FOOTHOLD = (
    "command injection", "remote code", "rce", "code execution",
    "server-side template injection", "ssti", "deserial", "file upload",
)


def load(path) -> list[dict]:
    """Parse a wraith findings.json (a list of finding objects)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("not a wraith findings.json (expected a JSON list)")
    return data


def runs_dir() -> str:
    """The per-user runs directory wraith writes to by default — the same path
    wraith computes, so hickok finds runs from any working directory. Override
    with WRAITH_RUNS; both tools honour it."""
    env = os.environ.get("WRAITH_RUNS")
    if env:
        return os.path.expanduser(env)
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "wraith", "runs")


def latest(base: str | None = None) -> str | None:
    """The most recent wraith findings.json, or None. Looks in the shared runs
    dir (XDG / $WRAITH_RUNS) and, as a fallback, ./wraith-runs in the cwd."""
    where = [base] if base else [runs_dir(), "wraith-runs"]
    found: set[Path] = set()
    for d in where:
        found.update(Path(d).glob("*/findings.json"))
    paths = sorted(found, key=lambda p: p.stat().st_mtime, reverse=True)
    return str(paths[0]) if paths else None


def is_foothold(title: str) -> bool:
    """True if the finding's title implies code execution — a path to a shell."""
    t = (title or "").lower()
    return any(k in t for k in _FOOTHOLD)


def footholds(findings: list[dict]) -> list[dict]:
    return [f for f in findings if is_foothold(f.get("title", ""))]
