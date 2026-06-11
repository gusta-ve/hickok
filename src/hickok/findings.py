"""Read a wraith findings.json and pick out what can be turned into a foothold.

This is the bridge: wraith holds the aces (it finds and proves the way in),
hickok brings the eights (it acts on them). A finding that means code execution
is a door to a shell — hickok's whole reason to exist.
"""

from __future__ import annotations

import json
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


def latest(base: str = "wraith-runs") -> str | None:
    """The most recent wraith findings.json under ./<base>/*/, or None — so
    `hickok hand` can just pick up the last run without being told where."""
    paths = sorted(Path(base).glob("*/findings.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return str(paths[0]) if paths else None


def is_foothold(title: str) -> bool:
    """True if the finding's title implies code execution — a path to a shell."""
    t = (title or "").lower()
    return any(k in t for k in _FOOTHOLD)


def footholds(findings: list[dict]) -> list[dict]:
    return [f for f in findings if is_foothold(f.get("title", ""))]
