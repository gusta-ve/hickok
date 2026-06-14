"""A per-target value cache for `hickok sql`.

Boolean/time-blind extraction costs many requests per value, so we never want to
pull the same value twice. Every resolved SQL expression (a length, a char code,
a row count) is written to a small per-target log the moment it's found; a later
run — or one resumed after Ctrl-C — loads the log and returns those values
instantly (zero requests), picking up exactly where it left off.

Append-only JSONL keyed by the SQL expression: O(1) crash/Ctrl-C-safe writes, and
a dict lookup on read, so a cache hit costs nothing.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit


def runs_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return Path(base) / "hickok" / "sql"


def _key(url: str, param: str) -> str:
    u = urlsplit(url)
    sig = f"{u.scheme}://{u.netloc}{u.path}|{param}"
    digest = hashlib.sha1(sig.encode("utf-8")).hexdigest()[:10]
    host = (u.hostname or "target").replace(":", "_")
    return f"{host}_{param}_{digest}"


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)[:64] or "x"


def save_dump(url: str, param: str, table: str, cols, rows, out_dir=None) -> "Path | None":
    """Write a dumped table to a CSV (header + rows). Returns the path, or None if
    it couldn't be written.

    Default location is runs_dir()/dumps with a host/param/table name, so dumps
    from any target land in one place without colliding. With `out_dir` (the
    `--output` override) the file is just `<table>.csv` in that directory — the
    user owns the layout there."""
    if out_dir:
        path = Path(out_dir).expanduser() / f"{_safe(table)}.csv"
    else:
        u = urlsplit(url)
        host = (u.hostname or "target").replace(":", "_")
        path = runs_dir() / "dumps" / f"{host}_{_safe(param)}_{_safe(table)}.csv"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(list(cols))
            w.writerows(rows)
    except OSError:
        return None
    return path


class Cache:
    """Maps an SQL expression to its extracted integer value, backed by a file."""

    def __init__(self, url: str, param: str, fresh: bool = False):
        self.path = runs_dir() / f"{_key(url, param)}.jsonl"
        self._data: dict[str, int] = {}
        self._fh = None
        if fresh:
            try:
                self.path.unlink()
            except OSError:
                pass
        else:
            self._load()
        self._open()

    def _load(self) -> None:
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError:
            return
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                self._data[rec["e"]] = rec["v"]
            except (ValueError, KeyError, TypeError):
                continue

    def _open(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("a", encoding="utf-8")
        except OSError:
            self._fh = None

    def __len__(self) -> int:
        return len(self._data)

    def get(self, expr: str):
        """The cached value for an expression, or None if it hasn't been pulled."""
        return self._data.get(expr)

    def put(self, expr: str, value: int) -> None:
        if expr in self._data:
            return
        self._data[expr] = value
        if self._fh is not None:
            try:
                self._fh.write(json.dumps({"e": expr, "v": value}, separators=(",", ":")) + "\n")
                self._fh.flush()          # durable now, so Ctrl-C keeps it
            except OSError:
                pass

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None
