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
                    "an empty no-results page goes here", threshold=0.6)
    o.ask("(SELECT count(*) FROM information_schema.tables)>1")
    assert o.blocked == 1


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
        sqli.union_columns(_Http(), o, dbms, 4, 0, "app_users")
        sqli.union_dump(_Http(), o, dbms, 4, 0, "app_users", ["a", "b"])
        assert all("%27" not in u and "'" not in u for u in sent), (dbms, sent)


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
