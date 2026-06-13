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
