from hickok.sqlcache import Cache


def test_cache_persists_and_resumes(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    c = Cache("http://t/p?id=1", "id")
    assert len(c) == 0
    c.put("LENGTH(x)", 5)
    c.put("CODE(x,1)", 104)
    c.close()
    # a fresh process (new Cache) loads what was written — durable, resumable
    again = Cache("http://t/p?id=1", "id")
    assert len(again) == 2
    assert again.get("LENGTH(x)") == 5
    assert again.get("CODE(x,1)") == 104
    assert again.get("never-pulled") is None
    again.close()


def test_cached_zero_is_a_hit_not_a_miss(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    c = Cache("http://t/p?id=1", "id")
    c.put("CODE(x,9)", 0)          # a null char extracts to 0
    c.close()
    again = Cache("http://t/p?id=1", "id")
    assert again.get("CODE(x,9)") == 0   # 0 is cached, not treated as absent
    again.close()


def test_fresh_wipes_the_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    c = Cache("http://t/p?id=1", "id")
    c.put("a", 1)
    c.close()
    fresh = Cache("http://t/p?id=1", "id", fresh=True)
    assert len(fresh) == 0
    assert fresh.get("a") is None
    fresh.close()


def test_different_targets_dont_share(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    a = Cache("http://host-a/p?id=1", "id"); a.put("x", 1); a.close()
    b = Cache("http://host-b/p?id=1", "id")
    assert b.get("x") is None      # a separate target keeps its own cache
    b.close()
