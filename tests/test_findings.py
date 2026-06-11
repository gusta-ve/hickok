import json

from hickok import findings


def test_is_foothold_flags_code_execution():
    assert findings.is_foothold("Command Injection in 'host'") is True
    assert findings.is_foothold("Server-Side Template Injection in 'name'") is True
    assert findings.is_foothold("Reflected XSS in 'q'") is False
    assert findings.is_foothold("SQL Injection (boolean blind) in 'id'") is False


def test_footholds_filters_actionable():
    items = [
        {"title": "Command Injection in 'host'", "severity": "Critical", "target": "http://t/ping"},
        {"title": "Reflected XSS in 'q'", "severity": "High", "target": "http://t/search"},
        {"title": "SSTI in 'name'", "severity": "High", "target": "http://t/render"},
    ]
    foot = findings.footholds(items)
    assert {f["target"] for f in foot} == {"http://t/ping", "http://t/render"}


def test_load_reads_wraith_json(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps([{"title": "x", "severity": "Low", "target": "http://t/"}]))
    data = findings.load(str(p))
    assert isinstance(data, list) and data[0]["title"] == "x"


def test_latest_picks_most_recent_run(tmp_path):
    import os
    base = tmp_path / "wraith-runs"
    old = base / "a.com-1"; old.mkdir(parents=True)
    new = base / "b.com-2"; new.mkdir(parents=True)
    (old / "findings.json").write_text("[]")
    (new / "findings.json").write_text("[]")
    os.utime(old / "findings.json", (1000, 1000))
    os.utime(new / "findings.json", (2000, 2000))   # newer
    assert findings.latest(str(base)) == str(new / "findings.json")


def test_latest_none_when_nothing_there(tmp_path):
    assert findings.latest(str(tmp_path / "missing")) is None
