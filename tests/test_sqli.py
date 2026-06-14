import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from hickok import http, sqli


class _FakeOracle:
    """Answers `(expr) > n` / `(expr) >= n` for a known value, so the binary
    search can be tested without a server."""

    def __init__(self, resolver):
        self.resolver = resolver   # cond -> the integer being compared
        self.count = 0

    def ask(self, cond: str) -> bool:
        self.count += 1
        op, n = re.search(r"(>=|>)\s*(\d+)\s*$", cond).groups()
        val = self.resolver(cond)
        return val > int(n) if op == ">" else val >= int(n)


def test_extract_int_binary_search():
    o = _FakeOracle(lambda cond: 31337)
    assert sqli.extract_int(o, "whatever") == 31337


def test_extract_str_reads_each_char():
    secret = "s3cr3t!"
    prof = sqli._PROFILES["sqlite"]

    def resolver(cond):
        if "length(" in cond.lower():
            return len(secret)
        i = int(re.search(r",\s*(\d+)\s*,\s*1", cond).group(1))   # substr((q),i,1)
        return ord(secret[i - 1]) if 1 <= i <= len(secret) else 0

    assert sqli.extract_str(_FakeOracle(resolver), prof, "(SELECT password ...)") == secret


def test_profiles_cover_each_dbms_with_the_same_shape():
    keys = set(sqli._PROFILES["sqlite"])
    for name, prof in sqli._PROFILES.items():
        assert set(prof) == keys, f"{name} profile is missing keys"
    assert {"sqlite", "mysql", "mssql", "postgres"} <= set(sqli._PROFILES)


def _reflecting_sqlite_server():
    """A tiny app: SELECT a,b FROM t WHERE a='<id>', reflected — UNION-injectable."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript("CREATE TABLE t (a TEXT, b TEXT);"
                     "INSERT INTO t VALUES ('x1','y1'),('x2','y2');")
    lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            raw = (parse_qs(urlsplit(self.path).query).get("id") or ["x1"])[0]
            try:
                with lock:
                    row = db.execute(f"SELECT a, b FROM t WHERE a = '{raw}'").fetchone()
            except Exception:
                row = None
            body = (f"<h1>{row[0]}</h1><p>{row[1]}</p>" if row else "none").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_union_walks_and_dumps_a_table():
    srv = _reflecting_sqlite_server()
    port = srv.server_address[1]
    net = http.Http(timeout=5)
    oracle = sqli.calibrate(net, f"http://127.0.0.1:{port}/?id=x1", "id", "x1")
    assert oracle is not None
    setup = sqli.union_setup(net, oracle, "sqlite")
    assert setup == (2, 0)                     # 2 columns, the first is reflected
    dbs = sqli.union_databases(net, oracle, "sqlite", *setup)
    assert "main" in dbs                       # the attached database, read via UNION
    cols = sqli.union_columns(net, oracle, "sqlite", *setup, "t")
    assert cols == ["a", "b"]
    rows = sqli.union_dump(net, oracle, "sqlite", *setup, "t", cols)
    srv.shutdown()
    assert ["x1", "y1"] in rows and ["x2", "y2"] in rows


def _blind_sleep_server():
    """A totally blind app: same page always, but a true condition can sleep —
    only time-based works here."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript("CREATE TABLE u (id INTEGER); INSERT INTO u VALUES (1);")
    db.create_function("sleep", 1, lambda n: time.sleep(min(float(n), 2)) or 0)
    lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            raw = (parse_qs(urlsplit(self.path).query).get("id") or ["1"])[0]
            try:
                with lock:
                    db.execute(f"SELECT id FROM u WHERE id = '{raw}'").fetchone()
            except Exception:
                pass
            body = b"<h1>ok</h1>"                  # identical no matter what
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_time_based_calibrates_and_answers():
    srv = _blind_sleep_server()
    net = http.Http(timeout=10)
    o = sqli.time_calibrate(net, f"http://127.0.0.1:{srv.server_address[1]}/?id=1", "id", "1", n=1)
    try:
        assert o is not None and o.dbms == "sqlite"
        assert o.ask("1=1") is True        # a true condition sleeps -> over threshold
        assert o.ask("1=2") is False       # a false one stays fast
    finally:
        srv.shutdown()
