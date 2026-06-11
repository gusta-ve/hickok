"""hickok — reverse-shell handler & post-exploitation console."""

from __future__ import annotations

import argparse
import asyncio
import sys

from hickok import __version__, findings, payloads
from hickok.console import DIM, THEMES, Console
from hickok.handler import ShellServer

EXAMPLES = """\
examples:
  hickok                                 listen on :9001 and drop into the console
  hickok -l 9001,9002 --lhost 10.10.14.7 multiple listeners, fixed LHOST
  hickok hand                            act on wraith's latest run (found on its own)
  hickok payloads 10.10.14.7 9001        print reverse-shell one-liners
"""

_COMMANDS = {"listen", "hand", "payloads", "eights"}


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
