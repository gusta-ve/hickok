"""Console output: banner, colour themes, card art and the dead man's hand.

Dependency-free (ANSI / truecolor). Colour auto-enables on a TTY and honours
NO_COLOR; force it with HICKOK_COLOR=1. Pick a theme with --theme or HICKOK_THEME
(ember | steel | bone | crimson).
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from pathlib import Path

from hickok import __version__

_ART_DIR = Path(__file__).resolve().parent / "art"
_RAMP = " .:-=+*#%@"
_HSPIN = "⣾⣽⣻⢿⡿⣟⣯⣷"   # a turning block for the live "working" heartbeat

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

THEMES = {
    "ember":   {"grad": ((255, 205, 95), (150, 60, 0)), "accent": (255, 185, 70)},   # Deadwood gold
    "steel":   {"grad": ((180, 200, 220), (40, 60, 90)), "accent": (150, 180, 215)},  # gunmetal
    "bone":    {"grad": ((235, 235, 235), (120, 120, 120)), "accent": (220, 220, 220)},
    "crimson": {"grad": ((255, 80, 80), (110, 0, 12)), "accent": (255, 85, 85)},      # match wraith
}
DEFAULT_THEME = "ember"

_BONE = (235, 235, 235)   # black suits render bright on a dark terminal


def _fg(rgb) -> str:
    return f"\033[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"


def _lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _supports_color(force=None) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("HICKOK_COLOR"):
        return True
    return sys.stdout.isatty()


class Console:
    def __init__(self, theme=None, color=None, banner=True, verbose=0):
        name = theme or os.environ.get("HICKOK_THEME") or DEFAULT_THEME
        self.theme = THEMES.get(name, THEMES[DEFAULT_THEME])
        self.color = _supports_color(color)
        self.show_banner = banner
        self.verbose = int(verbose or 0)
        self._spinning = False   # a working-spinner line is currently drawn (TTY)
        self.showdown = None     # a Showdown (see showdown.py) when the mode is on
        # The working-heartbeat (see _Working) redraws the spinner from a background
        # thread while the main thread emits real output; both touch stdout and the
        # _spinning flag, so a lock serializes them — no half-written, interleaved line.
        self._lock = threading.Lock()

    def trace(self, msg, level: int = 1) -> None:
        """Verbose-only line (e.g. -v shows each SQLi payload). Silent without -v."""
        if self.verbose >= level:
            self._emit(self._c(DIM, "      · ") + str(msg))

    def _emit(self, text: str = "") -> None:
        with self._lock:
            if self._spinning:           # wipe the spinner line before real output lands
                sys.stdout.write("\r\033[K")
                self._spinning = False
            print(text, flush=True)

    def spinner(self, frame: str, label: str) -> None:
        """Draw one frame of a spinner — a single rewritten line, TTY only,
        auto-cleared by _emit before any real output. No newline."""
        if not sys.stdout.isatty():
            return
        line = "\r\033[K" + self._accent(frame) + " " + self._c(DIM, label)
        with self._lock:
            sys.stdout.write(line)
            sys.stdout.flush()
            self._spinning = True

    def spin_clear(self) -> None:
        with self._lock:
            if self._spinning:
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
                self._spinning = False

    def working(self, label: str, count_fn=None):
        """A live heartbeat for a blocking call: a spinner that turns on its own
        timer (not per request), so even a slow remote looks alive. Use it as a
        context manager around the blocking work; it clears itself on exit. No-op
        off a TTY or at -v 2+, where every payload is already traced."""
        return _Working(self, label, count_fn)

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def _accent(self, text: str) -> str:
        return self._c(_fg(self.theme["accent"]), text)

    # --------------------------------------------------------------- cards
    # a face-down card — the dead man's hand's fifth card, never known
    _BACK = ("╭───────╮", "│╱╲╱╲╱╲╱│", "│╲╱╲╱╲╱╲│", "│╱╲╱╲╱╲╱│",
             "│╲╱╲╱╲╱╲│", "│╱╲╱╲╱╲╱│", "╰───────╯")

    def _cards(self, specs, indent: str = "    ") -> None:
        """Lay a row of playing cards face-up, in bright bone — rank in the
        corners, the suit pip centred, the way a real card reads. A spec of
        ``None`` is a face-down card (muted back), the unknown fifth card."""
        white = _fg(_BONE)
        cols = []
        for spec in specs:
            if spec is None:
                cols.append([self._c(DIM + white, ln) for ln in self._BACK])
                continue
            r, s = spec
            face = ("╭───────╮", f"│ {r:<6}│", "│       │", f"│   {s}   │",
                    "│       │", f"│{r:>6} │", "╰───────╯")
            cols.append([self._c(BOLD + white, ln) for ln in face])
        for row in zip(*cols):
            self._emit(indent + "   ".join(row))

    # -------------------------------------------------------------- banner
    def banner(self) -> None:
        if not self.show_banner:
            return
        self._emit()
        self._glow_art("banner.txt", *self._GLOW)        # the gunslinger, his hat low
        self._emit()
        self._emit("  " + self._c(BOLD + _fg(self.theme["accent"]), "hickok")
                   + self._c(DIM, "  ·  reverse-shell handler & post-exploitation")
                   + "   " + self._c(DIM, f"v{__version__}"))
        self._emit("  " + self._c(DIM, "gusta-ve · github.com/gusta-ve/hickok · authorized use only"))
        self._emit("  " + self._c(DIM, "Wild Bill Hickok · Deadwood, 1876"))
        if self.showdown:
            self._emit("  " + self._accent("◆ ") + self._c(BOLD, "showdown mode")
                       + self._c(DIM, " — hickok plays the catch out"))
        self._emit()

    # --------------------------------------------------------------- lines
    def info(self, msg) -> None:
        self._emit(self._c("\033[36m", "  [*] ") + str(msg))

    def good(self, msg) -> None:
        self._emit(self._c("\033[32m", "  [+] ") + str(msg))

    def warn(self, msg) -> None:
        self._emit(self._c("\033[33m", "  [!] ") + str(msg))

    def bad(self, msg) -> None:
        self._emit(self._c("\033[31m", "  [-] ") + str(msg))

    def plain(self, msg: str = "") -> None:
        self._emit(msg)

    def rule(self, title: str = "") -> None:
        if title:
            self._emit(self._c(DIM, f"── {title} " + "─" * max(0, 52 - len(title))))
        else:
            self._emit(self._c(DIM, "─" * 56))

    # ----------------------------------------------------------- the hand
    def eights(self) -> None:
        """Hickok lays down the eights — half the dead man's hand."""
        self._emit()
        self._cards([("8", "♠"), ("8", "♣")])
        self._emit()
        self._emit("        " + self._c(DIM, "Hickok lays down the eights."))
        self._emit("        " + self._c(DIM, "…and Hickok was holding the eights."))
        self._emit()

    def _center(self, text: str, center: float = 40) -> str:
        """Indent a (possibly coloured) line so its visible text centres on the
        ``center`` column — used to sit the cards and captions under the art."""
        visible = re.sub(r"\x1b\[[0-9;]*m", "", text)
        return " " * max(0, round(center - len(visible) / 2)) + text

    def _art_center(self, name: str) -> float:
        """The column the art's figure is centred on when drawn (with the 2-space
        indent of `_glow_art`), so the cards/captions can line up under it."""
        try:
            art = (_ART_DIR / name).read_text(encoding="utf-8").rstrip("\n").split("\n")
        except OSError:
            return 40
        ne = [l for l in art if l.strip()]
        if not ne:
            return 40
        left = min(len(l) - len(l.lstrip()) for l in ne)
        right = max(len(l.rstrip()) for l in ne)
        return 2 + (left + right) / 2

    def dead_mans_hand(self, dealt_by_wraith: bool = False, center: float = 40) -> None:
        """The full hand laid down — aces and eights. When the aces came from a
        wraith findings file, the catch is acknowledged. Cards and captions are
        centred on ``center`` (the reveal passes the gunslinger's own centre)."""
        block = 5 * 9 + 4 * 3
        indent = " " * max(0, round(center - block / 2))
        self._emit()
        self._cards([("A", "♠"), ("A", "♣"), ("8", "♠"), ("8", "♣"), None], indent=indent)
        self._emit()
        self._emit(self._center(self._c(BOLD, "aces and eights — the dead man's hand."), center))
        self._emit(self._center(self._c(DIM, "the fifth card stayed face down — nobody knows what Bill held."), center))
        if dealt_by_wraith:
            self._emit(self._center(self._c(DIM, "the wraith dealt the aces; Hickok brought the eights."), center))
        self._emit(self._center(self._c(DIM, "J.B. Hickok, Deadwood 1876.  the house always collects."), center))
        self._emit()

    # ------------------------------------------------------- the gunslinger
    @staticmethod
    def _tint(run, idx, lo, hi) -> str:
        if not run:
            return ""
        if idx <= 0:
            return run
        bold = BOLD if idx >= 6 else ""
        return bold + _fg(_lerp(lo, hi, (idx - 1) / 8)) + run + RESET

    def _glow_art(self, name: str, lo, hi, live: bool = False) -> None:
        """Render a ramp-art file with a low→high glow. ``live`` draws it row by
        row (the reveal rises into view); otherwise it lands all at once (banner).
        Piped / non-interactive output is never animated."""
        try:
            art = (_ART_DIR / name).read_text(encoding="utf-8").rstrip("\n").split("\n")
        except OSError:
            return
        draw = live and self.color and sys.stdout.isatty()
        for line in art:
            if not self.color:
                self._emit("  " + line)
                continue
            out, run, idx = "  ", "", -1
            for ch in line:
                i = _RAMP.find(ch)
                if i < 0:
                    i = 0
                if i != idx:
                    out += self._tint(run, idx, lo, hi)
                    run, idx = "", i
                run += ch
            out += self._tint(run, idx, lo, hi)
            self._emit(out)
            if draw:
                sys.stdout.flush()
                time.sleep(0.03)               # the draw

    _GLOW = ((120, 80, 30), (255, 225, 160))   # dark amber → bright gold

    def _gunslinger(self) -> None:
        self._glow_art("hickok.txt", *self._GLOW, live=True)

    def hand(self) -> None:
        """The signature reveal — the gunslinger rises, then lays down the hand,
        cards and captions centred on his own column."""
        self._emit()
        self._gunslinger()
        self.dead_mans_hand(center=self._art_center("hickok.txt"))


class _Working:
    """Background heartbeat for a blocking call (see Console.working).

    While it turns, the terminal stops echoing keystrokes and drops buffered
    input — so typing or pasting during a long blind walk can't corrupt the
    spinner line or leak a stray command into the next prompt."""

    def __init__(self, console, label, count_fn):
        self.c, self.label, self.count_fn = console, label, count_fn
        self._stop = None
        self._thread = None
        self._tty = None      # (fd, saved termios) while we hold the terminal quiet

    def __enter__(self):
        if not sys.stdout.isatty() or self.c.verbose >= 2:
            return self
        self._hush_input()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _hush_input(self) -> None:
        try:
            import termios
            fd = sys.stdin.fileno()
            saved = termios.tcgetattr(fd)
            quiet = termios.tcgetattr(fd)
            quiet[3] &= ~(termios.ECHO | termios.ICANON)   # no echo, no line buffering
            termios.tcsetattr(fd, termios.TCSANOW, quiet)
            termios.tcflush(fd, termios.TCIFLUSH)          # drop anything already typed
            self._tty = (fd, saved)
        except Exception:
            self._tty = None

    def _restore_input(self) -> None:
        if self._tty:
            try:
                import termios
                fd, saved = self._tty
                termios.tcflush(fd, termios.TCIFLUSH)       # discard whatever was typed during
                termios.tcsetattr(fd, termios.TCSANOW, saved)
            except Exception:
                pass
            self._tty = None

    def _run(self) -> None:
        i = 0
        while not self._stop.wait(0.1):
            n = self.count_fn() if self.count_fn else None
            label = f"{self.label} · {n} requests" if n is not None else self.label
            self.c.spinner(_HSPIN[i % len(_HSPIN)], label)
            i += 1

    def __exit__(self, *exc):
        if self._thread is not None:
            self._stop.set()
            self._thread.join(timeout=0.3)
            self.c.spin_clear()
        self._restore_input()
        return False
