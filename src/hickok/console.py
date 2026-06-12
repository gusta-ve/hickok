"""Console output: banner, colour themes, card art and the dead man's hand.

Dependency-free (ANSI / truecolor). Colour auto-enables on a TTY and honours
NO_COLOR; force it with HICKOK_COLOR=1. Pick a theme with --theme or HICKOK_THEME
(ember | steel | bone | crimson).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from hickok import __version__

_ART_DIR = Path(__file__).resolve().parent / "art"
_RAMP = " .:-=+*#%@"

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

WORDMARK = [
    "██╗  ██╗██╗ ██████╗██╗  ██╗ ██████╗ ██╗  ██╗",
    "██║  ██║██║██╔════╝██║ ██╔╝██╔═══██╗██║ ██╔╝",
    "███████║██║██║     █████╔╝ ██║   ██║█████╔╝",
    "██╔══██║██║██║     ██╔═██╗ ██║   ██║██╔═██╗",
    "██║  ██║██║╚██████╗██║  ██╗╚██████╔╝██║  ██╗",
    "╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝",
]

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

    def trace(self, msg, level: int = 1) -> None:
        """Verbose-only line (e.g. -v shows each SQLi payload). Silent without -v."""
        if self.verbose >= level:
            self._emit(self._c(DIM, "      · ") + str(msg))

    def _emit(self, text: str = "") -> None:
        if self._spinning:           # wipe the spinner line before real output lands
            sys.stdout.write("\r\033[K")
            self._spinning = False
        print(text, flush=True)

    def spinner(self, frame: str, label: str) -> None:
        """Draw one frame of a spinner — a single rewritten line, TTY only,
        auto-cleared by _emit before any real output. No newline."""
        if not sys.stdout.isatty():
            return
        sys.stdout.write("\r\033[K" + self._accent(frame) + " " + self._c(DIM, label))
        sys.stdout.flush()
        self._spinning = True

    def spin_clear(self) -> None:
        if self._spinning:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()
            self._spinning = False

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
        c0, c1 = self.theme["grad"]
        self._emit()
        for i, line in enumerate(WORDMARK):
            shade = _lerp(c0, c1, i / (len(WORDMARK) - 1))
            self._emit("  " + ((BOLD + _fg(shade) + line + RESET) if self.color else line))
        self._emit()
        self._emit("  " + self._accent("» ")
                   + self._c(DIM, "reverse-shell handler & post-exploitation")
                   + "   " + self._c(DIM, f"v{__version__}"))
        self._emit("  " + self._c(DIM, "gusta-ve · github.com/gusta-ve/hickok · authorized use only"))
        self._emit("  " + self._c(DIM, "J.B. Hickok · Deadwood, 1876"))
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

    def dead_mans_hand(self, dealt_by_wraith: bool = False) -> None:
        """The full hand laid down — aces and eights. When the aces came from a
        wraith findings file, the catch is acknowledged."""
        self._emit()
        self._cards([("A", "♠"), ("A", "♣"), ("8", "♠"), ("8", "♣"), None])
        self._emit()
        self._emit("      " + self._c(BOLD, "aces and eights — the dead man's hand."))
        self._emit("      " + self._c(DIM, "the fifth card stayed face down — nobody knows what Bill held."))
        if dealt_by_wraith:
            self._emit("      " + self._c(DIM, "the wraith dealt the aces; Hickok brought the eights."))
        self._emit("      " + self._c(DIM, "J.B. Hickok, Deadwood 1876.  the house always collects."))
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

    def _gunslinger(self) -> None:
        """Render the gunslinger line-art with a dark-amber → bright-gold glow.
        On a TTY the rows are drawn one at a time, so he rises into view; piped
        or non-interactive output gets it all at once."""
        try:
            art = (_ART_DIR / "hickok.txt").read_text(encoding="utf-8").rstrip("\n").split("\n")
        except OSError:
            return
        live = self.color and sys.stdout.isatty()
        lo, hi = (120, 80, 30), (255, 225, 160)      # dark amber → bright gold
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
            if live:
                sys.stdout.flush()
                time.sleep(0.03)               # the draw

    def hand(self) -> None:
        """The signature reveal — the gunslinger rises, then lays down the hand."""
        self._emit()
        self._gunslinger()
        self.dead_mans_hand()
