"""Console output: banner, colour themes, card art and the dead man's hand.

Dependency-free (ANSI / truecolor). Colour auto-enables on a TTY and honours
NO_COLOR; force it with HICKOK_COLOR=1. Pick a theme with --theme or HICKOK_THEME
(ember | steel | bone | crimson).
"""

from __future__ import annotations

import os
import sys

from hickok import __version__

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
    def __init__(self, theme=None, color=None, banner=True):
        name = theme or os.environ.get("HICKOK_THEME") or DEFAULT_THEME
        self.theme = THEMES.get(name, THEMES[DEFAULT_THEME])
        self.color = _supports_color(color)
        self.show_banner = banner

    def _emit(self, text: str = "") -> None:
        print(text, flush=True)

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def _accent(self, text: str) -> str:
        return self._c(_fg(self.theme["accent"]), text)

    # --------------------------------------------------------------- cards
    def _cards(self, specs, indent: str = "    ") -> None:
        """Lay a row of playing cards (rank, suit) face-up, in bright bone."""
        top = "   ".join("┌─────┐" for _ in specs)
        mid = "   ".join(f"│ {r}{s}  │" for r, s in specs)
        bot = "   ".join("└─────┘" for _ in specs)
        white = _fg(_BONE)
        for line in (top, mid, bot):
            self._emit(indent + self._c(BOLD + white, line))

    # -------------------------------------------------------------- banner
    def banner(self) -> None:
        if not self.show_banner:
            return
        self._emit()
        self._cards([("8", "♠"), ("8", "♣")])
        self._emit()
        wordmark = "   ".join("HICKOK")
        c0, c1 = self.theme["grad"]
        if self.color:
            out = ""
            for i, ch in enumerate(wordmark):
                out += _fg(_lerp(c0, c1, i / max(1, len(wordmark) - 1))) + ch
            self._emit("    " + BOLD + out + RESET)
        else:
            self._emit("    " + wordmark)
        self._emit("    " + self._accent("» ")
                   + self._c(DIM, "reverse-shell handler & post-exploitation")
                   + "   " + self._c(DIM, f"v{__version__}"))
        self._emit("    " + self._c(DIM, "gusta-ve · github.com/gusta-ve/hickok · authorized use only"))
        self._emit("    " + self._c(DIM, "J.B. Hickok · Deadwood, 1876"))
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
        self._cards([("A", "♠"), ("A", "♣"), ("8", "♠"), ("8", "♣")])
        self._emit()
        self._emit("      " + self._c(BOLD, "aces and eights — the dead man's hand."))
        if dealt_by_wraith:
            self._emit("      " + self._c(DIM, "the wraith dealt the aces; Hickok brought the eights."))
        self._emit("      " + self._c(DIM, "J.B. Hickok, Deadwood 1876.  the house always collects."))
        self._emit()
