"""Showdown mode — hickok's payoff when a shell lands.

Off by default. Turn it on with `hickok showdown` (it sticks between runs); from
then on, the moment a reverse shell connects, hickok plays the catch out: the
gunslinger rises, lays down the dead man's hand, and calls it. Plain `call` and a
plain listener never touch this — the theatrics are the reward for landing a shell.
"""

from __future__ import annotations

from hickok.console import BOLD


class Showdown:
    """The showdown mode. Hand it the console; it plays the catch out on a shell."""

    def __init__(self, console):
        self.c = console

    def shell(self) -> None:
        """A reverse shell just landed — the hand is yours. Play it out."""
        if self.c.show_banner:
            self.c.hand()                 # the gunslinger rises + the dead man's hand
        self.c._emit()
        self.c.rule("showdown")
        self.c._emit("  " + self.c._c(BOLD, "the house folds — you're holding the hand now."))
        self.c._emit()
