from hickok.cli import _with_default_command
from hickok.console import Console


def test_banner_shows_wordmark_and_wild_bill(capsys):
    Console(color=False, banner=True).banner()
    out = capsys.readouterr().out
    assert "█" in out                            # the block wordmark
    assert "Hickok" in out and "1876" in out     # the memorial


def test_eights_reveal(capsys):
    Console(color=False, banner=False).eights()
    out = capsys.readouterr().out
    assert "8" in out and "♠" in out and "♣" in out   # the eights, both suits
    assert "eights" in out


def test_dead_mans_hand_completes_and_credits_wraith(capsys):
    Console(color=False, banner=False).dead_mans_hand(dealt_by_wraith=True)
    out = capsys.readouterr().out
    assert "A" in out and "8" in out and "♠" in out and "♣" in out  # aces & eights
    assert "dead man's hand" in out
    assert "wraith" in out                       # the catch is credited


def test_hand_reveal_draws_the_gunslinger(capsys):
    Console(color=False, banner=False).hand()
    out = capsys.readouterr().out
    assert "dead man's hand" in out
    assert out.count("\n") > 40                  # the gunslinger art + the cards


def test_listen_is_the_default_command():
    assert _with_default_command(["-l", "9001"]) == ["listen", "-l", "9001"]
    assert _with_default_command([]) == []
    assert _with_default_command(["call", "x.json"]) == ["call", "x.json"]
    assert _with_default_command(["--no-color", "-l", "9001"]) == ["--no-color", "listen", "-l", "9001"]
