from hickok.cli import _with_default_command
from hickok.console import Console


def test_banner_shows_eights_and_wild_bill(capsys):
    Console(color=False, banner=True).banner()
    out = capsys.readouterr().out
    assert "8♠" in out and "8♣" in out          # Hickok holds the eights
    assert "HICKOK" in out.replace(" ", "")      # the wordmark (spaced)
    assert "Hickok" in out and "1876" in out     # the memorial


def test_eights_reveal(capsys):
    Console(color=False, banner=False).eights()
    out = capsys.readouterr().out
    assert "8♠" in out and "8♣" in out
    assert "eights" in out


def test_dead_mans_hand_completes_and_credits_wraith(capsys):
    Console(color=False, banner=False).dead_mans_hand(dealt_by_wraith=True)
    out = capsys.readouterr().out
    assert "A♠" in out and "A♣" in out and "8♠" in out and "8♣" in out
    assert "dead man's hand" in out
    assert "wraith" in out                       # the catch is credited


def test_listen_is_the_default_command():
    assert _with_default_command(["-l", "9001"]) == ["listen", "-l", "9001"]
    assert _with_default_command([]) == []
    assert _with_default_command(["hand", "x.json"]) == ["hand", "x.json"]
    assert _with_default_command(["--no-color", "-l", "9001"]) == ["--no-color", "listen", "-l", "9001"]
