from hickok.console import Console
from hickok.showdown import Showdown


def test_showdown_shell_plays_the_hand(capsys):
    c = Console(color=False, banner=True)        # banner on → the gunslinger rises
    Showdown(c).shell()
    out = capsys.readouterr().out
    assert "dead man's hand" in out              # the hand is laid down
    assert "showdown" in out                     # the call
    assert "you're holding the hand" in out


def test_showdown_shell_gates_the_art_on_the_banner(capsys):
    c = Console(color=False, banner=False)       # banner off → the call, no art
    Showdown(c).shell()
    out = capsys.readouterr().out
    assert "showdown" in out
    assert "dead man's hand" not in out
