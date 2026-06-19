import threading

from hickok.cli import _with_default_command
from hickok.console import Console


def test_banner_shows_the_gunslinger(capsys):
    Console(color=False, banner=True).banner()
    out = capsys.readouterr().out
    assert "hickok" in out                       # the name label (no figlet wordmark anymore)
    assert "Hickok" in out and "1876" in out     # the memorial
    assert out.count("\n") > 15                  # the gunslinger art, not just text


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


def test_console_tees_output_to_a_log_without_colour(tmp_path):
    """log_to mirrors every emitted line into a run log with the colour stripped, so
    the log is plain text while the terminal stays coloured."""
    p = tmp_path / "log.txt"
    c = Console(color=True, banner=False)               # colour on → there's ANSI to strip
    c.log_to(p)
    c.good("found admin")
    c.info("done")
    text = p.read_text()
    assert "found admin" in text and "done" in text
    assert "\x1b[" not in text                          # colour codes stripped in the log
    assert "[+]" in text and "[*]" in text              # status markers survive


def test_emit_is_thread_safe(capsys):
    """The working-heartbeat redraws from a background thread while the main thread
    emits output; concurrent writers must each land a whole line, never interleave."""
    c = Console(color=False, banner=False)
    lines = [f"line-{i:03d}-end" for i in range(200)]
    threads = [threading.Thread(target=c._emit, args=(s,)) for s in lines]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    emitted = [ln for ln in capsys.readouterr().out.split("\n") if ln]
    assert sorted(emitted) == sorted(lines)      # every line intact, none merged


def test_listen_is_the_default_command():
    assert _with_default_command(["-l", "9001"]) == ["listen", "-l", "9001"]
    assert _with_default_command([]) == []
    assert _with_default_command(["call", "x.json"]) == ["call", "x.json"]
    assert _with_default_command(["--no-color", "-l", "9001"]) == ["--no-color", "listen", "-l", "9001"]


def test_default_command_skips_global_options():
    """A global option before the (implicit) command is skipped over, in both the
    `--opt value` and `--opt=value` forms, so `listen` lands in the right place."""
    assert _with_default_command(["--theme", "steel", "-l", "9001"]) == \
        ["--theme", "steel", "listen", "-l", "9001"]
    assert _with_default_command(["--theme=steel", "-l", "9001"]) == \
        ["--theme=steel", "listen", "-l", "9001"]
    # a global option before an explicit command leaves the command in place
    assert _with_default_command(["--no-banner", "sql", "-u", "x"]) == \
        ["--no-banner", "sql", "-u", "x"]
    # --help / --version short-circuit, untouched
    assert _with_default_command(["--version"]) == ["--version"]
