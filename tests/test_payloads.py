from hickok import payloads


def test_generate_has_common_shells_with_lhost_lport():
    p = payloads.generate("10.10.14.7", 9001)
    assert {"bash", "python3", "nc-e", "php", "perl", "powershell"} <= set(p)
    assert "10.10.14.7" in p["bash"] and "9001" in p["bash"]
    assert "/dev/tcp/10.10.14.7/9001" in p["bash"]


def test_guess_lhost_returns_an_address():
    host = payloads.guess_lhost()
    assert isinstance(host, str) and host.count(".") == 3
