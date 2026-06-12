from hickok import http


def test_random_agent_is_a_real_browser_ua():
    ua = http.random_agent()
    assert ua in http._AGENTS and "Mozilla/5.0" in ua


def test_request_headers_carry_ua_cookie_and_extras():
    h = http.Http(ua="scanner/1", cookie="sid=abc123", headers={"Referer": "http://ref/"})
    hd = h._request_headers()
    assert hd["User-Agent"] == "scanner/1"
    assert hd["Cookie"] == "sid=abc123"
    assert hd["Referer"] == "http://ref/"


def test_default_user_agent_when_unset():
    assert http.Http()._request_headers()["User-Agent"] == http._DEFAULT_UA


def test_tor_defaults_to_remote_dns_socks_port():
    # without PySocks installed this raises TorError; otherwise it wires socks5h.
    try:
        h = http.Http(tor=True)
        assert h.proxy == "socks5h://127.0.0.1:9050"   # socks5h => DNS via Tor, no leak
    except http.TorError:
        pass
