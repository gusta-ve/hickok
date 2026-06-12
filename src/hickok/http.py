"""HTTP sending for hickok — User-Agent, proxy/Tor, headers, cookie, throttle.

OPSEC-minded by design:
  * Tor / SOCKS uses **remote DNS** (socks5h / rdns) so the target hostname is
    resolved by Tor, never by your local resolver — no DNS leak.
  * `--tor` is **verified** before any attack traffic and **fails closed**: if
    the exit can't be confirmed as Tor, hickok aborts instead of sending in the
    clear and deanonymising you.

Dependency-free for HTTP proxies (stdlib urllib). SOCKS/Tor needs PySocks
(optional: `pip install hickok[tor]`); or just run `torsocks hickok ...`.
"""

from __future__ import annotations

import http.client
import json
import random
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

# A few current, common browser User-Agents. Written here from public values —
# not lifted from any (GPL) tool.
_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]
_DEFAULT_UA = "hickok/0.4"


def random_agent() -> str:
    return random.choice(_AGENTS)


class TorError(RuntimeError):
    pass


# --- minimal SOCKS5 (RFC 1928), pure stdlib — so --tor needs no PySocks. ----
def _recvn(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("SOCKS proxy closed the connection")
        buf += chunk
    return buf


def _socks5_connect(proxy_host, proxy_port, dst_host, dst_port, timeout):
    """Open a TCP tunnel to dst via a SOCKS5 proxy. The destination is sent as a
    *domain name* (ATYP 0x03), so the proxy (Tor) resolves DNS — never leaks."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00")                       # VER, 1 method, NO-AUTH
        if _recvn(s, 2) != b"\x05\x00":
            raise OSError("SOCKS5 proxy refused no-auth")
        host = dst_host.encode("idna") if any(ord(ch) > 127 for ch in dst_host) else dst_host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", dst_port))
        rep = _recvn(s, 4)                                # VER, REP, RSV, ATYP
        if rep[1] != 0x00:
            raise OSError(f"SOCKS5 connect failed (code {rep[1]})")
        atyp = rep[3]                                     # drain the bound address
        if atyp == 0x01:
            _recvn(s, 4)
        elif atyp == 0x04:
            _recvn(s, 16)
        elif atyp == 0x03:
            _recvn(s, _recvn(s, 1)[0])
        _recvn(s, 2)                                      # bound port
        return s
    except Exception:
        s.close()
        raise


def _socks_handlers(proxy_host, proxy_port, ctx):
    """urllib handlers that tunnel HTTP(S) through a SOCKS5 proxy."""
    class _HTTPSConn(http.client.HTTPSConnection):
        def connect(self):
            raw = _socks5_connect(proxy_host, proxy_port, self.host, self.port, self.timeout)
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)

    class _HTTPConn(http.client.HTTPConnection):
        def connect(self):
            self.sock = _socks5_connect(proxy_host, proxy_port, self.host, self.port, self.timeout)

    class _HTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_HTTPSConn, req)

    class _HTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(_HTTPConn, req)

    return [_HTTPHandler(), _HTTPSHandler()]


def _tor_proxy() -> str:
    """Find a running Tor SOCKS port (daemon 9050, Tor Browser 9150)."""
    for port in (9050, 9150):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=3).close()
            return f"socks5://127.0.0.1:{port}"
        except OSError:
            continue
    raise TorError("can't reach the Tor SOCKS proxy on 127.0.0.1:9050 or :9150 — "
                   "is Tor running? (`sudo systemctl start tor`)")


class Http:
    def __init__(self, ua=None, headers=None, cookie=None, proxy=None, tor=False,
                 delay=0.0, timeout=15.0, verify=False):
        self.ua = ua or _DEFAULT_UA
        self.headers = dict(headers or {})
        self.cookie = cookie
        self.delay = max(0.0, float(delay or 0))
        self.timeout = float(timeout)
        self.tor = tor
        self.count = 0
        self._last = 0.0
        if tor and not proxy:
            proxy = _tor_proxy()             # auto-detect Tor's SOCKS port (or raise)
        self.proxy = proxy
        self._opener = self._build_opener(proxy, verify)

    # ------------------------------------------------------------- wiring
    def _build_opener(self, proxy, verify):
        ctx = ssl.create_default_context()
        if not verify:                       # offensive targets often have bad certs
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        if proxy and proxy.startswith("socks"):
            u = urlsplit(proxy)              # our SOCKS client always resolves DNS
            handlers = _socks_handlers(u.hostname or "127.0.0.1", u.port or 9050, ctx)  # remotely
        elif proxy:
            handlers = [urllib.request.HTTPSHandler(context=ctx),
                        urllib.request.ProxyHandler({"http": proxy, "https": proxy})]
        else:
            handlers = [urllib.request.HTTPSHandler(context=ctx)]
        return urllib.request.build_opener(*handlers)

    # --------------------------------------------------------- safety gate
    def check_tor(self) -> bool:
        """Confirm traffic actually exits through Tor (fail closed if not)."""
        try:
            body = self.get("https://check.torproject.org/api/ip")
            return bool(json.loads(body).get("IsTor"))
        except Exception:
            return False

    # ------------------------------------------------------------- request
    def get(self, url: str) -> str:
        if self.delay:
            wait = self._last + self.delay - time.monotonic()
            if wait > 0:
                time.sleep(wait)
        req = urllib.request.Request(url, headers=self._request_headers())
        self.count += 1
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                body = r.read(200_000).decode("utf-8", "ignore")
        except urllib.error.HTTPError as exc:
            body = exc.read(200_000).decode("utf-8", "ignore")
        except Exception:
            body = ""
        self._last = time.monotonic()
        return body

    def _request_headers(self) -> dict:
        h = {"User-Agent": self.ua}
        h.update(self.headers)
        if self.cookie:
            h["Cookie"] = self.cookie
        return h
