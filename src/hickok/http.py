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

import json
import random
import ssl
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
            proxy = "socks5h://127.0.0.1:9050"   # Tor's default SOCKS port
        self.proxy = proxy
        self._opener = self._build_opener(proxy, verify)

    # ------------------------------------------------------------- wiring
    def _build_opener(self, proxy, verify):
        ctx = ssl.create_default_context()
        if not verify:                       # offensive targets often have bad certs
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers = [urllib.request.HTTPSHandler(context=ctx)]

        if proxy and proxy.startswith("socks"):
            self._install_socks(proxy)       # process-wide; rdns = no DNS leak
        elif proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        return urllib.request.build_opener(*handlers)

    @staticmethod
    def _install_socks(proxy):
        try:
            import socket
            import socks
        except ImportError:
            raise TorError(
                "SOCKS/Tor needs PySocks — `pip install hickok[tor]`, "
                "or route the whole process with `torsocks hickok ...`")
        u = urlsplit(proxy)
        # socks5h = resolve the hostname through the proxy (Tor), never locally.
        rdns = u.scheme in ("socks5h", "socks4a")
        kind = socks.SOCKS4 if u.scheme.startswith("socks4") else socks.SOCKS5
        socks.set_default_proxy(kind, u.hostname or "127.0.0.1", u.port or 9050, rdns=rdns)
        socket.socket = socks.socksocket

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
