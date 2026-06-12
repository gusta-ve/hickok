import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

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


def test_tor_auto_detect_or_fails_closed():
    # Http(tor=True) auto-detects the Tor port; with no Tor running it must raise
    # (fail closed), never silently fall back to a direct connection.
    try:
        h = http.Http(tor=True)
        assert h.proxy.startswith("socks5://127.0.0.1:")
    except http.TorError:
        pass


def _tiny_http_server():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"hello-through-socks"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _tiny_socks5_server():
    """A minimal SOCKS5 proxy that supports no-auth + domain/IPv4 CONNECT."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)

    def pipe(a, b):
        try:
            while True:
                data = a.recv(4096)
                if not data:
                    break
                b.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass

    def serve():
        while True:
            try:
                cli, _ = srv.accept()
            except OSError:
                break
            try:
                cli.recv(2)                              # ver, nmethods
                cli.recv(8)                              # method bytes (drain)
                cli.sendall(b"\x05\x00")                 # no-auth
                hdr = cli.recv(4)                        # ver, cmd, rsv, atyp
                atyp = hdr[3]
                if atyp == 0x03:
                    host = cli.recv(cli.recv(1)[0]).decode()
                else:
                    host = socket.inet_ntoa(cli.recv(4))
                port = struct.unpack(">H", cli.recv(2))[0]
                up = socket.create_connection((host, port))
                cli.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                threading.Thread(target=pipe, args=(cli, up), daemon=True).start()
                threading.Thread(target=pipe, args=(up, cli), daemon=True).start()
            except Exception:
                cli.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


def test_socks5_tunnel_reaches_the_target():
    web = _tiny_http_server()
    socks_port = _tiny_socks5_server()
    net = http.Http(proxy=f"socks5://127.0.0.1:{socks_port}", timeout=5)
    body = net.get(f"http://127.0.0.1:{web.server_address[1]}/")
    web.shutdown()
    assert "hello-through-socks" in body
