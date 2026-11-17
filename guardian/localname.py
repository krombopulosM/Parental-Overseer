"""A dashboard address people can remember: http://family.local

Nobody should have to find the Pi's IP address. The dashboard answers to a
name, "family" by default (changeable in the setup wizard), under several
endings so that every kind of device finds it:

  family.local      the one to tell people. Apple devices, Windows, Linux and
                    most Android phones look up ".local" names by asking the
                    network (mDNS); the Pi announces it with Avahi. The
                    gateway's DNS answers it too.
  family.home.arpa  the official ending for home networks (RFC 8375). Every
                    device uses the gateway's DNS, so this always works, and
                    browsers recognise it as an address rather than a search.
  family.home, family.lan
                    convenience aliases, answered by the gateway's DNS.

On the Pi the dashboard also answers on port 80, so no ":8080" is needed.
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import sys
import threading

SUFFIXES = ("local", "home.arpa", "home", "lan")
DEFAULT_NAME = "family"
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")


def valid_label(name: str) -> bool:
    return bool(_LABEL.match(name or ""))


def base_name(cfg: dict) -> str:
    n = str((cfg.get("web") or {}).get("local_name") or DEFAULT_NAME).lower()
    return n if valid_label(n) else DEFAULT_NAME


def names(cfg: dict) -> list[str]:
    b = base_name(cfg)
    return [f"{b}.{s}" for s in SUFFIXES]


def server_ip(cfg: dict, client_ip: str | None = None) -> str:
    """The address the dashboard name should point to, as seen by this client."""
    if cfg.get("mode") == "gateway" and sys.platform.startswith("linux"):
        return (cfg.get("gateway") or {}).get("lan_ip") or "127.0.0.1"
    if client_ip in (None, "", "127.0.0.1", "::1"):
        return "127.0.0.1" if client_ip else _primary_ip()
    try:                                     # the local address on the route to this client
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((client_ip, 9))
            return s.getsockname()[0]
    except OSError:
        return _primary_ip()


def _primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))      # no packet is sent; just picks the outgoing interface
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def port_suffix(cfg: dict) -> str:
    if cfg.get("mode") == "gateway" and sys.platform.startswith("linux"):
        return ""                            # port 80 is redirected to the dashboard
    port = int((cfg.get("web") or {}).get("port", 8080))
    return "" if port == 80 else f":{port}"


def addresses(cfg: dict, client_ip: str | None = None) -> dict:
    b, p = base_name(cfg), port_suffix(cfg)
    ip = server_ip(cfg, client_ip)
    return {
        "name": b,
        "primary": f"http://{b}.local{p}",
        "fallback": f"http://{b}.home.arpa{p}",
        "ip": f"http://{ip}{p}",
        "names": names(cfg),
        # A QR code is scanned by a phone; .home.arpa doesn't depend on mDNS support.
        "qr_url": f"http://{b}.home.arpa{p}",
        "reachable_from_others": cfg.get("mode") == "gateway" or
        (cfg.get("web") or {}).get("host") not in ("127.0.0.1", "localhost"),
    }


def qr_svg(text: str, scale: int = 6) -> str:
    """An SVG QR code (dark modules as one path) - no image libraries needed."""
    import qrcode
    q = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_M)
    q.add_data(text)
    q.make(fit=True)
    m = q.get_matrix()
    n = len(m)
    d = "".join(f"M{x},{y}h1v1h-1z" for y, row in enumerate(m) for x, v in enumerate(row) if v)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" width="{n * scale}" '
            f'height="{n * scale}" shape-rendering="crispEdges" role="img" aria-label="QR code for {text}">'
            f'<rect width="{n}" height="{n}" fill="#fff"/><path d="{d}" fill="#000"/></svg>')


class MdnsPublisher:
    """Announces <name>.local on the home network with Avahi (gateway mode).
    Without Avahi the .home.arpa name still works through the gateway's DNS."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.proc: subprocess.Popen | None = None
        self.published: tuple | None = None
        self.error: str | None = None
        self._lock = threading.Lock()

    @staticmethod
    def available() -> bool:
        return shutil.which("avahi-publish") is not None

    def sync(self):
        """(Re)publish if the name or address changed, or the publisher died."""
        want = (f"{base_name(self.cfg)}.local", server_ip(self.cfg))
        with self._lock:
            alive = self.proc is not None and self.proc.poll() is None
            if alive and self.published == want:
                return
            self._stop()
            if not self.available():
                self.error = "Avahi isn't installed (sudo apt install avahi-daemon avahi-utils)"
                return
            try:
                self.proc = subprocess.Popen(["avahi-publish", "-a", "-R", want[0], want[1]],
                                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                self.published, self.error = want, None
            except OSError as e:
                self.error = str(e)

    def _stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.proc is not None and self.proc.poll() is not None and self.proc.returncode not in (0, -15, None):
            err = (self.proc.stderr.read() or b"").decode(errors="replace").strip() if self.proc.stderr else ""
            self.error = err[-200:] or f"avahi-publish exited ({self.proc.returncode})"
        self.proc = None

    def stop(self):
        with self._lock:
            self._stop()

    def status(self) -> dict:
        running = self.proc is not None and self.proc.poll() is None
        if self.proc is not None and not running and not self.error:
            err = (self.proc.stderr.read() or b"").decode(errors="replace").strip() if self.proc.stderr else ""
            self.error = err[-200:] or "avahi-publish stopped"
        return {"running": running, "name": self.published[0] if self.published and running else None,
                "error": None if running else self.error}
