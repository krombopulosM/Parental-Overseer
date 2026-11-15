import os
import socket
import ssl
import struct
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from guardian.alerts import AlertSink  # noqa: E402
from guardian.config import load_config  # noqa: E402
from guardian.dnscache import DnsCache  # noqa: E402
from guardian.identity import Identity  # noqa: E402
from guardian.inspector import FlowLabels, Inspector  # noqa: E402
from guardian.lists import ListManager  # noqa: E402
from guardian.policy import Policy  # noqa: E402


# ------------------------------------------------------------------ packet builders
def client_hello(sni=None, alpn=("h2", "http/1.1")) -> bytes:
    """A real ClientHello as produced by OpenSSL."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(list(alpn))
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=sni)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def split_records(hello: bytes, at: int) -> bytes:
    """Re-frame one ClientHello record as two TLS records (a DPI-evasion trick)."""
    body = hello[5:]
    a, b = body[:at], body[at:]
    hdr = hello[:3]
    return hdr + struct.pack("!H", len(a)) + a + hdr + struct.pack("!H", len(b)) + b


def ipv4(src, dst, proto, l4: bytes) -> bytes:
    total = 20 + len(l4)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + l4


def tcp(src, dst, sport, dport, seq=1000, flags=0x18, payload=b"") -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0)
    return ipv4(src, dst, 6, hdr + payload)


def udp(src, dst, sport, dport, payload=b"") -> bytes:
    return ipv4(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)


SYN, ACK, PSH_ACK = 0x02, 0x10, 0x18


class Conn:
    """Drives one TCP connection through the inspector like NFQUEUE would."""

    def __init__(self, insp, src, dst, dport, sport=40000, mac=None):
        self.insp, self.src, self.dst, self.dport, self.sport, self.mac = insp, src, dst, dport, sport, mac
        self.seq = 5000

    def syn(self):
        return self.insp.inspect(tcp(self.src, self.dst, self.sport, self.dport, self.seq, SYN), self.mac)

    def ack(self):
        return self.insp.inspect(tcp(self.src, self.dst, self.sport, self.dport, self.seq + 1, ACK), self.mac)

    def send(self, data: bytes, offset=None):
        off = offset if offset is not None else 0
        return self.insp.inspect(tcp(self.src, self.dst, self.sport, self.dport,
                                     self.seq + 1 + off, PSH_ACK, data), self.mac)

    def open_and_send(self, data: bytes):
        v = self.syn()
        if v.action != "accept":
            return v
        self.ack()
        return self.send(data)


# ------------------------------------------------------------------ fixtures
@pytest.fixture
def env(tmp_path):
    """A complete policy stack with small local lists and no database."""
    (tmp_path / "adult.txt").write_text("pornhub.com\n")
    (tmp_path / "bypass.txt").write_text("protonvpn.com\ncloudflare-dns.com\n")
    (tmp_path / "vpn-ips.txt").write_text("185.159.157.0/24\n")
    (tmp_path / "doh-ips.txt").write_text("9.9.9.9\n")
    (tmp_path / "exempt.txt").write_text("17.0.0.0/8\n")
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg["lists_cache_dir"] = str(tmp_path / "cache")
    cfg["categories"] = {
        "adult": {"files": [str(tmp_path / "adult.txt")]},
        "bypass": {"files": [str(tmp_path / "bypass.txt")]},
    }
    cfg["ip_lists"] = {"vpn": {"files": [str(tmp_path / "vpn-ips.txt")]},
                       "doh": {"files": [str(tmp_path / "doh-ips.txt")]}}
    cfg["enforcement"]["consistency_exempt"] = str(tmp_path / "exempt.txt")
    for g in cfg["groups"].values():
        g["categories"] = [c for c in g["categories"] if c in ("adult", "bypass")]
    lists = ListManager(cfg)
    lists.load()
    alerts = AlertSink()
    policy = Policy(cfg, None, lists, Identity(cfg), alerts)
    dnscache = DnsCache(grace=3600)
    insp = Inspector(cfg, policy, lists, dnscache, alerts, FlowLabels())

    class E:
        pass
    e = E()
    e.cfg, e.lists, e.alerts, e.policy, e.dnscache, e.insp = cfg, lists, alerts, policy, dnscache, insp
    e.kinds = lambda: [a["kind"] for a in alerts.memory]
    return e
