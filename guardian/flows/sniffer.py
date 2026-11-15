"""Monitor-mode backend (Windows/macOS/Linux dev machine): passively capture
packets with scapy, count bytes per connection, and read site names from TLS
handshakes / HTTP requests. Needs Npcap on Windows and admin rights.

It only sees traffic to/from this machine (or a mirrored switch port), so on
your PC it shows your own browsing - ideal for testing the dashboard."""
from __future__ import annotations

import ipaddress
import socket
import threading
import time

from ..protocols import NEED_MORE, TCP_FIN, TCP_RST, parse_client_hello, parse_http_request, parse_ip
from . import FlowSample


class _Entry:
    __slots__ = ("up", "down", "pu", "pd", "last", "ended", "buf", "labelled")

    def __init__(self):
        self.up = self.down = self.pu = self.pd = 0
        self.last = time.time()
        self.ended = False
        self.buf = b""
        self.labelled = False


class SnifferBackend:
    name = "sniffer"

    def __init__(self, cfg: dict, labels):
        self.iface = (cfg.get("flows") or {}).get("sniffer_interface")
        self.labels = labels
        self._flows: dict[tuple, _Entry] = {}
        self._lock = threading.Lock()
        self._local = self._local_ips()
        self.error = None

    @staticmethod
    def available() -> bool:
        try:
            import scapy.all  # noqa: F401
            return True
        except Exception:
            return False

    @staticmethod
    def _local_ips() -> set:
        ips = set()
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None):
                ips.add(info[4][0])
        except Exception:
            pass
        return ips

    def _is_local(self, ip: str) -> bool:
        if ip in self._local:
            return True
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return a.is_private or a.is_loopback or a.is_link_local

    def start(self):
        def run():
            try:
                from scapy.all import IP, IPv6, sniff
                self._IP, self._IPv6 = IP, IPv6
                sniff(iface=self.iface, prn=self._on_packet, store=False, filter="ip or ip6")
            except Exception as e:
                self.error = str(e)
                print(f"[flows] packet capture unavailable: {e} "
                      f"(on Windows install Npcap and run as administrator)")
        threading.Thread(target=run, name="sniffer", daemon=True).start()

    def _on_packet(self, sp):
        layer = sp.getlayer(self._IP) or sp.getlayer(self._IPv6)
        if layer is None:
            return
        p = parse_ip(bytes(layer))
        if p is None or not (p.is_tcp or p.is_udp):
            return
        src_local, dst_local = self._is_local(p.src), self._is_local(p.dst)
        if src_local and not dst_local:
            up, key = True, ("tcp" if p.is_tcp else "udp", p.src, p.sport, p.dst, p.dport)
        elif dst_local and not src_local:
            up, key = False, ("tcp" if p.is_tcp else "udp", p.dst, p.dport, p.src, p.sport)
        else:
            return
        with self._lock:
            e = self._flows.get(key)
            if e is None:
                e = self._flows[key] = _Entry()
            e.last = time.time()
            if up:
                e.up += p.length
                e.pu += 1
            else:
                e.down += p.length
                e.pd += 1
            if p.is_tcp and p.flags & (TCP_FIN | TCP_RST):
                e.ended = True
            need_label = up and p.is_tcp and key[4] in (80, 443) and not e.labelled \
                and p.payload and len(e.buf) < 16384
            if need_label:
                e.buf += p.payload
                buf = e.buf
        if need_label:
            res = parse_client_hello(buf) if key[4] == 443 else parse_http_request(buf)
            if res is not NEED_MORE:
                e.labelled = True
                e.buf = b""
                if res is not None:
                    if key[4] == 443:
                        self.labels.set(key, domain=res.sni, domain_src="sni", ja4=res.ja4)
                    else:
                        self.labels.set(key, domain=res.host, domain_src="http")

    def snapshot(self) -> list[FlowSample]:
        now = time.time()
        out = []
        with self._lock:
            for key, e in list(self._flows.items()):
                if now - e.last > 120 or (e.ended and now - e.last > 5):
                    del self._flows[key]
                    continue
                out.append(FlowSample("|".join(map(str, key)), key, e.up, e.down, e.pu, e.pd))
        return out
