"""Linux gateway backend: the kernel already counts bytes and packets for every
connection it routes (conntrack accounting). Polling that table costs almost
nothing, even at full line rate on a Raspberry Pi."""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
import sys

from . import FlowSample

_PROTOS = {"tcp", "udp", "icmp", "icmpv6", "sctp", "udplite", "dccp", "gre"}


def parse_line(line: str) -> dict | None:
    toks = line.split()
    if not toks:
        return None
    proto = next((t for t in toks[:4] if t in _PROTOS), None)
    if proto is None:
        return None
    orig, reply, extra = {}, {}, {}
    for t in toks:
        if "=" not in t:
            continue
        k, v = t.split("=", 1)
        if k in ("src", "dst", "sport", "dport", "packets", "bytes"):
            (reply if k in orig else orig)[k] = v
        else:
            extra[k] = v
    if "src" not in orig or "dst" not in orig:
        return None
    return {"proto": proto, "orig": orig, "reply": reply, "id": extra.get("id"),
            "mark": extra.get("mark")}


class ConntrackBackend:
    name = "conntrack"

    def __init__(self, cfg: dict):
        gw = cfg["gateway"]
        self.lan_nets = [ipaddress.ip_network(n, strict=False) for n in gw.get("lan_subnets") or []]
        self.lan_ip = gw.get("lan_ip")
        self.families = ["ipv4"] + (["ipv6"] if gw.get("ipv6") else [])

    @staticmethod
    def available() -> bool:
        return sys.platform.startswith("linux") and shutil.which("conntrack") is not None

    def start(self):
        pass

    def _is_lan(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.lan_nets)

    def snapshot(self) -> list[FlowSample]:
        out = []
        for fam in self.families:
            try:
                text = subprocess.run(["conntrack", "-L", "-o", "id", "-f", fam],
                                      capture_output=True, text=True, timeout=15).stdout
            except Exception:
                continue
            for line in text.splitlines():
                e = parse_line(line)
                if e is None or e["proto"] not in ("tcp", "udp"):
                    continue
                o, r = e["orig"], e["reply"]
                if not self._is_lan(o["src"]) or o["src"] == self.lan_ip:
                    continue                    # only devices, never the Pi's own traffic
                if o["dst"] == self.lan_ip or r.get("src") == self.lan_ip or self._is_lan(o["dst"]):
                    continue                    # to the Pi itself (incl. redirected DNS) or LAN-internal
                tup = (e["proto"], o["src"], int(o.get("sport", 0)), o["dst"], int(o.get("dport", 0)))
                key = f"ct{e['id']}" if e.get("id") else "|".join(map(str, tup))
                out.append(FlowSample(key, tup, int(o.get("bytes", 0)), int(r.get("bytes", 0)),
                                      int(o.get("packets", 0)), int(r.get("packets", 0))))
        return out
