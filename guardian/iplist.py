"""Fast membership tests for large sets of IPs / CIDR ranges (VPN servers,
DoH resolvers, exemptions). Ranges are merged and binary-searched."""
from __future__ import annotations

import bisect
import ipaddress


class IPSet:
    def __init__(self, items=None):
        self._pending: list = []
        self._starts = {4: [], 6: []}
        self._ends = {4: [], 6: []}
        self._networks: list = []
        if items:
            for it in items:
                self.add(it)
            self.finalize()

    def add(self, item: str) -> bool:
        item = (item or "").strip()
        if not item or item.startswith("#"):
            return False
        item = item.split()[0]
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            return False
        self._pending.append(net)
        return True

    def finalize(self) -> "IPSet":
        nets = self._networks + self._pending
        self._pending = []
        merged = {4: [], 6: []}
        for v in (4, 6):
            fam = [n for n in nets if n.version == v]
            merged[v] = list(ipaddress.collapse_addresses(fam))
        self._networks = merged[4] + merged[6]
        for v in (4, 6):
            self._starts[v] = [int(n.network_address) for n in merged[v]]
            self._ends[v] = [int(n.broadcast_address) for n in merged[v]]
        return self

    def __contains__(self, ip) -> bool:
        try:
            addr = ip if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) \
                else ipaddress.ip_address(ip)
        except ValueError:
            return False
        v = addr.version
        if v == 6 and addr.ipv4_mapped:
            addr, v = addr.ipv4_mapped, 4
        n = int(addr)
        i = bisect.bisect_right(self._starts[v], n) - 1
        return i >= 0 and n <= self._ends[v][i]

    def __len__(self):
        return len(self._networks)

    def cidrs(self, version: int) -> list[str]:
        return [str(n) for n in self._networks if n.version == version]


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast
