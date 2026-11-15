"""Memory of DNS answers: which IPs each device was told about, for which names.

This underpins the strongest anti-bypass check: a filtered device may only open
connections to addresses the gateway's own DNS gave it. Hard-coded VPN server
IPs, private DNS (DoH/DoT), hosts-file tricks and VPN apps' built-in resolvers
all produce connections to addresses we never handed out.
"""
from __future__ import annotations

import threading
import time


class DnsCache:
    def __init__(self, grace: float = 21600):
        self.grace = grace
        self._client: dict[tuple, list] = {}     # (client_ip, ip) -> [expiry, set(names)]
        self._global: dict[str, dict] = {}       # ip -> {name: expiry}
        self._lock = threading.Lock()

    def record(self, client_ip: str, names, answers):
        """answers: iterable of (ip, ttl). names: the query name + CNAME chain."""
        now = time.time()
        names = {n.lower().rstrip(".") for n in names if n}
        with self._lock:
            for ip, ttl in answers:
                exp = now + max(int(ttl or 0), 60) + self.grace
                ent = self._client.get((client_ip, ip))
                if ent is None:
                    self._client[(client_ip, ip)] = [exp, set(names)]
                else:
                    ent[0] = max(ent[0], exp)
                    ent[1].update(names)
                g = self._global.setdefault(ip, {})
                for n in names:
                    g[n] = max(g.get(n, 0), now + max(int(ttl or 0), 60) + self.grace)

    def resolved_by(self, client_ip: str, ip: str):
        """Names this client looked up that pointed at ip, or None if it never did."""
        with self._lock:
            ent = self._client.get((client_ip, ip))
            if ent is None or ent[0] < time.time():
                return None
            return set(ent[1])

    def names_for_ip(self, ip: str) -> set:
        now = time.time()
        with self._lock:
            g = self._global.get(ip) or {}
            return {n for n, exp in g.items() if exp >= now}

    def best_name(self, client_ip: str, ip: str) -> str | None:
        names = self.resolved_by(client_ip, ip) or self.names_for_ip(ip)
        if not names:
            return None
        # prefer the most specific (longest) name: the one the app actually asked for
        return sorted(names, key=lambda n: (-n.count("."), n))[0]

    def prune(self):
        now = time.time()
        with self._lock:
            self._client = {k: v for k, v in self._client.items() if v[0] >= now}
            for ip in list(self._global):
                g = {n: e for n, e in self._global[ip].items() if e >= now}
                if g:
                    self._global[ip] = g
                else:
                    del self._global[ip]

    def __len__(self):
        return len(self._client)
