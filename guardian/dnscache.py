"""Memory of DNS answers: which IPs each device was told about, for which names.

This underpins the strongest anti-bypass check: a filtered device may only open
connections to addresses the gateway's own DNS gave it. Hard-coded VPN server
IPs, private DNS (DoH/DoT), hosts-file tricks and VPN apps' built-in resolvers
all produce connections to addresses we never handed out.
"""
from __future__ import annotations

import threading
import time


_UPSERT = ("INSERT INTO dns_answers (client_ip, ip, name, expires) VALUES (?,?,?,?) "
           "ON CONFLICT(client_ip, ip, name) DO UPDATE SET expires=MAX(expires, excluded.expires)")


class DnsCache:
    """Kept in memory for speed and written through to the database, so a
    restart or an update doesn't forget what devices were told - their own DNS
    caches still hold those answers."""

    def __init__(self, grace: float = 21600, db=None):
        self.grace = grace
        self.db = db
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
                if self.db is not None:
                    for n in names:
                        self.db.enqueue(_UPSERT, (client_ip, ip, n, exp))

    def _put(self, client_ip, ip, name, exp):
        ent = self._client.get((client_ip, ip))
        if ent is None:
            self._client[(client_ip, ip)] = [exp, {name}]
        else:
            ent[0] = max(ent[0], exp)
            ent[1].add(name)
        g = self._global.setdefault(ip, {})
        g[name] = max(g.get(name, 0), exp)

    def load(self) -> int:
        """Reload unexpired answers from the database (at start-up)."""
        if self.db is None:
            return 0
        rows = self.db.query("SELECT client_ip, ip, name, expires FROM dns_answers WHERE expires>=?",
                             (time.time(),))
        with self._lock:
            for r in rows:
                self._put(r["client_ip"], r["ip"], r["name"], r["expires"])
        return len(rows)

    def lookup_db(self, client_ip: str, ip: str):
        """Ask the database directly - used during an update hand-over, when the
        previous process may have answered a lookup a moment ago."""
        if self.db is None:
            return None
        rows = self.db.query("SELECT name, expires FROM dns_answers WHERE client_ip=? AND ip=? AND expires>=?",
                             (client_ip, ip, time.time()))
        if not rows:
            return None
        with self._lock:
            for r in rows:
                self._put(client_ip, ip, r["name"], r["expires"])
        return {r["name"] for r in rows}

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
