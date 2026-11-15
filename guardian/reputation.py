"""Is a destination *known*? And is this client software a known tunnel?

Targeting the technology rather than lists of servers means asking two
questions about every connection a child's device makes:

  1. Where is it going?  A self-hosted VPN, a VPN routed through a CDN
     (VLESS/V2Ray on Cloudflare Workers), a Tor WebTunnel bridge, a Trojan
     server - all of them need *some* destination that carries a lot of
     traffic. Real browsing heavy enough to matter goes to known services,
     popular sites, sites the adults in the house use too, or sites a parent
     approved. Anything else carrying a lot is a candidate tunnel.

  2. What software is talking?  Every TLS client - browser, app, VPN
     client - opens connections with a characteristic "hello" (its JA4
     fingerprint). Once one tunnel has been caught, its fingerprint is
     remembered and that software is blocked on any server, including ones
     that didn't exist yesterday. Fingerprints ever seen talking to a known
     site (i.e. browsers and normal apps) are never learned as bad.
"""
from __future__ import annotations

import threading
import time

from .services import SERVICES, registrable_domain, service_for

# Platforms where anyone can host anything under a subdomain: popularity of the
# parent domain says nothing about the subdomain, so these never count as known
# just for being popular.
HOSTING_SUFFIXES = (
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "cloudapp.azure.com", "cloudapp.net",
    "herokuapp.com", "appspot.com", "workers.dev", "pages.dev", "vercel.app", "netlify.app", "github.io",
    "fly.dev", "onrender.com", "railway.app", "glitch.me", "repl.co", "replit.dev", "ngrok.io",
    "ngrok-free.app", "ngrok.app", "trycloudflare.com", "duckdns.org", "ddns.net", "no-ip.org", "no-ip.com",
    "dynu.net", "freedns.afraid.org", "oraclecloud.com", "linodeusercontent.com", "digitaloceanspaces.com",
    "deno.dev", "web.app", "firebaseapp.com", "loca.lt", "serveo.net", "pinggy.link",
)


def on_hosting_platform(name: str | None) -> bool:
    if not name:
        return False
    n = name.lower().rstrip(".")
    return any(n == s or n.endswith("." + s) for s in HOSTING_SUFFIXES)


class Reputation:
    def __init__(self, cfg: dict, db, lists, guard=None):
        self.cfg, self.db, self.lists, self.guard = cfg, db, lists, guard
        self.refresh_settings()
        self._familiar: dict[str, float] = {}
        self._good: dict[str, int] = {}
        self._bad: dict[str, str] = {}
        self._lock = threading.Lock()
        self.load()

    def refresh_settings(self):
        r = self.cfg.get("reputation") or {}
        self.familiar_days = float(r.get("familiar_days", 60))
        a, d = self.cfg.get("adult") or {}, self.cfg.get("downloads") or {}
        self.extra_known = {x.lower() for x in (a.get("video_sites") or [])}
        self.trusted_services = set(d.get("trusted_services") or [])

    # ------------------------------------------------------------ state
    def load(self):
        if self.db is None:
            return
        cutoff = time.time() - self.familiar_days * 86400
        fam = {r["domain"]: r["last_seen"] for r in
               self.db.query("SELECT domain, last_seen FROM familiar_domains WHERE last_seen>=?", (cutoff,))}
        good, bad = {}, {}
        for r in self.db.query("SELECT ja4, good, bad_label FROM tls_fingerprints"):
            good[r["ja4"]] = r["good"] or 0
            if r["bad_label"]:
                bad[r["ja4"]] = r["bad_label"]
        with self._lock:
            self._familiar, self._good, self._bad = fam, good, bad

    @property
    def has_popularity(self) -> bool:
        return bool(getattr(self.lists, "popular", None))

    # ------------------------------------------------------------ destinations
    def mark_familiar(self, name: str):
        """An adult's device used this site: it's normal for this household."""
        reg = registrable_domain(name)
        if not reg or on_hosting_platform(name):
            return
        now = time.time()
        last = self._familiar.get(reg)
        if last is None or now - last > 3600:
            self._familiar[reg] = now
            if self.db is not None:
                self.db.enqueue("INSERT INTO familiar_domains (domain, last_seen) VALUES (?,?) "
                                "ON CONFLICT(domain) DO UPDATE SET last_seen=excluded.last_seen", (reg, now))

    def known(self, name: str | None, device_id: str | None = None):
        """(True, why) if this destination is one that real use explains."""
        if not name:
            return False, "no site name"
        name = name.lower().rstrip(".")
        reg = registrable_domain(name)
        svc = service_for(name)
        if svc in SERVICES or svc in self.trusted_services:
            return True, "a known service"
        if reg in self.extra_known or name in self.extra_known:
            return True, "a known video / education service"
        if self.guard is not None and device_id and (device_id, self.guard.site_key(name)) in self.guard.approved:
            return True, "you approved it"
        hosted = on_hosting_platform(name)
        if not hosted and reg in (getattr(self.lists, "popular", None) or ()):
            return True, "a popular site"
        if not hosted and reg in self._familiar:
            return True, "used by an adult in the house"
        if hosted:
            return False, "a self-hosting platform (anyone can run a server there)"
        return False, "not a popular site, a known service, or one the adults here use"

    # ------------------------------------------------------------ TLS fingerprints
    def note_good(self, ja4: str | None):
        if not ja4:
            return
        with self._lock:
            self._good[ja4] = self._good.get(ja4, 0) + 1
            first = self._good[ja4] == 1
            forgiven = self._bad.pop(ja4, None)
        if self.db is not None and (first or forgiven or self._good[ja4] % 50 == 0):
            self.db.enqueue("INSERT INTO tls_fingerprints (ja4, good, last) VALUES (?,?,?) ON CONFLICT(ja4) "
                            "DO UPDATE SET good=excluded.good, bad_label=CASE WHEN excluded.good>0 THEN NULL "
                            "ELSE tls_fingerprints.bad_label END, last=excluded.last",
                            (ja4, self._good[ja4], time.time()))

    def learn_bad(self, ja4: str | None, label: str, source: str) -> bool:
        """Remember a tunnel client's fingerprint - unless browsers/apps use it for normal sites."""
        if not ja4 or not (self.cfg.get("vpn") or {}).get("learn_fingerprints", True):
            return False
        with self._lock:
            if self._good.get(ja4):
                return False
            new = ja4 not in self._bad
            self._bad[ja4] = label
        if self.db is not None:
            self.db.enqueue("INSERT INTO tls_fingerprints (ja4, good, bad_label, bad_source, learned, last) "
                            "VALUES (?,?,?,?,?,?) ON CONFLICT(ja4) DO UPDATE SET bad_label=excluded.bad_label, "
                            "bad_source=excluded.bad_source, learned=excluded.learned",
                            (ja4, 0, label, source, time.time(), time.time()))
        return new

    def bad_label(self, ja4: str | None) -> str | None:
        if not ja4:
            return None
        with self._lock:
            return None if self._good.get(ja4) else self._bad.get(ja4)

    def forgive(self, ja4: str | None):
        """Parent said 'not a bypass': this fingerprint is fine."""
        if not ja4:
            return
        with self._lock:
            self._bad.pop(ja4, None)
            self._good[ja4] = max(1, self._good.get(ja4, 0))
        if self.db is not None:
            self.db.execute("INSERT INTO tls_fingerprints (ja4, good, last) VALUES (?,1,?) ON CONFLICT(ja4) "
                            "DO UPDATE SET good=MAX(tls_fingerprints.good,1), bad_label=NULL", (ja4, time.time()))

    def learned(self) -> list[dict]:
        if self.db is None:
            return []
        return self.db.query("SELECT ja4, bad_label, bad_source, learned FROM tls_fingerprints "
                             "WHERE bad_label IS NOT NULL ORDER BY learned DESC")
