"""Filtering DNS server.

For every lookup: identify the device, apply pause/schedule, policy and
anti-bypass rules, forward allowed names upstream, then re-check the answer's
CNAME chain (so an allowed name can't alias to a blocked one) and remember
which IPs this device was given (used by the inspector's DNS-consistency check).
"""
from __future__ import annotations

import collections
import threading
import time

from dnslib import CNAME, RR, DNSRecord, QTYPE, RCODE
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from .services import is_ip_literal, registrable_domain

FIREFOX_CANARY = "use-application-dns.net"


class QueryStats:
    """Per-client query timestamps; the detector uses these to spot devices
    whose DNS has gone quiet because it's travelling inside a tunnel."""

    def __init__(self, keep: float = 900):
        self.keep = keep
        self._q: dict[str, collections.deque] = {}
        self._lock = threading.Lock()

    def note(self, ip: str):
        now = time.time()
        with self._lock:
            dq = self._q.setdefault(ip, collections.deque())
            dq.append(now)
            while dq and dq[0] < now - self.keep:
                dq.popleft()

    def count(self, ip: str, window: float) -> int:
        cutoff = time.time() - window
        with self._lock:
            dq = self._q.get(ip)
            return sum(1 for t in dq if t >= cutoff) if dq else 0


class DnsTunnelDetector:
    """Flags a device that sends a stream of long, unique, random-looking
    subdomains of one domain - the signature of iodine/dnscat-style tunnels."""

    def __init__(self, cfg: dict, alerts=None):
        self.enabled = cfg.get("enabled", True)
        self.window = cfg.get("window", 300)
        self.unique_names = cfg.get("unique_names", 120)
        self.min_label_len = cfg.get("min_label_len", 24)
        self.block_seconds = cfg.get("block_hours", 24) * 3600
        self.alerts = alerts
        self._seen: dict[tuple, dict] = {}
        self._blocked: dict[tuple, float] = {}
        self._lock = threading.Lock()

    def check(self, ctx, qname: str) -> bool:
        """Returns True if this lookup should be blocked as tunnel traffic."""
        if not self.enabled:
            return False
        base = registrable_domain(qname) or qname
        key = (ctx.device_id, base)
        now = time.time()
        with self._lock:
            until = self._blocked.get(key)
            if until and until > now:
                return True
            sub = qname[: -len(base)].rstrip(".") if qname != base else ""
            longest = max((len(l) for l in sub.split(".")), default=0) if sub else 0
            if longest < self.min_label_len and len(sub) < self.min_label_len * 2:
                return False
            names = self._seen.setdefault(key, {})
            names[qname] = now
            if len(names) > self.unique_names // 2:
                cutoff = now - self.window
                for n in [n for n, t in names.items() if t < cutoff]:
                    del names[n]
            if len(names) >= self.unique_names:
                self._blocked[key] = now + self.block_seconds
                names.clear()
                fire = True
            else:
                fire = False
        if fire and self.alerts:
            self.alerts.emit("dns_tunnel", device_id=ctx.device_id, client_ip=ctx.ip, domain=base,
                             detail=f"{self.unique_names}+ long random subdomains of {base} within "
                                    f"{self.window // 60} min - data is being smuggled through DNS. "
                                    f"Blocked {base} for this device.")
        return fire


class GuardianResolver(BaseResolver):
    def __init__(self, cfg, policy, lists, dnscache, db, alerts, scheduler, stats, tunnel):
        self.cfg = cfg
        d = cfg["dns"]
        self.upstreams = list(d.get("upstreams") or ["1.1.1.1"])
        self.up_port = int(d.get("upstream_port", 53))
        self.strip_https = d.get("strip_https_records", "filtered")
        self.block_qtypes = set(d.get("block_qtypes_filtered") or [])
        self.strip_aaaa = cfg["mode"] == "gateway" and not cfg["gateway"].get("ipv6", False)
        self.ech_names = set(cfg["enforcement"].get("ech_public_names") or [])
        # DNS meant for some other server is redirected to this port, so we know
        # the device was set up with its own DNS server.
        self.redirect_port = int(d.get("redirect_port", 0)) if cfg["mode"] == "gateway" else 0
        self.policy, self.lists, self.dnscache, self.db = policy, lists, dnscache, db
        self.alerts, self.scheduler, self.stats, self.tunnel = alerts, scheduler, stats, tunnel
        self._seen_domains: set[str] = set()
        self.counters = collections.Counter()
        self.adult = None                     # AdultGuard, wired by the app
        self.reputation = None                # Reputation: adults' sites become "familiar"

    # ------------------------------------------------------------ helpers
    def _log(self, ctx, qname, qtype, action, reason):
        if self.db is not None:
            self.db.log_query(ctx.device_id, ctx.ip, qname, qtype, action, reason)

    @staticmethod
    def _reply(request, rcode=RCODE.NOERROR):
        r = request.reply()
        r.header.rcode = rcode
        return r

    def forward(self, request, upstreams=None):
        for up in upstreams or self.upstreams:
            try:
                data = request.send(up, self.up_port, tcp=False, timeout=3)
                rec = DNSRecord.parse(data)
                if rec.header.tc:
                    rec = DNSRecord.parse(request.send(up, self.up_port, tcp=True, timeout=4))
                return rec
            except Exception:
                continue
        return None

    def lookup(self, name: str, qtype: str = "A") -> list[str]:
        """Plain upstream lookup used by list pinning (bypasses policy)."""
        out = []
        for qt in ("A", "AAAA") if qtype == "both" else (qtype,):
            rec = self.forward(DNSRecord.question(name, qt))
            if rec:
                out += [str(rr.rdata) for rr in rec.rr if QTYPE[rr.rtype] in ("A", "AAAA")]
        return out

    # ------------------------------------------------------------ main path
    def resolve(self, request, handler):
        client_ip = handler.client_address[0]
        if client_ip.startswith("::ffff:"):
            client_ip = client_ip[7:]
        qname = str(request.q.qname).rstrip(".").lower()
        try:
            qtype = QTYPE[request.q.qtype]
        except Exception:
            qtype = str(request.q.qtype)
        ctx = self.policy.context(client_ip)
        self.stats.note(client_ip)
        self.counters["queries"] += 1
        redirected = bool(self.redirect_port) and \
            getattr(getattr(handler, "server", None), "server_address", ("", 0))[1] == self.redirect_port
        if redirected and ctx.filtered and self.alerts:
            self.alerts.emit("custom_dns", device_id=ctx.device_id, client_ip=ctx.ip, action="redirected",
                             detail="Sent its DNS lookups to a server of its own choosing instead of the "
                                    "gateway. They were quietly redirected here and filtered anyway.")

        paused, why = self.scheduler.is_paused(ctx.device_id, ctx.group)
        if paused:
            self._log(ctx, qname, qtype, "blocked", why)
            return self._reply(request, RCODE.NXDOMAIN)

        if qname == FIREFOX_CANARY or qname.endswith("." + FIREFOX_CANARY):
            self._log(ctx, qname, qtype, "blocked", "Firefox DoH canary (keeps Firefox on our DNS)")
            return self._reply(request, RCODE.NXDOMAIN)

        if ctx.filtered:
            if qtype in self.block_qtypes:
                self._log(ctx, qname, qtype, "blocked", f"{qtype} records are only used by tunnels")
                return self._reply(request, RCODE.REFUSED)
            if self.tunnel.check(ctx, qname):
                self._log(ctx, qname, qtype, "blocked", "DNS tunnel")
                return self._reply(request, RCODE.NXDOMAIN)

        decision = self.policy.decide(ctx, qname)
        if decision.block:
            self.counters["blocked"] += 1
            self._log(ctx, qname, qtype, "blocked", decision.reason)
            if decision.category == "bypass" and ctx.filtered and self.alerts:
                self.alerts.emit("bypass_domain", device_id=ctx.device_id, client_ip=ctx.ip,
                                 domain=registrable_domain(qname),
                                 detail=f"Looked up {qname} (VPN / proxy / encrypted-DNS service)")
            elif decision.category == "torrent" and ctx.filtered and self.alerts:
                self.alerts.emit("torrent_site", device_id=ctx.device_id, client_ip=ctx.ip,
                                 domain=registrable_domain(qname),
                                 detail=f"Looked up {qname} (torrent site, tracker or client)")
            elif decision.category in ("adult", "mirrors", "unsafe_search") and ctx.filtered and self.alerts:
                kind, what = {"adult": ("adult_site", "a known adult site"),
                              "mirrors": ("content_mirror", "a web archive / page cache that can show "
                                                            "blocked sites' content"),
                              "unsafe_search": ("unsafe_search", "a search engine whose SafeSearch can't "
                                                                 "be locked on")}[decision.category]
                self.alerts.emit(kind, device_id=ctx.device_id, client_ip=ctx.ip,
                                 domain=registrable_domain(qname), detail=f"Looked up {qname} - {what}")
            return self._reply(request, RCODE.NXDOMAIN)

        adult = self.adult if ctx.filtered else None
        if adult is not None:
            hit = adult.check_name(ctx, qname)
            if hit:
                kind, reason, base = hit
                self.counters["blocked"] += 1
                self._log(ctx, qname, qtype, "blocked", reason)
                if self.alerts:
                    self.alerts.emit(kind, device_id=ctx.device_id, client_ip=ctx.ip, base=base,
                                     domain=registrable_domain(qname), detail=f"{qname}: {reason}")
                return self._reply(request, RCODE.NXDOMAIN)

        if qtype in ("HTTPS", "SVCB", "TYPE65", "TYPE64") and (
                self.strip_https == "all" or (self.strip_https == "filtered" and ctx.filtered)):
            self.counters["https_stripped"] += 1
            return self._reply(request)             # NOERROR, no records: no ECH keys
        if qtype == "AAAA" and self.strip_aaaa:
            return self._reply(request)

        family = adult.family_dns if adult is not None and adult.use_family_dns(ctx) else None
        target = adult.safesearch_target(qname, ctx) if adult is not None else None
        note = decision.reason
        if target and qtype in ("A", "AAAA"):
            # SafeSearch / Restricted Mode: answer with the engine's locked "safe" address
            sub = self.forward(DNSRecord.question(target, qtype))
            if sub is None:
                self._log(ctx, qname, qtype, "error", "upstream unreachable")
                return self._reply(request, RCODE.SERVFAIL)
            reply = request.reply()
            reply.add_answer(RR(request.q.qname, QTYPE.CNAME, rdata=CNAME(target + "."), ttl=300))
            for rr in sub.rr:
                reply.add_answer(rr)
            note = f"SafeSearch enforced ({target})"
            family = None
        else:
            reply = self.forward(request, family) if family else None
            if reply is None:
                if family:
                    self.counters["family_dns_unreachable"] += 1
                    family = None
                reply = self.forward(request)
        if reply is None:
            self._log(ctx, qname, qtype, "error", "upstream unreachable")
            return self._reply(request, RCODE.SERVFAIL)

        names, ips = [qname], []
        for rr in reply.rr:
            rt = QTYPE[rr.rtype]
            if rt == "CNAME":
                names.append(str(rr.rdata).rstrip(".").lower())
            elif rt in ("A", "AAAA"):
                ips.append((str(rr.rdata), rr.ttl))
        for alias in names[1:]:
            d2 = self.policy.decide(ctx, alias)
            if d2.block:
                self._log(ctx, qname, qtype, "blocked", f"alias {alias} -> {d2.reason}")
                return self._reply(request, RCODE.NXDOMAIN)
        if family and adult.family_flagged([ip for ip, _ in ips]):
            self.counters["blocked"] += 1
            reason = "flagged by the family DNS filter (adult or malware)"
            self._log(ctx, qname, qtype, "blocked", reason)
            if self.alerts:
                self.alerts.emit("adult_family_dns", device_id=ctx.device_id, client_ip=ctx.ip,
                                 domain=registrable_domain(qname),
                                 detail=f"{qname} isn't on our lists, but the family DNS filter classifies it "
                                        f"as adult or malicious")
            return self._reply(request, RCODE.NXDOMAIN)
        if adult is not None and family and qtype == "A":
            origin = adult.decode_proxy(qname)          # translator/AMP proxy: ask about the real site too
            if origin:
                o = self.forward(DNSRecord.question(origin, "A"), family)
                oips = [str(rr.rdata) for rr in (o.rr if o else []) if QTYPE[rr.rtype] == "A"]
                if adult.family_flagged(oips):
                    self._log(ctx, qname, qtype, "blocked", f"proxied site {origin} flagged by family DNS")
                    if self.alerts:
                        self.alerts.emit("adult_proxy", device_id=ctx.device_id, client_ip=ctx.ip, base=90,
                                         domain=registrable_domain(origin),
                                         detail=f"Tried to open {origin} through a translator/cache proxy - "
                                                f"the family DNS filter classifies it as adult")
                    return self._reply(request, RCODE.NXDOMAIN)
        if self.strip_aaaa and ips:
            reply.rr = [rr for rr in reply.rr if QTYPE[rr.rtype] != "AAAA"]
        if ips:
            self.dnscache.record(client_ip, names, ips)

        self._log(ctx, qname, qtype, "allowed", note)
        if self.reputation is not None and not ctx.filtered and qtype in ("A", "AAAA") and ips:
            self.reputation.mark_familiar(qname)
        base = registrable_domain(qname)
        if base and base not in self._seen_domains and not is_ip_literal(base):
            self._seen_domains.add(base)
            if len(self._seen_domains) > 200000:
                self._seen_domains.clear()
            if self.db is not None:
                self.db.note_domain_seen(base)
        return reply


def start_dns(resolver: GuardianResolver, host: str, port: int):
    logger = DNSLogger(log="-request,-reply,-truncated,-data,-recv,-send", prefix=False)
    # After a restart the previous process may hold the port for a moment
    # (always on Windows, where a restart is a new process): retry briefly.
    deadline = time.time() + 15
    while True:
        try:
            servers = [DNSServer(resolver, address=host, port=port, tcp=False, logger=logger),
                       DNSServer(resolver, address=host, port=port, tcp=True, logger=logger)]
            break
        except OSError:
            if time.time() > deadline:
                raise
            time.sleep(0.5)
    for s in servers:
        s.start_thread()
    return servers
