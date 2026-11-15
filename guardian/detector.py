"""Behavioural VPN/tunnel detection - the last safety net.

Everything a VPN does to hide on the wire (real TLS, a plausible site name,
port 443) still leaves a behavioural fingerprint:

  * one long-lived connection carrying most of the device's traffic
  * the device stops making DNS lookups (its DNS now goes through the tunnel)
  * the destination has no recognisable site name, or was never seen before

Each signal adds to a score; above the threshold the destination is blocked
for filtered devices (gateway mode) or reported (monitor mode), with the
reasons spelled out so a false positive is easy to judge and allow.
"""
from __future__ import annotations

import threading
import time

from .services import registrable_domain, service_label


def _span(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 7200:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min"


class Detector:
    def __init__(self, cfg, db, monitor, stats, lists, alerts, gateway=None):
        d = cfg["detector"]
        self.cfg = d
        self.db, self.monitor, self.stats, self.lists, self.alerts = db, monitor, stats, lists, alerts
        self.gateway = gateway
        self.exempt = set(d.get("exempt_services") or [])
        self._allow_ips: set[str] = set()
        self._allow_domains: set[str] = set()
        self.last_run = 0.0
        self.flagged: list[dict] = []

    def reload_allowlist(self):
        if self.db is None:
            return
        rows = self.db.allowlist()
        self._allow_ips = {r["value"] for r in rows if r["kind"] == "ip"}
        self._allow_domains = {r["value"] for r in rows if r["kind"] == "domain"}

    def start(self):
        def loop():
            while True:
                time.sleep(self.cfg.get("interval", 30))
                try:
                    self.evaluate()
                except Exception as e:
                    print(f"[detector] {e}")
        threading.Thread(target=loop, name="detector", daemon=True).start()

    def _learning(self, now) -> bool:
        if self.db is None:
            return True
        installed = float(self.db.get_meta("installed_at") or now)
        return now - installed < self.cfg.get("learning_days", 3) * 86400

    def score(self, rec, dev_window_bytes, dns_queries, now):
        c = self.cfg
        score, why = 0, []
        if not rec.domain:
            score += 50
            why.append("no recognisable site name (no TLS name, no DNS lookup)")
        if dns_queries <= c.get("dns_silence_max_queries", 3) and \
                dev_window_bytes >= c.get("silence_min_bytes", 5_000_000):
            score += 40
            why.append(f"device made only {dns_queries} DNS lookups in {_span(c['window'])} while "
                       f"moving {dev_window_bytes / 1e6:.0f} MB (its DNS is going through a tunnel)")
        wb = rec.window_bytes(now, c["window"])
        if dev_window_bytes and wb / dev_window_bytes >= 0.7:
            score += 20
            why.append(f"this one connection carries {100 * wb // dev_window_bytes}% of the device's traffic")
        if rec.domain and not self._learning(now) and self.db is not None:
            first = self.db.domain_first_seen(registrable_domain(rec.domain))
            if first is None or now - first < 86400:
                score += 20
                why.append(f"{registrable_domain(rec.domain)} was first seen on this network today")
        if rec.domain and self.lists.category_match(rec.domain, ["bypass"]):
            score += 100
            why.append(f"{rec.domain} is a known VPN/proxy service")
        if self.lists.ip_list_match(rec.dst_ip) == "vpn":
            score += 100
            why.append(f"{rec.dst_ip} is a known VPN server")
        if rec.dst_port not in (80, 443):
            score += 10
            why.append(f"unusual port {rec.proto}/{rec.dst_port}")
        return score, why

    def evaluate(self, now: float | None = None):
        now = now or time.time()
        self.last_run = now
        self.reload_allowlist()
        c = self.cfg
        by_client: dict[str, list] = {}
        for rec in self.monitor.active_flows():
            if rec.filtered:
                by_client.setdefault(rec.client_ip, []).append(rec)
        results = []
        for client, recs in by_client.items():
            dev_bytes = sum(r.window_bytes(now, c["window"]) for r in recs)
            queries = self.stats.count(client, c["window"])
            for rec in recs:
                if rec.flagged or rec.verdict == "blocked":
                    continue
                if rec.duration < c["min_duration"] or rec.total < c["min_bytes"]:
                    continue
                if rec.service in self.exempt or rec.dst_ip in self._allow_ips:
                    continue
                if rec.domain and registrable_domain(rec.domain) in self._allow_domains:
                    continue
                score, why = self.score(rec, dev_bytes, queries, now)
                if score >= c["threshold"]:
                    results.append(self._act(rec, score, why))
        return results

    def _act(self, rec, score, why):
        rec.flagged = True
        hours = self.cfg.get("block_hours", 24)
        target = f"{rec.dst_ip}:{rec.dst_port}" + (f" ({rec.domain})" if rec.domain else "")
        detail = (f"Long-lived connection to {target}, {rec.total / 1e6:.0f} MB over "
                  f"{_span(rec.duration)}. Score {score}: " + "; ".join(why))
        if self.gateway is not None:
            self.gateway.block_ip(rec.dst_ip, hours * 3600, detail[:300], rec.device_id)
            action = f"blocked for {hours}h"
        else:
            action = "would block (monitor mode)"
        self.alerts.emit("tunnel_behaviour", device_id=rec.device_id, client_ip=rec.client_ip,
                         dst=rec.dst_ip, domain=rec.domain, detail=detail, action=action)
        res = {"device_id": rec.device_id, "dst": rec.dst_ip, "domain": rec.domain,
               "service": service_label(rec.service), "score": score, "why": why, "action": action}
        self.flagged.append(res)
        self.flagged = self.flagged[-50:]
        return res
