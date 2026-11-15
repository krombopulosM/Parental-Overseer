"""Bypass-attempt alerts, de-duplicated so one blocked VPN app retrying every
second shows up as one alert with a counter rather than thousands of rows.
Each alert carries a category and a 'deliberate' confidence score."""
from __future__ import annotations

import threading
import time

from .confidence import ConfidenceScorer, kind_category

KINDS = {
    "vpn_server":         ("Connection to a known VPN server blocked", "high"),
    "doh_server":         ("Encrypted DNS server blocked", "medium"),
    "bypass_domain":      ("VPN / proxy / bypass service blocked", "medium"),
    "protocol_violation": ("Disguised traffic on a web port", "high"),
    "server_first":       ("Non-web protocol on a web port", "high"),
    "evasion":            ("Deliberately fragmented handshake (filter evasion)", "high"),
    "no_dns":             ("Direct-IP connection (skipped the gateway's DNS)", "medium"),
    "sni_mismatch":       ("Site name doesn't match DNS (disguised tunnel)", "high"),
    "dns_bypass_site":    ("Reached a blocked site without the gateway's DNS", "medium"),
    "no_sni":             ("Encrypted connection with no site name", "medium"),
    "ech":                ("Encrypted Client Hello (hidden destination)", "medium"),
    "http_proxy":         ("HTTP proxy tunnel attempt", "high"),
    "blocked_udp":        ("VPN protocol over UDP blocked", "high"),
    "blocked_port":       ("Connection on a non-web port blocked", "low"),
    "dns_tunnel":         ("DNS tunnelling detected", "high"),
    "custom_dns":         ("Device set to its own DNS server", "medium"),
    "tunnel_behaviour":   ("Traffic behaves like a VPN tunnel", "high"),
    "torrent":            ("Torrent download blocked", "high"),
    "torrent_peers":      ("Torrent / P2P client activity", "medium"),
    "torrent_site":       ("Torrent site blocked", "medium"),
    "torrent_lan":        ("Torrent client running on the network", "medium"),
    "mac_spoof":          ("Trusted device's identity used by another device", "high"),
    "mac_clone":          ("Two devices using the same hardware address", "high"),
    "mac_change":         ("Device reappeared with a new hardware address", "low"),
    "arp_spoof":          ("Device pretending to be the gateway (ARP spoofing)", "high"),
    "ip_spoof":           ("Device claiming another device's address", "high"),
    "rogue_dhcp":         ("Unauthorised DHCP server on the network", "high"),
    "rogue_ra":           ("Device advertising itself as an IPv6 router", "high"),
    "static_ip":          ("Device using a manually set IP address", "low"),
    "gateway_probe":      ("Tried to log in to the gateway", "medium"),
    "port_scan":          ("Port scan of the gateway", "high"),
    "dashboard_bruteforce": ("Repeated wrong dashboard passwords", "high"),
    "hidden_router":      ("Other devices hidden behind this one", "medium"),
    "gateway_offline":    ("Gateway was offline", "medium"),
    "download_held":      ("Suspicious download held for review", "medium"),
    "adult_site":         ("Adult site blocked", "medium"),
    "adult_keyword":      ("Site with an adult name blocked", "medium"),
    "adult_family_dns":   ("Adult site caught by the family DNS filter", "medium"),
    "adult_proxy":        ("Adult site via a translator / cache proxy", "high"),
    "content_mirror":     ("Web archive / page-cache mirror blocked", "low"),
    "unsafe_search":      ("Search engine without enforceable SafeSearch", "low"),
    "video_held":         ("Video from an unknown site held for review", "medium"),
    "new_device":         ("New device joined the network", "info"),
}


class AlertSink:
    def __init__(self, db=None, dedupe_window: float = 600, echo: bool = False, scorer=None):
        self.db = db
        self.dedupe_window = dedupe_window
        self.echo = echo
        self.scorer = scorer or ConfidenceScorer(db)
        self.memory: list[dict] = []          # used when there's no DB (replay tool, tests)
        self.listeners: list = []             # callables(alert) - e.g. auto-pause on tampering
        self._lock = threading.Lock()
        self._recent: dict = {}

    def emit(self, kind: str, *, device_id=None, client_ip=None, detail="", dst=None,
             domain=None, action="blocked", severity=None, base=None):
        title, default_sev = KINDS.get(kind, (kind, "medium"))
        key = (device_id, kind, dst, domain)
        now = time.time()
        with self._lock:
            last = self._recent.get(key)
            fresh = last is None or now - last[0] > self.dedupe_window
            count = 1 if fresh else last[1] + 1
            self._recent[key] = (now, count)
            if len(self._recent) > 20000:
                cutoff = now - self.dedupe_window
                self._recent = {k: v for k, v in self._recent.items() if v[0] > cutoff}
        confidence, why = self.scorer.score(kind, device_id, dst, domain, count, base)
        alert = {"kind": kind, "title": title, "severity": severity or default_sev,
                 "category": kind_category(kind), "device_id": device_id, "client_ip": client_ip,
                 "detail": detail, "dst": dst, "domain": domain, "action": action, "ts": now,
                 "count": count, "confidence": confidence, "confidence_why": why}
        if self.db is None:
            with self._lock:
                if fresh:
                    self.memory.append(alert)
                else:
                    for a in reversed(self.memory):
                        if (a["device_id"], a["kind"], a["dst"], a["domain"]) == key:
                            a.update(count=count, confidence=confidence, confidence_why=why)
                            break
        else:
            self.db.upsert_alert(alert, self.dedupe_window)
        if fresh:
            if self.echo:
                c = f" [{confidence}% deliberate]" if confidence is not None else ""
                print(f"[alert] {alert['severity']:6} {kind}{c}: {detail} (device {device_id}, {client_ip})")
            for fn in self.listeners:
                try:
                    fn(alert)
                except Exception as e:
                    print(f"[alert] listener failed: {e}")
        return alert
