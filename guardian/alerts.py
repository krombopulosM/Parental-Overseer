"""Bypass-attempt alerts, de-duplicated so one blocked VPN app retrying every
second shows up as one alert with a counter rather than thousands of rows."""
from __future__ import annotations

import threading
import time

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
    "tunnel_behaviour":   ("Traffic behaves like a VPN tunnel", "high"),
    "new_device":         ("New device joined the network", "info"),
}


class AlertSink:
    def __init__(self, db=None, dedupe_window: float = 600, echo: bool = False):
        self.db = db
        self.dedupe_window = dedupe_window
        self.echo = echo
        self.memory: list[dict] = []          # used when there's no DB (replay tool, tests)
        self._lock = threading.Lock()
        self._recent: dict = {}

    def emit(self, kind: str, *, device_id=None, client_ip=None, detail="", dst=None,
             domain=None, action="blocked", severity=None):
        title, default_sev = KINDS.get(kind, (kind, "medium"))
        alert = {"kind": kind, "title": title, "severity": severity or default_sev,
                 "device_id": device_id, "client_ip": client_ip, "detail": detail,
                 "dst": dst, "domain": domain, "action": action, "ts": time.time()}
        key = (device_id, kind, dst, domain)
        now = time.time()
        with self._lock:
            last = self._recent.get(key)
            fresh = last is None or now - last > self.dedupe_window
            self._recent[key] = now
            if len(self._recent) > 20000:
                cutoff = now - self.dedupe_window
                self._recent = {k: v for k, v in self._recent.items() if v > cutoff}
            if self.db is None:
                if fresh:
                    self.memory.append(alert)
                else:
                    for a in reversed(self.memory):
                        if (a["device_id"], a["kind"], a["dst"], a["domain"]) == key:
                            a["count"] = a.get("count", 1) + 1
                            break
        if self.db is not None:
            self.db.upsert_alert(alert, self.dedupe_window)
        if self.echo and fresh:
            print(f"[alert] {alert['severity']:6} {kind}: {detail} (device {device_id}, {client_ip})")
        return alert
