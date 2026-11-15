"""How sure are we that an alert was a *deliberate* attempt to get around the
filter, rather than an app or device just behaving oddly?

Every alert gets a confidence (5-99%) and the reasons behind it:

  1. a base likelihood for that kind of event (a 1-byte-segmented handshake is
     almost never accidental; a stale DNS cache causing a direct-IP connection
     often is),
  2. calibrated by your own reviews: each "Not a bypass" / "Confirmed" click
     teaches it how often that kind of alert is wrong in *your* house,
  3. adjusted by the device's recent behaviour: one odd connection is
     probably an app; five different techniques in a day is a person.
"""
from __future__ import annotations

import json
import threading
import time

CATEGORIES = {
    "vpn": "VPNs & proxies",
    "dns": "DNS tricks",
    "disguise": "Disguised traffic",
    "torrent": "Torrents",
    "tamper": "Tampering with the gateway",
    "download": "Suspicious downloads",
    "adult": "Adult content",
    "info": "Info",
}

# kind: (category, base %, what "Not a bypass" does, why it might be a false positive)
KIND_META: dict[str, tuple] = {
    "vpn_server":         ("vpn", 85, "allow_ip", "the IP list can be out of date"),
    "bypass_domain":      ("vpn", 60, "none", "looking up a VPN site may just be curiosity or an ad"),
    "blocked_udp":        ("vpn", 90, "allow_ip", "a work/school VPN on this device"),
    "blocked_port":       ("vpn", 65, "allow_ip", "some apps try odd ports before falling back to 443"),
    "http_proxy":         ("vpn", 90, "allow_ip", "very few apps use HTTP CONNECT"),
    "tunnel_behaviour":   ("vpn", 75, "allow_ip", "big downloads or streaming from an unlisted service"),
    "doh_server":         ("dns", 55, "allow_ip", "browsers may try encrypted DNS automatically"),
    "no_dns":             ("dns", 50, "allow_ip", "apps with built-in server addresses or old DNS caches"),
    "dns_bypass_site":    ("dns", 70, "none", "a cached address shared with an allowed site"),
    "dns_tunnel":         ("dns", 90, "none", "some security/telemetry software uses random hostnames"),
    "custom_dns":         ("dns", 55, "none", "some gadgets (e.g. Chromecast) hard-code Google DNS"),
    "ech":                ("dns", 50, "allow_ip", "browsers enable it automatically when they can"),
    "protocol_violation": ("disguise", 75, "allow_ip", "a few apps use their own protocol on port 443"),
    "server_first":       ("disguise", 70, "allow_ip", "rare custom app protocols"),
    "evasion":            ("disguise", 95, "allow_ip", "almost never accidental"),
    "sni_mismatch":       ("disguise", 80, "allow_ip", "unusual CDN setups"),
    "no_sni":             ("disguise", 60, "allow_ip", "some games and gadgets connect by IP"),
    "torrent":            ("torrent", 92, "allow_ip", "a game launcher using BitTorrent for updates"),
    "torrent_peers":      ("torrent", 70, "none", "peer-to-peer games or video calls"),
    "torrent_site":       ("torrent", 55, "none", "following a link without knowing what the site is"),
    "torrent_lan":        ("torrent", 85, "none", "a torrent client left running in the background"),
    "mac_spoof":          ("tamper", 85, "identity", "an OS update or a new network adapter on your own device"),
    "mac_clone":          ("tamper", 95, "identity", "two of your devices sharing an adapter (rare)"),
    "mac_change":         ("tamper", 35, "none", "phones rotate 'private Wi-Fi addresses' on their own"),
    "arp_spoof":          ("tamper", 95, "none", "a misconfigured device claiming the wrong address"),
    "ip_spoof":           ("tamper", 80, "none", "an address re-used after a DHCP lease expired"),
    "rogue_dhcp":         ("tamper", 85, "none", "your Wi-Fi access point still running its own DHCP"),
    "rogue_ra":           ("tamper", 80, "none", "a device sharing its internet connection"),
    "static_ip":          ("tamper", 40, "none", "printers and some gadgets use fixed addresses"),
    "gateway_probe":      ("tamper", 60, "none", "an app scanning the network for devices"),
    "port_scan":          ("tamper", 90, "none", "network tools / some antivirus scans"),
    "dashboard_bruteforce": ("tamper", 75, "none", "a parent mistyping the password"),
    "hidden_router":      ("tamper", 45, "none", "a virtual machine or a phone hotspot"),
    "gateway_offline":    ("tamper", 30, "none", "a power cut or a planned reboot"),
    "download_held":      ("download", 50, "none", "a legitimate file from a site the gateway doesn't know"),
    "adult_site":         ("adult", 65, "none", "pop-up ads and redirects can trigger lookups nobody chose"),
    "adult_keyword":      ("adult", 60, "none", "an innocent site whose name happens to contain the word"),
    "adult_family_dns":   ("adult", 65, "none", "the family filter also blocks malware and occasionally misjudges"),
    "adult_proxy":        ("adult", 90, "none", "very rare by accident"),
    "content_mirror":     ("adult", 50, "none", "homework research using a web archive"),
    "unsafe_search":      ("adult", 40, "none", "simply preferring another search engine"),
    "video_held":         ("adult", 50, "none", "a normal site with its own video player (news, school)"),
    "new_device":         ("info", None, "none", ""),
}

PRIOR_WEIGHT = 5            # how many reviews it takes to move the base halfway


def kind_category(kind: str) -> str:
    return KIND_META.get(kind, ("vpn",))[0]


class ConfidenceScorer:
    def __init__(self, db=None):
        self.db = db
        self._reviews: dict[str, tuple[int, int]] = {}
        self._allowed: set = set()
        self._loaded = 0.0
        self._lock = threading.Lock()

    def reload(self):
        if self.db is None:
            return
        rows = self.db.review_stats()
        allowed = {r["value"] for r in self.db.allowlist()}
        with self._lock:
            self._reviews = {r["kind"]: (r["reviewed"], r["fp"]) for r in rows}
            self._allowed = allowed
            self._loaded = time.time()

    def _maybe_reload(self):
        if self.db is not None and time.time() - self._loaded > 60:
            self.reload()

    def score(self, kind: str, device_id=None, dst=None, domain=None, count: int = 1,
              base: int | None = None) -> tuple[int | None, list[str]]:
        meta = KIND_META.get(kind)
        if meta is None or meta[1] is None and base is None:
            return None, []
        self._maybe_reload()
        b = base if base is not None else meta[1]
        why = [f"{b}%: typical for this kind of event"]
        conf = float(b)

        reviewed, fp = self._reviews.get(kind, (0, 0))
        if reviewed:
            observed = 100.0 * (reviewed - fp) / reviewed
            new = (conf * PRIOR_WEIGHT + observed * reviewed) / (PRIOR_WEIGHT + reviewed)
            why.append(f"{new - conf:+.0f}: you reviewed {reviewed} alerts like this, "
                       f"{fp} were false positives")
            conf = new

        if self.db is not None and device_id:
            others = self.db.distinct_kinds_since(device_id, time.time() - 86400, exclude=kind)
            others = [k for k in others if KIND_META.get(k, ("info",))[0] != "info"]
            if others:
                bump = min(20, 6 * len(others))
                why.append(f"+{bump}: this device tried {len(others)} other technique"
                           f"{'s' if len(others) > 1 else ''} in the last 24 h")
                conf += bump
        if count >= 5:
            why.append(f"+5: repeated {count} times")
            conf += 5
        if (dst and dst in self._allowed) or (domain and domain in self._allowed):
            why.append("-40: you marked this destination as fine before")
            conf -= 40
        return int(max(5, min(99, round(conf)))), why

    @staticmethod
    def dumps(why: list[str]) -> str:
        return json.dumps(why)
