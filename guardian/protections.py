"""The anti-bypass protections, each one switchable.

Every protection has a house-wide setting (config `protections:`) that applies
to all filtered groups, and any group can override it (`groups.<name>.protections`).
A value of null in a group means "use the house-wide setting". Unfiltered groups
(adults) get none of them.

Turning a protection off opens exactly the route it closes - the descriptions
below say which, so the dashboard can be honest about the trade-off.
"""
from __future__ import annotations

# key -> label, what it does, what turning it off allows, choices (None = on/off)
PROTECTIONS: dict[str, dict] = {
    "vpn": {
        "label": "VPNs",
        "does": "VPN websites and app sign-in servers, known VPN server addresses (Mullvad, Proton, WARP...), "
                "VPN protocols (WireGuard, OpenVPN, IPsec, AnyConnect) and the fingerprints of VPN apps caught "
                "before - so new servers are blocked too.",
        "off": "VPN apps can connect. Once connected, everything the device does is hidden from the gateway.",
        "group": "Apps and services",
    },
    "tor": {
        "label": "Tor",
        "does": "The Tor website and bridge distribution, every running Tor relay, and Tor's own handshake "
                "(its made-up site names), so a copy of Tor Browser from a USB stick doesn't work either.",
        "off": "Tor Browser can connect and hide everything it visits.",
        "group": "Apps and services",
    },
    "proxies": {
        "label": "Proxies",
        "does": "Web-proxy sites ('browse any site through us'), iCloud Private Relay, public tunnelling "
                "services and proxy connections (HTTP CONNECT, SOCKS).",
        "off": "Proxy sites and proxy settings work, and show blocked sites through someone else's server.",
        "group": "Apps and services",
    },
    "encrypted_dns": {
        "label": "Encrypted DNS",
        "does": "Public DNS-over-HTTPS / DNS-over-TLS resolvers (Android 'Private DNS', browsers' secure DNS) "
                "and Firefox's switch for it.",
        "off": "A device can look sites up through an encrypted resolver, which skips the gateway's site "
               "filter (the deeper checks still see where it connects).",
        "group": "Apps and services",
    },
    "disguised_tunnels": {
        "label": "Disguised tunnels",
        "does": "Traffic on the web ports must really be web traffic: tunnels pretending to be HTTPS "
                "(Shadowsocks, obfs4, 'stealth' VPN modes), protocols where the server talks first, and "
                "handshakes split into tiny pieces to slip past inspection are cut.",
        "off": "Stealth VPN modes and Tor bridges that disguise themselves as web traffic can connect.",
        "group": "Tricks",
    },
    "hidden_names": {
        "label": "Hidden site names",
        "does": "Encrypted connections must say which site they're for. Connections that hide it (no name, "
                "Encrypted Client Hello) are refused, HTTPS DNS records that carry ECH keys are removed, and "
                "QUIC is switched off so browsers use connections whose site name is visible.",
        "off": "Some connections can hide which site they're going to; ECH-capable sites stay hidden.",
        "group": "Tricks",
    },
    "direct_ip": {
        "label": "Direct-to-address connections",
        "does": "Connections to an address that wasn't looked up through the gateway are judged by the site "
                "they turn out to be for: a real, allowed site goes through (apps and browsers often reuse "
                "addresses they remember), one that won't say which site it's for is refused - that's how VPN "
                "and proxy apps with built-in server addresses look. Domain fronting (a connection claiming one "
                "site while going to another) is refused. 'Strict' refuses every connection that wasn't looked "
                "up first: it catches more hard-coded servers, but some apps and sites stop working.",
        "off": "Apps with built-in server addresses connect without ever looking anything up.",
        "choices": [["enforce", "Block unnamed ones"], ["strict", "Strict: block all"], ["log", "Allow and tell me"],
                    ["off", "Off"]],
        "group": "Tricks",
    },
    "dns_tunnels": {
        "label": "DNS tunnels",
        "does": "Traffic smuggled inside DNS lookups (iodine, dnscat and similar), and the unusual record "
                "types only tunnels use.",
        "off": "A DNS-tunnel app can carry traffic through the gateway's own DNS.",
        "group": "Tricks",
    },
    "non_web": {
        "label": "Traffic other than the web",
        "does": "Which kinds of traffic may leave the device. 'Web only' is the strongest: VPN protocols "
                "and most tunnels need something else. Games consoles need UDP.",
        "off": "With 'Allow everything', other traffic is still checked for VPN, Tor and torrent signatures "
               "when those protections are on, but anything unrecognised gets through.",
        "choices": [["block", "Web only"], ["games", "Web + games (UDP)"], ["allow", "Allow everything"]],
        "group": "Other traffic",
    },
    "torrents": {
        "label": "Torrent protocols",
        "does": "BitTorrent traffic itself: peer connections (even disguised on web ports), tracker "
                "announcements, DHT/uTP, and devices contacting dozens of peers. Torrent websites are the "
                "separate 'Torrents' category.",
        "off": "A torrent client that reaches its peers can download.",
        "group": "Other traffic",
    },
    "behaviour": {
        "label": "Behaviour detection",
        "does": "Watches for traffic that behaves like a tunnel even when nothing else gives it away - "
                "one long connection carrying almost everything while the device stops looking sites up - "
                "and blocks that destination.",
        "off": "A brand-new tunnel no list or fingerprint knows can keep running.",
        "group": "Detection",
    },
    "network_attacks": {
        "label": "Attacks on the gateway",
        "does": "Reports filtered devices probing the gateway (port scans, trying its dashboard or SSH) "
                "and devices hiding other devices behind them (hotspots, virtual machines).",
        "off": "Those attempts are still refused, but you aren't told about them.",
        "group": "Detection",
    },
}

DEFAULTS = {k: (v["choices"][0][0] if v.get("choices") else True) for k, v in PROTECTIONS.items()}
OFF = {"direct_ip": "off", "non_web": "allow"}

# Domain categories implied by a protection (not chosen per group).
CATEGORY_FOR = {"tor": "tor", "encrypted_dns": "doh", "vpn": "vpn", "proxies": "proxy"}
BYPASS_CATEGORIES = {"bypass", "vpn", "tor", "proxy", "doh"}


def _norm(key, v):
    if v is None:
        return None
    if key == "direct_ip":
        if v is True:
            return "enforce"
        if v is False:
            return "off"
        v = str(v).lower()
        return v if v in ("enforce", "strict", "log", "off") else "enforce"
    if key == "non_web":
        if v is True:
            return "block"
        if v is False:
            return "allow"
        v = str(v).lower()
        return v if v in ("block", "games", "allow") else "block"
    return bool(v)


def normalize(cfg: dict):
    """Fill in house-wide defaults and clean values (called from config.normalize)."""
    p = cfg.setdefault("protections", {})
    for k, d in DEFAULTS.items():
        p[k] = _norm(k, p.get(k, d))
        if p[k] is None:
            p[k] = d
    for g in cfg["groups"].values():
        over = g.get("protections")
        if not isinstance(over, dict):
            g["protections"] = over = {}
        for k in list(over):
            if k not in PROTECTIONS:
                over.pop(k)
            else:
                over[k] = _norm(k, over[k])


def convert_legacy(group: dict):
    """Older configs used allow_udp / require_sni / dns_consistency on a group."""
    over = group.get("protections")
    if not isinstance(over, dict):
        over = {}
    if "allow_udp" in group:
        if group.pop("allow_udp"):
            over.setdefault("non_web", "games")
    if "require_sni" in group:
        if not group.pop("require_sni"):
            over.setdefault("hidden_names", False)
    if "dns_consistency" in group:
        v = group.pop("dns_consistency")
        v = "off" if v is False else ("enforce" if v is True else str(v).lower())
        if v != "enforce":
            over.setdefault("direct_ip", v)
    if over:
        group["protections"] = over


def on(cfg: dict, group_cfg: dict | None, key: str):
    """Effective setting of one protection for a group (bool, or the choice string)."""
    if not group_cfg or not group_cfg.get("filtered"):
        return OFF.get(key, False)
    v = (group_cfg.get("protections") or {}).get(key)
    if v is None:
        v = (cfg.get("protections") or {}).get(key, DEFAULTS[key])
    return v


def effective(cfg: dict, group_cfg: dict | None) -> dict:
    return {k: on(cfg, group_cfg, k) for k in PROTECTIONS}


def is_off(key: str, value) -> bool:
    return value is False or value == OFF.get(key)
