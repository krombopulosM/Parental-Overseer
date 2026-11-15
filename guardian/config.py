"""Configuration loading.

config.yaml holds the shared defaults; config.local.yaml (optional, same layout,
gitignored) is deep-merged on top so each machine (your PC, the Pi) can override
just what differs.
"""
from __future__ import annotations

import copy
import os

import yaml

DEFAULTS: dict = {
    "mode": "monitor",
    "dns": {
        "listen_host": "0.0.0.0",
        "listen_port": 5353,
        "upstreams": ["1.1.1.1", "9.9.9.9"],
        "upstream_port": 53,
        "strip_https_records": "filtered",
        "block_qtypes_filtered": ["NULL", "ANY"],
        "redirect_port": 5354,
        "tunnel_detection": {"enabled": True, "window": 300, "unique_names": 120,
                             "min_label_len": 24, "block_hours": 24},
    },
    "web": {"host": "127.0.0.1", "port": 8080},
    "database": "guardian.db",
    "retention_days": 30,
    "groups": {
        "adults": {"filtered": False, "categories": ["ads"]},
    },
    "default_group": "adults",
    "categories": {},
    "ip_lists": {},
    "lists_refresh_hours": 24,
    "lists_cache_dir": "blocklists/cache",
    "enforcement": {
        "consistency_grace": 21600,
        "consistency_exempt": None,
        "ech_public_names": ["cloudflare-ech.com"],
        "fail_open": False,
        "queue_backend": "auto",
        "inspect_packets": 10,
        "protocol_exempt_domains": ["whatsapp.net", "whatsapp.com"],
    },
    "torrent": {"fanout_peers": 25, "window": 60},
    "adult": {
        "mode": "strict", "safesearch": True, "youtube_restricted": "strict",
        "family_dns": ["1.1.1.3", "1.0.0.3"], "family_blocked_answers": ["0.0.0.0", "::"],
        "unknown_video": "review", "video_min_bytes": 2_000_000, "video_sites": [],
    },
    "downloads": {
        "policy": "review_suspicious", "min_bytes": 5_000_000, "min_rate": 200_000, "suspicious_score": 50,
        "risky_extensions": ["exe", "msi", "bat", "cmd", "com", "scr", "ps1", "vbs", "js", "jar", "apk", "xapk",
                             "apks", "ipa", "dmg", "pkg", "deb", "rpm", "iso", "img", "zip", "rar", "7z",
                             "torrent"],
        "trusted_services": ["apple", "microsoft", "google", "steam", "epicgames", "xbox", "playstation",
                             "nintendo", "minecraft", "roblox", "spotify", "netflix", "youtube"],
    },
    "tamper": {
        "enabled": True, "auto_quarantine_confidence": 80, "carry_over_identity": True,
        "auto_pause_minutes": 30, "auto_pause_confidence": 85,
        "auto_pause_kinds": ["arp_spoof", "ip_spoof", "rogue_dhcp", "rogue_ra", "port_scan"],
        "port_scan_ports": 8, "hidden_router_min": 5, "offline_alert_minutes": 5,
        "repin_minutes": 10,
    },
    "detector": {
        "enabled": True, "interval": 30, "min_duration": 300, "min_bytes": 10_000_000,
        "window": 300, "dns_silence_max_queries": 3, "silence_min_bytes": 5_000_000,
        "threshold": 70, "block_hours": 24, "learning_days": 3, "exempt_services": [],
    },
    "flows": {
        "poll_interval": 2, "active_minute_bytes": 10_000, "sniffer_interface": None,
        "log_trusted_devices": True,
    },
    "gateway": {
        "wan_interface": "eth0", "lan_interfaces": ["eth1"], "lan_ip": "192.168.50.1",
        "lan_subnets": ["192.168.50.0/24"], "trusted_interfaces": [],
        "admin_only_dashboard": True, "admin_groups": ["adults"], "allow_wan_ssh": True,
        "ipv6": False, "dhcp_leases": "/var/lib/misc/dnsmasq.leases",
        "remove_rules_on_exit": False,
    },
}

_GROUP_DEFAULTS = {"filtered": True, "categories": [], "allow_udp": False,
                   "require_sni": True, "dns_consistency": "enforce"}


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _tristate(v, default):
    # YAML 1.1 turns bare off/on/yes/no into booleans; map them back to words.
    if v is False:
        return "off"
    if v is True:
        return default
    return str(v).lower() if v is not None else default


def load_config(path: str | None = None) -> dict:
    path = path or os.environ.get("GUARDIAN_CONFIG") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.yaml")
    path = os.path.abspath(path)
    base_dir = os.path.dirname(path)
    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    local = os.path.join(base_dir, "config.local.yaml")
    if os.path.exists(local):
        with open(local, "r", encoding="utf-8") as fh:
            cfg = deep_merge(cfg, yaml.safe_load(fh) or {})
    cfg = deep_merge(DEFAULTS, cfg)
    cfg["__base__"] = base_dir
    cfg["__path__"] = path
    normalize(cfg)
    return cfg


def normalize(cfg: dict) -> None:
    cfg["mode"] = str(cfg.get("mode", "monitor")).lower()
    for name, g in list(cfg["groups"].items()):
        merged = deep_merge(_GROUP_DEFAULTS, g or {})
        if not merged["filtered"]:
            merged["dns_consistency"] = "off"
            merged["require_sni"] = False
            merged["allow_udp"] = True
        merged["dns_consistency"] = _tristate(merged["dns_consistency"], "enforce")
        cfg["groups"][name] = merged
    if cfg["default_group"] not in cfg["groups"]:
        raise ValueError(f"default_group '{cfg['default_group']}' is not defined in groups")
    cfg["dns"]["strip_https_records"] = _tristate(cfg["dns"]["strip_https_records"], "filtered")
    cfg["dns"]["block_qtypes_filtered"] = [str(q).upper() if q is not None else "NULL"
                                           for q in cfg["dns"]["block_qtypes_filtered"]]


def resolve_path(cfg: dict, p: str | None) -> str | None:
    if not p:
        return None
    return p if os.path.isabs(p) else os.path.join(cfg["__base__"], p)
