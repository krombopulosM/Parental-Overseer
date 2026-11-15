"""Settings the first-run wizard (and later edits) can change.

The wizard works with a small, flat set of choices. Each maps onto one or more
config paths. Choices are:
  * written to config.local.yaml (next to config.yaml), so they survive
    restarts and updates of config.yaml, and
  * applied to the running gateway straight away where that's safe; the few
    that need a restart (ports, dashboard access, fail-closed) are reported so
    the wizard can restart the service.
"""
from __future__ import annotations

import copy
import os
import time

import yaml

from .config import normalize

FILTERED_GROUPS = ("kids", "quarantine", "consoles")
DEFAULT_FAMILY_DNS = ["1.1.1.3", "1.0.0.3"]

CATEGORY_INFO = {
    "adult": ("Adult content", "Pornography and other explicit sites.", True),
    "bypass": ("VPNs, proxies, Tor, encrypted DNS", "The services children use to get around the filter. "
               "Always blocked for filtered devices.", True),
    "gambling": ("Gambling", "Betting, casinos, lotteries.", True),
    "torrent": ("Torrents", "Torrent sites, trackers and clients.", True),
    "ads": ("Ads & trackers", "Advertising and tracking - fewer pop-ups and fewer ad-driven redirects.", True),
    "mirrors": ("Web archives & page caches", "Ways to view a blocked site through someone else's copy.", True),
    "unsafe_search": ("Search engines without SafeSearch", "Search engines whose safe mode can't be locked on "
                      "(Google, Bing, DuckDuckGo stay available, locked to SafeSearch).", True),
    "piracy": ("Piracy & cracked software", "Pirated films, games and 'free' cracked software - "
               "often bundled with malware.", False),
    "filehost": ("File lockers & APK sites", "Anonymous file sharing and app download sites outside the app "
                 "stores. Off by default: downloads from them are already held for review.", False),
}

PRESETS = {
    "strict": {
        "label": "Strict", "recommended": True,
        "summary": "For children who actively try to get around filters. Suspicious downloads, video from "
                   "unknown sites and heavy traffic to unknown destinations are stopped and held for you; "
                   "repeated bypass attempts pause the device.",
        "values": {"adult_mode": "strict", "safesearch": True, "youtube": "strict", "family_dns": True,
                   "unknown_video": "review", "downloads": "review_suspicious", "unknown_destinations": "review",
                   "escalation_pause": 15, "tamper_pause": 30,
                   "categories": ["adult", "bypass", "gambling", "torrent", "ads", "mirrors", "unsafe_search",
                                  "piracy"]},
    },
    "balanced": {
        "label": "Balanced",
        "summary": "Full filtering and bypass blocking with fewer interruptions: unknown video and unknown "
                   "destinations are reported rather than stopped, YouTube is moderately restricted.",
        "values": {"adult_mode": "standard", "safesearch": True, "youtube": "moderate", "family_dns": True,
                   "unknown_video": "alert", "downloads": "review_suspicious", "unknown_destinations": "alert",
                   "escalation_pause": 15, "tamper_pause": 30,
                   "categories": ["adult", "bypass", "gambling", "torrent", "ads", "mirrors", "unsafe_search"]},
    },
    "light": {
        "label": "Light",
        "summary": "Blocks adult content, gambling and the ways around the filter, and reports attempts - "
                   "but never holds downloads or pauses devices. Good for older teenagers.",
        "values": {"adult_mode": "standard", "safesearch": True, "youtube": "moderate", "family_dns": True,
                   "unknown_video": "off", "downloads": "off", "unknown_destinations": "off",
                   "escalation_pause": 0, "tamper_pause": 0,
                   "categories": ["adult", "bypass", "gambling", "torrent"]},
    },
}

# wizard key -> (config path, needs restart)
_PATHS = {
    "adult_mode": (("adult", "mode"), False),
    "safesearch": (("adult", "safesearch"), False),
    "youtube": (("adult", "youtube_restricted"), False),
    "family_dns": (("adult", "family_dns"), False),
    "unknown_video": (("adult", "unknown_video"), False),
    "downloads": (("downloads", "policy"), False),
    "unknown_destinations": (("vpn", "unknown_destinations"), False),
    "escalation_pause": (("escalation", "pause_minutes"), False),
    "tamper_pause": (("tamper", "auto_pause_minutes"), False),
    "default_group": (("default_group",), False),
    "retention_days": (("retention_days",), False),
    "log_trusted": (("flows", "log_trusted_devices"), False),
    "fail_open": (("enforcement", "fail_open"), True),
    "dns_port": (("dns", "listen_port"), True),
    "web_host": (("web", "host"), True),
}

_CHOICES = {
    "adult_mode": ("strict", "standard", "off"), "youtube": ("strict", "moderate", "off"),
    "unknown_video": ("review", "block", "alert", "off"),
    "downloads": ("off", "review_suspicious", "review_all", "block_suspicious"),
    "unknown_destinations": ("review", "alert", "off"), "web_host": ("127.0.0.1", "0.0.0.0"),
}


def _get(cfg, path, default=None):
    cur = cfg
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _set(d, path, value):
    for k in path[:-1]:
        d = d.setdefault(k, {})
    d[path[-1]] = value


def merge_into(dst: dict, src: dict):
    """Deep-merge src into dst *in place*, so components holding references to
    nested config dicts see the new values."""
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            merge_into(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)


def current(cfg: dict) -> dict:
    """The wizard's view of the running configuration."""
    vals = {}
    for key, (path, _) in _PATHS.items():
        vals[key] = _get(cfg, path)
    vals["family_dns"] = bool(vals["family_dns"])
    vals["categories"] = list(_get(cfg, ("groups", "kids", "categories"), []) or [])
    return vals


def local_path(cfg: dict) -> str:
    return os.path.join(cfg["__base__"], "config.local.yaml")


def validate(values: dict, cfg: dict) -> dict:
    """Clean and check wizard values; raises ValueError with a readable message."""
    out = {}
    for key, val in values.items():
        if key == "categories":
            cats = [c for c in val if c in (cfg.get("categories") or {}) or c in CATEGORY_INFO]
            if "bypass" not in cats:
                cats.append("bypass")          # the way around the filter is never optional
            out[key] = cats
        elif key in _CHOICES:
            if val not in _CHOICES[key]:
                raise ValueError(f"{key}: choose one of {', '.join(_CHOICES[key])}")
            out[key] = val
        elif key in ("safesearch", "family_dns", "fail_open", "log_trusted"):
            out[key] = bool(val)
        elif key in ("escalation_pause", "tamper_pause"):
            out[key] = max(0, min(24 * 60, int(val)))
        elif key == "retention_days":
            out[key] = max(1, min(365, int(val)))
        elif key == "dns_port":
            port = int(val)
            if port not in (53, 5353) and not 1024 < port < 65536:
                raise ValueError("DNS port must be 53, 5353 or above 1024")
            out[key] = port
        elif key == "default_group":
            if val not in cfg["groups"]:
                raise ValueError(f"unknown group {val}")
            out[key] = val
        elif key in _PATHS:
            out[key] = val
    if cfg.get("mode") == "gateway":
        out.pop("dns_port", None)               # the Pi's ports are set by setup-pi.sh
        out.pop("web_host", None)
    return out


def to_overrides(values: dict, cfg: dict) -> dict:
    over: dict = {}
    for key, val in values.items():
        if key == "categories":
            for g in FILTERED_GROUPS:
                if g in cfg["groups"]:
                    _set(over, ("groups", g, "categories"), list(val))
            continue
        if key == "family_dns":
            existing = _get(cfg, ("adult", "family_dns")) or []
            val = (existing or DEFAULT_FAMILY_DNS) if val else []
        _set(over, _PATHS[key][0], val)
    return over


def restart_needed(values: dict, cfg: dict) -> list[str]:
    return [k for k, v in values.items() if k in _PATHS and _PATHS[k][1] and _get(cfg, _PATHS[k][0]) != v]


def save_local(cfg: dict, overrides: dict):
    path = local_path(cfg)
    local = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            local = yaml.safe_load(fh) or {}
    merge_into(local, overrides)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("# Machine-specific settings - written by setup-pi.sh and the dashboard's setup wizard.\n"
                 f"# Last changed {time.strftime('%Y-%m-%d %H:%M')}. Deep-merged over config.yaml.\n")
        yaml.safe_dump(local, fh, sort_keys=False, default_flow_style=False)
    os.replace(tmp, path)


def apply(cfg: dict, values: dict) -> dict:
    """Validate, persist and apply to the live config dict. Returns what changed."""
    values = validate(values, cfg)
    restart = restart_needed(values, cfg)
    overrides = to_overrides(values, cfg)
    save_local(cfg, overrides)
    live = copy.deepcopy(overrides)
    for k in restart:                           # restart-only settings keep running values until then
        path = _PATHS[k][0]
        node = live
        for p in path[:-1]:
            node = node.get(p, {})
        node.pop(path[-1], None)
    merge_into(cfg, live)
    normalize(cfg)
    return {"restart_required": restart, "applied": sorted(values)}
