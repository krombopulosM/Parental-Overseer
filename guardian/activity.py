"""What is a device doing right now? Inferred from the *shape* of its traffic.

Almost everything is encrypted, so we can't read content - but different
activities move data in very different ways, and the kernel already counts
every packet and byte per connection:

  gaming      small packets (< ~350 B), steady 10-60 per second in BOTH
              directions, low bandwidth, no pauses (usually UDP)
  call        steady and roughly symmetrical, medium bandwidth, UDP
  video       big downstream bursts with pauses between (players fetch a few
              seconds of video at a time), or a known video service
  download    one-way, sustained, high bandwidth, no pauses
  music       a known music service, low steady bandwidth
  social/chat a known social or messaging service
  browsing    short, small, many different sites

Each connection gets a class with a confidence and reasons; a device's
connections are combined into one sentence, e.g.
"Likely playing an online game with YouTube in the background".
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .services import service_label

CLASSES = {
    "video": "Watching video", "gaming": "Gaming", "browsing": "Browsing", "download": "Downloading",
    "social": "Social & messaging", "music": "Music", "call": "Calls", "other": "Other",
}

SERVICE_CATEGORY = {
    "youtube": "video", "netflix": "video", "twitch": "video", "disneyplus": "video", "primevideo": "video",
    "tiktok": "video",
    "instagram": "social", "facebook": "social", "snapchat": "social", "x": "social", "reddit": "social",
    "pinterest": "social", "whatsapp": "social", "discord": "social",
    "spotify": "music",
    "roblox": "gaming", "minecraft": "gaming", "epicgames": "gaming", "steam": "gaming", "xbox": "gaming",
    "playstation": "gaming", "nintendo": "gaming",
    "zoom": "call", "teams": "call", "meet": "call",
}

WINDOW = 30          # seconds of history used for a judgement


@dataclass
class Features:
    seconds: float = 0
    bytes_up: int = 0
    bytes_down: int = 0
    pkts_up: int = 0
    pkts_down: int = 0
    active_ticks: int = 0
    ticks: int = 0
    peak_down: float = 0          # bytes/s in the busiest tick

    @property
    def rate_down(self):
        return self.bytes_down / self.seconds if self.seconds else 0

    @property
    def rate_up(self):
        return self.bytes_up / self.seconds if self.seconds else 0

    @property
    def pps_up(self):
        return self.pkts_up / self.seconds if self.seconds else 0

    @property
    def pps_down(self):
        return self.pkts_down / self.seconds if self.seconds else 0

    @property
    def avg_pkt_up(self):
        return self.bytes_up / self.pkts_up if self.pkts_up else 0

    @property
    def avg_pkt_down(self):
        return self.bytes_down / self.pkts_down if self.pkts_down else 0

    @property
    def idle_fraction(self):
        return 1 - self.active_ticks / self.ticks if self.ticks else 1

    @property
    def total(self):
        return self.bytes_up + self.bytes_down


def features(ticks, now, window=WINDOW) -> Features:
    """ticks: iterable of (ts, seconds, up_bytes, down_bytes, up_pkts, down_pkts)."""
    f = Features()
    for ts, secs, ub, db, up, dp in ticks:
        if ts < now - window:
            continue
        f.seconds += secs
        f.bytes_up += ub
        f.bytes_down += db
        f.pkts_up += up
        f.pkts_down += dp
        f.ticks += 1
        if ub + db > 1500:
            f.active_ticks += 1
        if secs:
            f.peak_down = max(f.peak_down, db / secs)
    return f


@dataclass
class FlowActivity:
    cls: str
    confidence: int
    why: list = field(default_factory=list)


def classify_flow(proto: str, service: str | None, f: Features) -> FlowActivity | None:
    """None = idle. Shape first (it can't be faked by a name), service second."""
    if f.ticks == 0 or f.total < 4000:
        return None
    cat = SERVICE_CATEGORY.get(service or "")
    steady = f.idle_fraction <= 0.2
    small = f.avg_pkt_up < 350 and (f.avg_pkt_down < 400 or f.pps_down < 1)
    both_ways = f.pps_up >= 8 and f.pps_down >= 8
    ratio = f.rate_up / f.rate_down if f.rate_down else 99

    if proto == "udp" and both_ways and small and f.rate_down < 150_000 and steady:
        return FlowActivity("gaming", 85 if cat == "gaming" else 75,
                            [f"{f.pps_up:.0f}/{f.pps_down:.0f} small packets a second each way, no pauses"])
    if proto == "udp" and both_ways and f.rate_down >= 25_000 and f.rate_up >= 25_000 and 0.25 <= ratio <= 4:
        return FlowActivity("call", 80 if cat == "call" else 70,
                            [f"steady two-way stream (~{f.rate_down / 1000:.0f} kB/s each way)"])
    if cat == "video" and f.bytes_down > 200_000:
        return FlowActivity("video", 90, [f"{service_label(service)} sending video"])
    if f.rate_down >= 250_000 and f.idle_fraction < 0.25 and ratio < 0.06 and f.bytes_down >= 3_000_000:
        conf = 85 if cat is None else 70
        return FlowActivity("download", conf, [f"one-way, sustained {f.rate_down / 1e6:.1f} MB/s with no pauses"])
    if f.idle_fraction >= 0.3 and f.peak_down >= 400_000 and f.avg_pkt_down > 900 and f.bytes_down > 1_000_000:
        return FlowActivity("video", 60 if cat is None else 75,
                            ["large bursts with pauses between - the pattern of a video player buffering"])
    if cat in ("social", "music", "gaming", "call"):
        return FlowActivity(cat, 70, [f"{service_label(service)}"])
    if cat == "video":
        return FlowActivity("video", 70, [f"{service_label(service)}"])
    if f.rate_down >= 250_000 and f.bytes_down >= 3_000_000:
        return FlowActivity("download", 60, [f"large transfer, {f.rate_down / 1e6:.1f} MB/s"])
    if proto == "tcp":
        return FlowActivity("browsing", 55, ["short, small web traffic"])
    return FlowActivity("other", 40, [f"{proto} traffic"])


# ------------------------------------------------------------------ per-device summary

_FOREGROUND = ["call", "gaming", "video", "download", "social", "browsing", "music", "other"]


def _name(items, fallback, category=None):
    """Most-used service name; with `category`, only names *known* to be that kind
    of service count (a game server reached as 'vps.example' is 'an online game')."""
    labels = [service_label(s) for s, _ in sorted(items.items(), key=lambda kv: -kv[1])
              if s and not s.startswith("ip:") and (category is None or SERVICE_CATEGORY.get(s) == category)]
    return labels[0] if labels else fallback


def summarize(flows: list) -> dict:
    """flows: list of (FlowActivity, service, bytes_in_window, domain). Returns the headline."""
    by: dict[str, dict] = {}
    for act, service, nbytes, domain in flows:
        if act is None:
            continue
        b = by.setdefault(act.cls, {"bytes": 0, "services": {}, "conf": 0, "why": [], "domains": {}})
        b["bytes"] += nbytes
        b["services"][service] = b["services"].get(service, 0) + nbytes
        if domain:
            b["domains"][domain] = b["domains"].get(domain, 0) + nbytes
        if act.confidence > b["conf"]:
            b["conf"], b["why"] = act.confidence, act.why
    if not by:
        return {"headline": "Idle", "activity": "idle", "confidence": 60, "why": ["no meaningful traffic"],
                "background": [], "classes": {}}

    fg = next(c for c in _FOREGROUND if c in by)
    texts = {
        "call": lambda b: f"on a call ({_name(b['services'], 'voice/video', 'call')})",
        "gaming": lambda b: "playing " + _name(b["services"], "an online game", "gaming"),
        "video": lambda b: "watching " + _name(b["services"], "a video", "video"),
        "download": lambda b: "downloading a file from " + _name(b["domains"] or b["services"], "an unknown site"),
        "social": lambda b: "on " + _name(b["services"], "social media"),
        "browsing": lambda b: "browsing" + (f" ({_name(b['services'], '')})" if _name(b["services"], "") else ""),
        "music": lambda b: "listening to " + _name(b["services"], "music", "music"),
        "other": lambda b: "using the internet",
    }
    headline = "Likely " + texts[fg](by[fg])
    background = []
    for c in ("video", "music", "download", "call"):
        if c in by and c != fg:
            background.append(c)
    if background:
        parts = []
        for c in background:
            name = _name(by[c]["services"], {"video": "a video", "music": "music", "call": "voice/video",
                                             "download": "a download"}[c], c)
            parts.append({"video": f"{name}", "music": f"{name}", "download": "a download",
                          "call": f"a call ({name})"}[c])
        headline += " with " + " and ".join(parts) + " in the background"
    elif fg in ("video", "gaming") and "social" in by:
        headline += " (also on " + _name(by["social"]["services"], "social media") + ")"
    why = list(by[fg]["why"])
    for c in background:
        why += by[c]["why"]
    conf = by[fg]["conf"]
    if background:
        conf = min(conf, min(by[c]["conf"] for c in background))
    return {"headline": headline, "activity": fg, "confidence": conf, "why": why,
            "background": background,
            "classes": {c: v["bytes"] for c, v in by.items()}}
