"""Domain helpers: registrable-domain extraction and grouping of the many
domains a service uses into one name, so usage reads "YouTube: 2h 10m"
rather than a dozen CDN hostnames."""
from __future__ import annotations

import ipaddress

# Multi-label public suffixes we care about (a compact stand-in for the full
# Public Suffix List; good enough for grouping and tunnel detection).
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "nhs.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "com.br", "com.cn", "net.cn", "org.cn", "co.in",
    "co.za", "com.mx", "com.tr", "com.sg", "com.hk", "co.kr", "com.tw", "co.il", "com.ar",
    "github.io", "blogspot.com", "appspot.com", "cloudfront.net", "herokuapp.com",
    "azurewebsites.net", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
    "firebaseapp.com", "web.app", "s3.amazonaws.com", "duckdns.org", "ddns.net", "no-ip.org",
}

SERVICES: dict[str, tuple[str, list[str]]] = {
    "youtube": ("YouTube", ["youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
                            "youtube-nocookie.com", "youtubei.googleapis.com", "youtubekids.com"]),
    "netflix": ("Netflix", ["netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com",
                            "nflxso.net", "netflix.net"]),
    "tiktok": ("TikTok", ["tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com",
                          "tiktokv.us", "byteoversea.com", "ibytedtos.com", "musical.ly"]),
    "instagram": ("Instagram", ["instagram.com", "cdninstagram.com"]),
    "facebook": ("Facebook", ["facebook.com", "fbcdn.net", "fb.com", "facebook.net", "messenger.com"]),
    "whatsapp": ("WhatsApp", ["whatsapp.com", "whatsapp.net"]),
    "snapchat": ("Snapchat", ["snapchat.com", "sc-cdn.net", "sc-static.net"]),
    "discord": ("Discord", ["discord.com", "discord.gg", "discordapp.com", "discordapp.net",
                            "discord.media", "discord.co"]),
    "roblox": ("Roblox", ["roblox.com", "rbxcdn.com", "rbx.com"]),
    "minecraft": ("Minecraft", ["minecraft.net", "mojang.com", "minecraftservices.com"]),
    "epicgames": ("Epic Games / Fortnite", ["epicgames.com", "epicgames.dev", "fortnite.com",
                                            "unrealengine.com"]),
    "twitch": ("Twitch", ["twitch.tv", "ttvnw.net", "jtvnw.net", "twitchsvc.net"]),
    "spotify": ("Spotify", ["spotify.com", "scdn.co", "spotifycdn.com"]),
    "reddit": ("Reddit", ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"]),
    "x": ("X / Twitter", ["x.com", "twitter.com", "twimg.com", "t.co"]),
    "pinterest": ("Pinterest", ["pinterest.com", "pinimg.com"]),
    "disneyplus": ("Disney+", ["disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com"]),
    "primevideo": ("Prime Video", ["primevideo.com", "aiv-cdn.net", "aiv-delivery.net",
                                   "amazonvideo.com", "pv-cdn.net"]),
    "steam": ("Steam", ["steampowered.com", "steamcommunity.com", "steamcontent.com",
                        "steamstatic.com", "steamserver.net"]),
    "xbox": ("Xbox", ["xbox.com", "xboxlive.com", "xboxservices.com"]),
    "playstation": ("PlayStation", ["playstation.com", "playstation.net",
                                    "sonyentertainmentnetwork.com"]),
    "nintendo": ("Nintendo", ["nintendo.com", "nintendo.net"]),
    "zoom": ("Zoom", ["zoom.us", "zoom.com", "zoomgov.com"]),
    "teams": ("Microsoft Teams", ["teams.microsoft.com", "teams.live.com"]),
    "meet": ("Google Meet", ["meet.google.com"]),
    "apple": ("Apple / iCloud", ["apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com",
                                 "cdn-apple.com", "aaplimg.com"]),
    "microsoft": ("Microsoft", ["microsoft.com", "windowsupdate.com", "live.com", "office.com",
                                "msftconnecttest.com", "msn.com", "skype.com", "bing.com"]),
    "google": ("Google", ["google.com", "gstatic.com", "googleapis.com", "gvt1.com", "gvt2.com",
                          "googleusercontent.com", "android.com", "google.co.uk"]),
}

_SUFFIX_TO_SERVICE: dict[str, str] = {}
for _key, (_label, _doms) in SERVICES.items():
    for _d in _doms:
        _SUFFIX_TO_SERVICE[_d] = _key


def normalize_name(name: str | None) -> str | None:
    if not name:
        return None
    return name.strip().rstrip(".").lower() or None


def is_ip_literal(name: str) -> bool:
    try:
        ipaddress.ip_address(name.strip("[]"))
        return True
    except ValueError:
        return False


def registrable_domain(name: str | None) -> str | None:
    name = normalize_name(name)
    if not name:
        return None
    if is_ip_literal(name):
        return name
    labels = name.split(".")
    if len(labels) <= 2:
        return name
    last3 = ".".join(labels[-3:])
    last2 = ".".join(labels[-2:])
    # check the longest matching multi-label suffix first
    if ".".join(labels[-3:]) in _MULTI_SUFFIXES and len(labels) >= 4:
        return ".".join(labels[-4:])
    if last2 in _MULTI_SUFFIXES:
        return last3
    return last2


def service_for(name: str | None) -> str | None:
    """Service key for a hostname: a known service ('youtube') or the
    registrable domain ('example.com')."""
    name = normalize_name(name)
    if not name:
        return None
    labels = name.split(".")
    for i in range(len(labels) - 1):
        hit = _SUFFIX_TO_SERVICE.get(".".join(labels[i:]))
        if hit:
            return hit
    return registrable_domain(name)


def service_label(key: str | None) -> str:
    if not key:
        return "Unidentified"
    if key in SERVICES:
        return SERVICES[key][0]
    if key.startswith("ip:"):
        return key[3:]
    return key


def name_matches(name: str, candidates) -> bool:
    """True if `name` equals one of the candidates or shares its registrable domain."""
    name = normalize_name(name)
    if not name:
        return False
    reg = registrable_domain(name)
    for c in candidates:
        c = normalize_name(c)
        if c and (c == name or registrable_domain(c) == reg):
            return True
    return False
