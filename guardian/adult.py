"""Stricter adult-content protection - layers that don't depend on a site
already being on a blocklist, and that close the indirect routes to it.

  1. SafeSearch / Restricted Mode, enforced in DNS: Google, Bing, DuckDuckGo
     and Yandex are answered with their locked "safe" addresses; YouTube with
     Restricted Mode. These are the search engines' own documented mechanisms.
  2. Family DNS second opinion: filtered devices' lookups are resolved through
     a family-filtering resolver (Cloudflare for Families by default), whose
     classifier covers millions of sites, including brand-new ones. An answer
     of 0.0.0.0 means "adult or malware" and the name is blocked.
  3. Site-name heuristics: strong adult terms anywhere in a name are blocked;
     weaker terms (matched as whole words, so Essex/Sussex are safe) are
     blocked in strict mode.
  4. Proxies that hide the real site: Google Translate (*.translate.goog) and
     the AMP cache (*.cdn.ampproject.org) encode the original site in the
     hostname - it's decoded and checked like any other site.
  5. Unknown video: streaming video from a site that isn't a known video
     service is cut and held for review (see downloads.py) - this catches
     adult and pirate streaming sites that no list knows about yet.

Mirrors (web archives, page caches) and search engines whose SafeSearch can't
be locked are handled as ordinary categories (blocklists/builtin/*.txt).
"""
from __future__ import annotations

import re

from .services import registrable_domain

STRONG = ["porn", "xxx", "hentai", "nsfw", "xvideo", "xnxx", "rule34", "camgirl", "sexcam", "livesex",
          "sextube", "freesex", "milf", "bdsm", "fetish", "erotic", "nudes", "onlyfans", "fansly",
          "chaturbate", "stripchat", "bongacams", "brazzers", "redgifs", "spankbang", "youjizz", "hclips",
          "upskirt", "voyeur", "incest", "gangbang", "blowjob", "deepthroat", "creampie", "nsfwgif"]
# Whole-word only, strict mode only. Deliberately excludes words common in innocent
# names ("adult" learning, comic "strip", traffic "cams").
WEAK = ["sex", "sexy", "nude", "naked", "escort", "escorts", "boobs", "tits", "horny", "slut", "nympho",
        "hookup", "18plus", "camsex", "lewd"]

_GOOGLE = re.compile(r"^(www\.)?google\.(com|[a-z]{2}|co\.[a-z]{2}|com\.[a-z]{2})$")
_YANDEX = re.compile(r"^(www\.)?yandex\.(ru|com|by|kz|ua|com\.tr|fr|eu|uz|az|md|lv|lt|ee|tm|tj|com\.ge|co\.il|com\.am)$")
_YOUTUBE = {"www.youtube.com", "m.youtube.com", "youtubei.googleapis.com", "youtube.googleapis.com",
            "www.youtube-nocookie.com", "youtube.com"}
_PROXY_SUFFIXES = (".translate.goog", ".cdn.ampproject.org")


def _decode_dashed(label: str) -> str:
    """Google's encoding: '-' separates labels, '--' is a literal hyphen."""
    return label.replace("--", "\x00").replace("-", ".").replace("\x00", "-")


class AdultGuard:
    def __init__(self, cfg: dict, lists, alerts=None):
        a = cfg.get("adult") or {}
        self.cfg, self.lists, self.alerts = cfg, lists, alerts
        self.default_mode = a.get("mode", "strict")
        self.safesearch = bool(a.get("safesearch", True))
        self.youtube = a.get("youtube_restricted", "strict")
        self.family_dns = list(a.get("family_dns") or [])
        self.blocked_answers = set(a.get("family_blocked_answers") or ["0.0.0.0", "::"])
        self.strong = [w.lower() for w in a.get("strong_terms") or STRONG]
        self.weak = {w.lower() for w in a.get("weak_terms") or WEAK}
        self.unknown_video = a.get("unknown_video", "review")
        self.video_sites = {d.lower() for d in a.get("video_sites") or []}

    # ------------------------------------------------------------ policy
    def mode(self, ctx) -> str:
        if not ctx.filtered:
            return "off"
        m = (ctx.g or {}).get("adult_protection") or self.default_mode
        return m if m in ("strict", "standard", "off") else "strict"

    def unknown_video_policy(self, group_cfg) -> str:
        if not group_cfg or not group_cfg.get("filtered"):
            return "off"
        m = group_cfg.get("adult_protection") or self.default_mode
        if m == "off":
            return "off"
        if m == "standard" and self.unknown_video == "review":
            return "alert"
        return self.unknown_video

    # ------------------------------------------------------------ 1. SafeSearch
    def safesearch_target(self, qname: str, ctx) -> str | None:
        if not self.safesearch or self.mode(ctx) == "off":
            return None
        if _GOOGLE.match(qname):
            return "forcesafesearch.google.com"
        if qname in ("www.bing.com", "bing.com"):
            return "strict.bing.com"
        if qname in ("duckduckgo.com", "www.duckduckgo.com", "start.duckduckgo.com", "html.duckduckgo.com"):
            return "safe.duckduckgo.com"
        if _YANDEX.match(qname):
            return "familysearch.yandex.ru"
        if qname in _YOUTUBE and self.youtube in ("strict", "moderate"):
            return "restrict.youtube.com" if self.youtube == "strict" else "restrictmoderate.youtube.com"
        return None

    # ------------------------------------------------------------ 2. family DNS
    def use_family_dns(self, ctx) -> bool:
        return bool(self.family_dns) and self.mode(ctx) != "off"

    def family_flagged(self, reply_ips) -> bool:
        return bool(reply_ips) and all(ip in self.blocked_answers for ip in reply_ips)

    # ------------------------------------------------------------ 3. names
    def keyword_hit(self, name: str):
        """('strong'|'weak', term) or None. Strong terms match anywhere in a
        label; weak terms only as whole words."""
        name = name.lower().rstrip(".")
        labels = name.split(".")
        reg = registrable_domain(name) or name
        tld_part = reg.split(".", 1)[1] if "." in reg else ""
        body = [l for l in labels[: len(labels) - (tld_part.count(".") + 1)]] or labels
        for label in body:
            for t in self.strong:
                if t in label:
                    return "strong", t
        for label in body:
            for tok in re.split(r"[^a-z0-9]+", label):
                if tok in self.weak:
                    return "weak", tok
        return None

    def decode_proxy(self, name: str) -> str | None:
        name = name.lower().rstrip(".")
        for suf in _PROXY_SUFFIXES:
            if name.endswith(suf):
                first = name[: -len(suf)].split(".")[-1]
                origin = _decode_dashed(first)
                return origin if "." in origin else None
        return None

    def check_name(self, ctx, name: str):
        """Returns (kind, reason, base_confidence) if this name should be blocked
        for adult reasons beyond the category lists, else None."""
        mode = self.mode(ctx)
        if mode == "off" or not name:
            return None
        origin = self.decode_proxy(name)
        if origin:
            cat = self.lists.category_match(origin, ["adult"])
            hit = self.keyword_hit(origin)
            if cat or (hit and (hit[0] == "strong" or mode == "strict")):
                why = "a known adult site" if cat else f"its name contains '{hit[1]}'"
                via = "Google Translate" if "translate.goog" in name else "the AMP page cache"
                return ("adult_proxy", f"Tried to open {origin} through {via} - {why}", 90)
        hit = self.keyword_hit(name)
        if hit:
            level, term = hit
            if level == "strong":
                return ("adult_keyword", f"Site name contains the adult term '{term}'", 75)
            if mode == "strict":
                return ("adult_keyword", f"Site name contains '{term}' (strict mode)", 45)
        return None

    def is_known_video_site(self, name: str | None) -> bool:
        if not name:
            return False
        reg = registrable_domain(name)
        return reg in self.video_sites or name in self.video_sites
