"""Stricter adult-content protection."""
import os
import socket

import pytest
from conftest import ROOT, Conn, client_hello

from guardian.adult import AdultGuard
from guardian.config import load_config


class Ctx:
    def __init__(self, filtered=True, mode=None):
        self.filtered = filtered
        self.g = {"filtered": filtered, "categories": ["adult", "unsafe_search"],
                  **({"adult_protection": mode} if mode else {})}
        self.device_id, self.ip, self.group = "kid", "192.168.50.23", "kids"


@pytest.fixture
def guard(env):
    return AdultGuard(env.cfg, env.lists, env.alerts)


@pytest.mark.parametrize("name,want", [
    ("www.freepornclips.example", "strong"),
    ("hotxxxvideos.example", "strong"),
    ("cdn.hentai-haven.example", "strong"),
    ("hot-sex-videos.example", "weak"),
    ("nude.example", "weak"),
    ("www.essex.ac.uk", None), ("middlesex.ac.uk", None), ("www.sussex.ac.uk", None),
    ("analytics.google.com", None), ("adult-learning.gov.uk", None), ("comic-strip.example", None),
    ("sexetc.org", None), ("traffic-cams.example", None), ("www.therapist.example", None),
])
def test_keyword_heuristics(guard, name, want):
    hit = guard.keyword_hit(name)
    assert (hit[0] if hit else None) == want, hit


def test_strict_vs_standard(guard):
    assert guard.check_name(Ctx(), "hot-sex-videos.example")[0] == "adult_keyword"
    assert guard.check_name(Ctx(mode="standard"), "hot-sex-videos.example") is None
    assert guard.check_name(Ctx(mode="standard"), "freepornclips.example")[0] == "adult_keyword"
    assert guard.check_name(Ctx(filtered=False), "freepornclips.example") is None      # adults untouched


def test_proxy_decoding(guard):
    assert guard.decode_proxy("www-pornhub-com.translate.goog") == "www.pornhub.com"
    assert guard.decode_proxy("my--site-example-com.translate.goog") == "my-site.example.com"
    assert guard.decode_proxy("www-example-org.cdn.ampproject.org") == "www.example.org"
    assert guard.decode_proxy("www.example.org") is None
    kind, reason, base = guard.check_name(Ctx(), "www-pornhub-com.translate.goog")
    assert kind == "adult_proxy" and "pornhub.com" in reason and "Google Translate" in reason
    assert guard.check_name(Ctx(), "en-wikipedia-org.translate.goog") is None              # benign translation


@pytest.mark.parametrize("q,target", [
    ("www.google.com", "forcesafesearch.google.com"), ("www.google.co.uk", "forcesafesearch.google.com"),
    ("google.com.au", "forcesafesearch.google.com"), ("www.bing.com", "strict.bing.com"),
    ("duckduckgo.com", "safe.duckduckgo.com"), ("www.youtube.com", "restrict.youtube.com"),
    ("youtubei.googleapis.com", "restrict.youtube.com"), ("yandex.ru", "familysearch.yandex.ru"),
    ("mail.google.com", None), ("maps.google.com", None),
])
def test_safesearch_targets(guard, q, target):
    assert guard.safesearch_target(q, Ctx()) == target
    assert guard.safesearch_target(q, Ctx(filtered=False)) is None


def test_youtube_moderate(env):
    env.cfg["adult"]["youtube_restricted"] = "moderate"
    g = AdultGuard(env.cfg, env.lists, env.alerts)
    assert g.safesearch_target("m.youtube.com", Ctx()) == "restrictmoderate.youtube.com"


def test_sni_keyword_and_proxy_blocked_inline(env, guard):
    env.insp.adult = guard
    env.dnscache.record("192.168.50.23", ["cdn.shared.example"], [("151.101.1.1", 300)])
    v = Conn(env.insp, "192.168.50.23", "151.101.1.1", 443).open_and_send(client_hello("www.freepornclips.example"))
    assert v.kind == "adult_keyword" and v.action == "reset"


# ------------------------------------------------------------------ resolver end to end
class Upstream:
    """Stub DNS server. flagged names answer 0.0.0.0 (family-filter style)."""

    def __init__(self, flagged=()):
        from dnslib import RR
        from dnslib.server import BaseResolver, DNSLogger, DNSServer
        flagged = set(flagged)

        class R(BaseResolver):
            def resolve(self, req, handler):
                r = req.reply()
                name = str(req.q.qname).rstrip(".")
                ip = "0.0.0.0" if name in flagged else ("216.239.38.120" if "forcesafesearch" in name
                                                         else "5.6.7.8")
                r.add_answer(*RR.fromZone(f"{name}. 60 A {ip}"))
                return r
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        DNSServer(R(), address="127.0.0.1", port=self.port, logger=DNSLogger("-request,-reply")).start_thread()


def make_resolver(tmp_path, family_port=None):
    from dnslib import DNSRecord
    from test_components import make_stack
    from guardian.dnscache import DnsCache
    from guardian.resolver import DnsTunnelDetector, GuardianResolver, QueryStats
    from guardian.schedule import Scheduler
    normal = Upstream()
    (tmp_path / "adult.txt").write_text("pornhub.com\n")
    (tmp_path / "mirrors.txt").write_text("archive.ph\n")
    (tmp_path / "unsafe.txt").write_text("search.brave.com\n")
    cfg, db, lists, alerts, policy = make_stack(tmp_path)
    cfg["categories"] = {"adult": {"files": [str(tmp_path / "adult.txt")]},
                         "mirrors": {"files": [str(tmp_path / "mirrors.txt")]},
                         "unsafe_search": {"files": [str(tmp_path / "unsafe.txt")]}}
    cfg["groups"]["kids"]["categories"] = ["adult", "mirrors", "unsafe_search"]
    lists.load()
    cfg["dns"].update(upstreams=["127.0.0.1"], upstream_port=normal.port)
    fam = Upstream(flagged={"spicy-new-site.example", "unlisted-adult.example"}) if family_port is None else None
    cfg["adult"]["family_dns"] = ["127.0.0.1"]
    cache = DnsCache()
    res = GuardianResolver(cfg, policy, lists, cache, db, alerts, Scheduler(db, policy), QueryStats(),
                           DnsTunnelDetector({}, alerts))
    res.adult = AdultGuard(cfg, lists, alerts)
    # family DNS lives on its own port in the test
    real_forward = res.forward
    port = fam.port if fam else family_port

    def forward(request, upstreams=None):
        if upstreams:
            res.up_port, saved = port, res.up_port
            try:
                return real_forward(request, upstreams)
            finally:
                res.up_port = saved
        return real_forward(request)
    res.forward = forward

    class H:
        client_address = ("192.168.50.23", 3333)

    def ask(name, qt="A"):
        r = res.resolve(DNSRecord.question(name, qt), H())
        return r.header.rcode, [str(a.rdata).rstrip(".") for a in r.rr]
    return res, db, cache, ask


def test_resolver_adult_layers(tmp_path):
    res, db, cache, ask = make_resolver(tmp_path)
    assert ask("www.google.com") == (0, ["forcesafesearch.google.com", "216.239.38.120"])
    assert cache.resolved_by("192.168.50.23", "216.239.38.120") == {"www.google.com", "forcesafesearch.google.com"}
    assert ask("ok.example") == (0, ["5.6.7.8"])
    assert ask("spicy-new-site.example")[0] == 3                 # family DNS flagged an unlisted site
    assert ask("www.pornhub.com")[0] == 3
    assert ask("hotxxxvideos.example")[0] == 3
    assert ask("www-pornhub-com.translate.goog")[0] == 3
    # an UNLISTED adult site through Google Translate: decoded, then checked with the family filter
    assert ask("unlisted--adult-example.translate.goog")[0] == 3
    assert ask("en-wikipedia-org.translate.goog")[0] == 0          # a benign translation still works
    assert ask("archive.ph")[0] == 3
    assert ask("search.brave.com")[0] == 3
    db.flush()
    kinds = {a["kind"] for a in db.alerts()}
    assert {"adult_family_dns", "adult_site", "adult_keyword", "adult_proxy", "content_mirror",
            "unsafe_search"} <= kinds


def test_family_dns_unreachable_falls_back(tmp_path):
    res, db, cache, ask = make_resolver(tmp_path, family_port=9)      # nothing listens on port 9
    assert ask("ok.example") == (0, ["5.6.7.8"])
    assert res.counters["family_dns_unreachable"] == 1


def test_unlocked_google_address_is_refused(env):
    """Pointing www.google.com at a normal Google address (hosts file, own DNS) to skip
    locked SafeSearch: a direct connection to a SafeSearch site is refused, while other
    direct connections to real sites are fine."""
    from conftest import Conn, client_hello
    env.insp.adult = AdultGuard(env.cfg, env.lists, env.alerts)
    env.cfg["groups"]["quarantine"]["categories"].append("unsafe_search")     # SafeSearch locked for this group
    v = Conn(env.insp, "192.168.1.23", "142.250.1.1", 443).open_and_send(client_hello("www.google.com"))
    assert (v.action, v.kind) == ("reset", "no_dns")
    v = Conn(env.insp, "192.168.1.23", "93.184.216.34", 443, sport=40001).open_and_send(client_hello("www.example.com"))
    assert v.action == "accept"
    env.dnscache.record("192.168.1.23", ["forcesafesearch.google.com"], [("216.239.38.120", 300)])
    v = Conn(env.insp, "192.168.1.23", "216.239.38.120", 443, sport=40002).open_and_send(client_hello("www.google.com"))
    assert v.action == "accept"                                  # the locked address we handed out
