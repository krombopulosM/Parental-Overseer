"""Speed: connections released as soon as they're checked, DNS answers cached,
and VPNs reported instantly in watch-only mode."""
import os
import socket
import threading
import time

import pytest
from dnslib import QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import BaseResolver, DNSServer

from conftest import Conn, client_hello, tcp
from guardian.inspector import ACCEPT

KID = "192.168.50.23"
SITE, VPS = "93.184.216.34", "45.32.1.1"


def resolve(env, name, ip, client=KID):
    env.dnscache.record(client, [name], [(ip, 300)])


# ------------------------------------------------------------------ released once checked
def test_connection_is_marked_done_after_the_client_hello(env):
    resolve(env, "www.example.com", SITE)
    c = Conn(env.insp, KID, SITE, 443)
    assert c.syn().kind != "done"                                    # not decided yet
    v = c.send(client_hello("www.example.com"))
    assert (v.action, v.kind) == (ACCEPT, "done")                     # decided: release it


def test_learned_fingerprint_still_checked_with_done(env):
    """The final-allow verdict must not skip the VPN-fingerprint check."""
    hello = client_hello("relay.unknown.example")
    from guardian.protocols import parse_client_hello
    ja4 = parse_client_hello(hello).ja4

    class Rep:
        def known(self, *a):
            return False, "unknown"

        def bad_label(self, j):
            return "a VPN app" if j == ja4 else None

        def learn_bad(self, *a):
            pass
    env.insp.reputation = Rep()
    resolve(env, "relay.unknown.example", VPS)
    assert Conn(env.insp, KID, VPS, 443).open_and_send(hello).kind == "vpn_fingerprint"


def test_nfq_marks_finished_connections(env):
    from guardian.gateway.nfq import NfqRunner
    from guardian.gateway.nft import M_DONE
    resolve(env, "www.example.com", SITE)

    class P:
        def __init__(self, raw):
            self.raw, self.mark, self.result = raw, None, None

        def get_payload(self):
            return self.raw

        def get_hw(self):
            return None

        def set_mark(self, m):
            self.mark = m

        def accept(self):
            self.result = "accept"

        def drop(self):
            self.result = "drop"

        def repeat(self):
            self.result = "repeat"
    r = NfqRunner(env.insp, 0)
    syn = P(tcp(KID, SITE, 40000, 443, 5000, 0x02))
    r._cb(syn)
    assert syn.result == "accept" and syn.mark is None
    hello = P(tcp(KID, SITE, 40000, 443, 5001, 0x18, client_hello("www.example.com")))
    r._cb(hello)
    assert hello.result == "accept" and hello.mark == M_DONE


# ------------------------------------------------------------------ DNS cache
class _Upstream(BaseResolver):
    def __init__(self):
        self.asked = 0
        self.fail = False

    def resolve(self, request, handler):
        self.asked += 1
        reply = request.reply()
        if self.fail:
            reply.header.rcode = RCODE.SERVFAIL
        elif str(request.q.qname).startswith("ok."):
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("5.6.7.8"), ttl=120))
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


@pytest.fixture
def upstream():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    up = _Upstream()
    srv = DNSServer(up, address="127.0.0.1", port=port)
    srv.start_thread()
    yield up, port
    srv.stop()


def _resolver(env, port):
    from guardian.resolver import DnsTunnelDetector, GuardianResolver, QueryStats

    class Sched:
        def is_paused(self, *a):
            return False, ""
    env.cfg["dns"].update(upstreams=["127.0.0.1"], upstream_port=port)
    env.cfg["adult"]["family_dns"] = []
    return GuardianResolver(env.cfg, env.policy, env.lists, env.dnscache, None, env.alerts, Sched(),
                            QueryStats(), DnsTunnelDetector({}, env.alerts))


def test_dns_cache_answers_repeats_locally(env, upstream):
    up, port = upstream
    res = _resolver(env, port)
    q = DNSRecord.question("ok.example")
    first = res.forward(q)
    q2 = DNSRecord.question("ok.example")
    second = res.forward(q2)
    assert up.asked == 1 and res.counters["cache_hits"] == 1
    assert second.header.id == q2.header.id and str(second.q.qname) == "ok.example."
    assert [str(r.rdata) for r in second.rr] == ["5.6.7.8"] and 1 <= second.rr[0].ttl <= 120
    res.forward(DNSRecord.question("nope.example"))
    res.forward(DNSRecord.question("nope.example"))
    assert up.asked == 2                                              # NXDOMAIN cached briefly too
    up.fail = True
    res.forward(DNSRecord.question("ok.other"))
    res.forward(DNSRecord.question("ok.other"))
    assert up.asked == 4                                              # failures never cached


def test_filtering_still_applies_to_cached_answers(env, upstream):
    up, port = upstream
    res = _resolver(env, port)

    class H:
        client_address = (KID, 5353)
    env.policy.forced_group = "adults"
    r = res.resolve(DNSRecord.question("ok.example"), H())
    assert r.header.rcode == 0 and up.asked == 1
    env.policy.forced_group = None                                     # the same answer, a filtered device
    env.lists.categories.setdefault("adult", None)
    r = res.resolve(DNSRecord.question("pornhub.com"), H())
    assert r.header.rcode == 3                                         # policy decided before any cache
    r = res.resolve(DNSRecord.question("ok.example"), H())
    assert r.header.rcode == 0 and up.asked == 1                       # served from the cache
    assert env.dnscache.resolved_by(KID, "5.6.7.8") == {"ok.example"}  # still recorded for this device


# ------------------------------------------------------------------ instant reporting in watch-only mode
def test_watch_only_reports_vpn_on_the_first_packet(env):
    assert env.insp.dry_run is True                                   # test config is monitor mode
    env.insp.observe(tcp(KID, "185.159.157.5", 40000, 443, 1, 0x02))
    a = [x for x in env.alerts.memory if x["kind"] == "vpn_server"]
    assert a and a[0]["action"] == "would block (watch only)"


def test_watch_only_direct_address_check_only_for_our_dns_users(env):
    env.cfg["protections"]["direct_ip"] = "strict"                   # judged on the first packet
    env.insp.dns_users = lambda ip: False                            # this device uses its own DNS
    env.insp.observe(tcp(KID, VPS, 40001, 443, 1, 0x02))
    assert "no_dns" not in env.kinds()                                # otherwise everything would be flagged
    env.insp.dns_users = lambda ip: True                             # uses the gateway's DNS
    env.insp.observe(tcp(KID, VPS, 40002, 443, 1, 0x02))
    assert "no_dns" in env.kinds()
    env.insp.observe(tcp("8.8.8.8", KID, 443, 40003, 1, 0x02))        # not from a home device: ignored


# ------------------------------------------------------------------ behaviour detector: time to notice a tunnel
class _Rec:
    """A connection as the flow monitor sees it, growing at `rate` bytes/s."""

    def __init__(self, t0, rate, domain=None):
        self.t0, self.rate, self.now = t0, rate, t0
        self.device_id, self.client_ip, self.group = "aa:bb:cc:00:00:09", KID, "kids"
        self.proto, self.dst_ip, self.dst_port = "tcp", "194.180.34.11", 443
        self.domain, self.service, self.ja4 = domain, None, None
        self.filtered, self.flagged, self.verdict = True, False, None

    @property
    def duration(self):
        return self.now - self.t0

    @property
    def total(self):
        return int(self.duration * self.rate)

    def window_bytes(self, now, window):
        return int(min(window, now - self.t0) * self.rate)


def _time_to_detect(detector_cfg, rate=130_000, domain=None, limit=300):
    from guardian.config import load_config
    from guardian.detector import Detector
    from conftest import ROOT
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg["detector"].update(detector_cfg)
    t0 = 1_000_000.0
    rec = _Rec(t0, rate, domain)

    class Mon:
        def active_flows(self):
            return [rec]

    class Stats:
        def count(self, ip, window):
            return 0                                             # its DNS goes through the tunnel

    class Rep:
        def known(self, *a):
            return False, "not a site anyone here uses"

        def learn_bad(self, *a):
            pass

    class Alerts:
        def emit(self, *a, **k):
            pass
    d = Detector(cfg, None, Mon(), Stats(), type("L", (), {"category_match": lambda *a: None,
                                                            "ip_list_match": lambda *a: None})(),
                 Alerts(), None, reputation=Rep())
    interval = cfg["detector"]["interval"]
    t = interval
    while t <= limit:
        rec.now = t0 + t
        if d.evaluate(now=t0 + t):
            return t
        t += interval
    return None


def test_tunnel_noticed_in_seconds_not_minutes():
    old = _time_to_detect({"interval": 30, "unknown_min_duration": 60, "unknown_min_bytes": 2_000_000,
                           "silence_min_bytes": 5_000_000})
    new = _time_to_detect({})                                        # today's defaults
    assert old >= 60                                                 # what the screenshot showed (88 s)
    assert new <= 25, new
    # a tunnel with a real-looking site name (passes the instant checks) is caught quickly too
    named = _time_to_detect({}, rate=300_000, domain="cdn.unknown-relay.example")
    assert named is not None and named <= 30, named
