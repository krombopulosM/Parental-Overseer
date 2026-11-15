"""Unit tests for the supporting pieces: lists, schedules, DB, monitor,
detector, resolver, nft rendering, replay tool."""
import datetime as dt
import json
import os
import socket
import sqlite3
import struct
import threading
import time

import pytest
from conftest import ROOT, client_hello, tcp, udp

from guardian.alerts import AlertSink
from guardian.config import load_config
from guardian.db import DB
from guardian.detector import Detector
from guardian.dnscache import DnsCache
from guardian.flows import FlowSample
from guardian.flows.conntrack import parse_line
from guardian.flows.monitor import FlowMonitor
from guardian.identity import Identity
from guardian.inspector import FlowLabels
from guardian.iplist import IPSet
from guardian.lists import ListManager, _extract_ips
from guardian.policy import Policy
from guardian.resolver import DnsTunnelDetector, GuardianResolver, QueryStats
from guardian.schedule import Scheduler, window_active
from guardian.services import name_matches, registrable_domain, service_for


# ------------------------------------------------------------------ helpers
def test_services_and_domains():
    assert registrable_domain("a.b.bbc.co.uk") == "bbc.co.uk"
    assert registrable_domain("rr1---sn-x.googlevideo.com") == "googlevideo.com"
    assert service_for("rr1---sn-x.googlevideo.com") == "youtube"
    assert service_for("v16.tiktokcdn.com") == "tiktok"
    assert service_for("news.example.org") == "example.org"
    assert name_matches("www.example.com", {"example.com"})
    assert not name_matches("www.microsoft.com", {"my-vps.example"})


def test_ipset():
    s = IPSet(["10.0.0.0/8", "1.1.1.1", "2606:4700::/32", "10.1.0.0/16"])
    assert "10.200.3.4" in s and "1.1.1.1" in s and "1.1.1.2" not in s
    assert "2606:4700:10::1" in s and "::ffff:1.1.1.1" in s
    assert s.cidrs(4) == ["1.1.1.1/32", "10.0.0.0/8"]


def test_vpn_server_list_json_parsing():
    mullvad = [{"hostname": "se-sto-wg-001", "ipv4_addr_in": "185.65.135.1", "ipv6_addr_in": "2a03:1b20::1"}]
    proton = {"LogicalServers": [{"Servers": [{"EntryIP": "185.159.157.10", "ExitIP": "185.159.157.11"}]}]}
    tor = {"relays": [{"or_addresses": ["51.15.1.1:9001", "[2001:bc8::1]:9001"]}]}
    for data, want in ((mullvad, {"185.65.135.1", "2a03:1b20::1"}),
                       (proton, {"185.159.157.10", "185.159.157.11"}),
                       (tor, {"51.15.1.1", "2001:bc8::1"})):
        out = []
        _extract_ips(data, out)
        assert set(out) == want


def test_list_manager_parsing(tmp_path):
    (tmp_path / "hosts").write_text("# c\n0.0.0.0 ads.example.com tracker.example.net\n*.wild.example\n"
                                    "||abp.example^\nplain.example\n127.0.0.1 localhost\n")
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg["lists_cache_dir"] = str(tmp_path / "c")
    cfg["categories"] = {"t": {"files": [str(tmp_path / "hosts")]}}
    cfg["ip_lists"] = {}
    lm = ListManager(cfg)
    lm.load()
    m = lm.categories["t"]
    for d in ("ads.example.com", "x.tracker.example.net", "a.wild.example", "abp.example", "plain.example"):
        assert m.match(d), d
    assert not m.match("localhost") and not m.match("example.com")
    guard_ip = "104.16.1.1"
    lm.cdn_guard = IPSet(["104.16.0.0/13"])
    got = lm._parse_ip_source("mullvad", json.dumps([{"ipv4_addr_in": guard_ip},
                                                     {"ipv4_addr_in": "185.65.135.1"},
                                                     {"ipv4_addr_in": "192.168.1.1"}]).encode())
    assert got == ["185.65.135.1"]          # CDN space and private IPs are never blocked


def test_schedule_windows():
    mon_2230 = dt.datetime(2026, 11, 16, 22, 30)    # a Monday
    tue_0630 = dt.datetime(2026, 11, 17, 6, 30)
    tue_1200 = dt.datetime(2026, 11, 17, 12, 0)
    assert window_active("mon,tue", "21:00", "07:00", mon_2230)
    assert window_active("mon", "21:00", "07:00", tue_0630)       # spills over from Monday night
    assert not window_active("mon", "21:00", "07:00", tue_1200)
    assert window_active("tue", "09:00", "15:00", tue_1200)
    assert not window_active("sat,sun", "00:00", "23:59", tue_1200)


def test_db_migration_from_phase1(tmp_path):
    p = str(tmp_path / "old.db")
    c = sqlite3.connect(p)
    c.executescript("CREATE TABLE devices (ip TEXT PRIMARY KEY, name TEXT, group_name TEXT, first_seen REAL, last_seen REAL);"
                    "CREATE TABLE queries (id INTEGER PRIMARY KEY, ts REAL, client_ip TEXT, qname TEXT, qtype TEXT, action TEXT, reason TEXT);"
                    "INSERT INTO devices VALUES ('192.168.1.5','PC','kids',1,2),('192.168.1.6',NULL,'default',1,2);")
    c.commit()
    c.close()
    db = DB(p)
    rows = {d["device_id"]: d for d in db.list_devices()}
    assert rows["192.168.1.5"]["group_name"] == "kids" and rows["192.168.1.5"]["name"] == "PC"
    assert rows["192.168.1.6"]["group_name"] is None
    db.log_query("x", "1.2.3.4", "a.com", "A", "allowed", "")
    db.flush()
    assert db.recent_queries(5)[0]["device_id"] == "x"


def test_adopt_ip_device(tmp_path):
    db = DB(str(tmp_path / "g.db"))
    db.update_device("10.0.0.5", name="Tablet", group="kids", set_group=True)
    db.log_query("10.0.0.5", "10.0.0.5", "a.com", "A", "allowed", "")
    assert db.adopt_ip_device("10.0.0.5", "aa:bb:cc:dd:ee:ff")
    d = db.get_device("aa:bb:cc:dd:ee:ff")
    assert d["name"] == "Tablet" and d["group_name"] == "kids" and db.get_device("10.0.0.5") is None
    assert db.recent_queries(1)[0]["device_id"] == "aa:bb:cc:dd:ee:ff"


def test_conntrack_parse():
    line = ("tcp      6 431999 ESTABLISHED src=192.168.50.23 dst=142.250.180.14 sport=51234 dport=443 "
            "packets=12 bytes=2000 src=142.250.180.14 dst=203.0.113.1 sport=443 dport=51234 packets=14 "
            "bytes=90000 [ASSURED] mark=2 use=1 id=3532465024")
    e = parse_line(line)
    assert e["orig"]["src"] == "192.168.50.23" and e["orig"]["bytes"] == "2000"
    assert e["reply"]["bytes"] == "90000" and e["id"] == "3532465024"


# ------------------------------------------------------------------ monitor + detector
class FakeBackend:
    name = "fake"

    def __init__(self):
        self.samples = []

    def start(self):
        pass

    def snapshot(self):
        return list(self.samples)


def make_stack(tmp_path, group="kids"):
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg["categories"], cfg["ip_lists"] = {}, {}
    cfg["lists_cache_dir"] = str(tmp_path / "c")
    cfg["detector"].update(min_duration=10, min_bytes=1_000_000, window=300, silence_min_bytes=500_000,
                           learning_days=0)
    db = DB(str(tmp_path / "g.db"))
    lists = ListManager(cfg)
    lists.load()
    alerts = AlertSink(db)
    policy = Policy(cfg, db, lists, Identity(cfg), alerts)
    policy.forced_group = group
    return cfg, db, lists, alerts, policy


def test_monitor_usage_and_detector(tmp_path):
    cfg, db, lists, alerts, policy = make_stack(tmp_path)
    dnscache = DnsCache()
    dnscache.record("192.168.50.9", ["vpn-ish.example"], [("45.1.1.1", 300)])
    dnscache.record("192.168.50.9", ["rr1.googlevideo.com"], [("142.250.1.1", 300)])
    backend = FakeBackend()
    mon = FlowMonitor(cfg, db, policy, dnscache, FlowLabels(), backend)
    t0 = 1_800_000_000.0
    tup1 = ("tcp", "192.168.50.9", 50000, "45.1.1.1", 443)
    tup2 = ("tcp", "192.168.50.9", 50001, "142.250.1.1", 443)
    for i in range(0, 40):
        backend.samples = [FlowSample("a", tup1, 10_000 * i, 200_000 * i),
                           FlowSample("b", tup2, 100 * i, 2_000 * i)]
        mon.ingest(backend.samples, t0 + i)
    db.flush()
    rows = db.usage_by_service(int(t0 // 60), 10_000)
    svc = {r["service"]: r for r in rows}
    assert svc["vpn-ish.example"]["bytes_down"] == 200_000 * 39 and svc["vpn-ish.example"]["minutes"] >= 1
    assert "youtube" in svc
    stats = QueryStats()                         # the device has gone DNS-silent
    det = Detector(cfg, db, mon, stats, lists, alerts, gateway=None)
    res = det.evaluate(now=t0 + 39)
    assert len(res) == 1 and res[0]["dst"] == "45.1.1.1"
    assert "would block" in res[0]["action"]
    assert any("DNS lookups" in w for w in res[0]["why"])
    assert det.evaluate(now=t0 + 40) == []       # flagged once only
    db.add_allow("ip", "45.1.1.1")


def test_detector_ignores_exempt_streaming(tmp_path):
    cfg, db, lists, alerts, policy = make_stack(tmp_path)
    dnscache = DnsCache()
    dnscache.record("192.168.50.9", ["ipv4-c001.1.oca.nflxvideo.net"], [("45.57.1.1", 300)])
    backend = FakeBackend()
    mon = FlowMonitor(cfg, db, policy, dnscache, FlowLabels(), backend)
    t0 = 1_800_000_000.0
    for i in range(40):
        mon.ingest([FlowSample("n", ("tcp", "192.168.50.9", 1, "45.57.1.1", 443), 1000 * i, 500_000 * i)], t0 + i)
    det = Detector(cfg, db, mon, QueryStats(), lists, alerts)
    assert det.evaluate(now=t0 + 39) == []


# ------------------------------------------------------------------ resolver
class StubUpstream:
    """Tiny upstream DNS: answers A for any name, plus a CNAME for alias.test."""

    def __init__(self):
        from dnslib import RR
        from dnslib.server import BaseResolver, DNSLogger, DNSServer

        class R(BaseResolver):
            def resolve(self, req, handler):
                r = req.reply()
                name = str(req.q.qname)
                if name.startswith("alias.test"):
                    r.add_answer(*RR.fromZone(f"{name} 60 CNAME blocked-target.test."))
                    r.add_answer(*RR.fromZone("blocked-target.test. 60 A 5.5.5.5"))
                else:
                    r.add_answer(*RR.fromZone(f"{name} 60 A 5.6.7.8"))
                return r
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        self.server = DNSServer(R(), address="127.0.0.1", port=self.port, logger=DNSLogger("-request,-reply"))
        self.server.start_thread()


def test_resolver_pipeline(tmp_path):
    from dnslib import DNSRecord
    up = StubUpstream()
    (tmp_path / "adult.txt").write_text("blocked-target.test\nadult.test\n")
    cfg, db, lists, alerts, policy = make_stack(tmp_path, group="kids")
    cfg["categories"] = {"adult": {"files": [str(tmp_path / "adult.txt")]}}
    cfg["groups"]["kids"]["categories"] = ["adult"]
    lists.load()
    cfg["dns"].update(upstreams=["127.0.0.1"], upstream_port=up.port)
    cache = DnsCache()
    sched = Scheduler(db, policy)
    res = GuardianResolver(cfg, policy, lists, cache, db, alerts, sched, QueryStats(),
                           DnsTunnelDetector({"unique_names": 5, "min_label_len": 20, "window": 60}, alerts))

    class H:
        client_address = ("192.168.50.9", 5353)

    def ask(name, qt="A"):
        r = res.resolve(DNSRecord.question(name, qt), H())
        return r.header.rcode, [str(a.rdata) for a in r.rr]

    assert ask("ok.test") == (0, ["5.6.7.8"])
    assert cache.resolved_by("192.168.50.9", "5.6.7.8") == {"ok.test"}
    assert ask("adult.test")[0] == 3
    assert ask("alias.test")[0] == 3                      # CNAME cloaking caught
    assert ask("ok.test", "HTTPS") == (0, [])             # ECH keys stripped
    assert ask("ok.test", "NULL")[0] == 5
    assert ask("use-application-dns.net")[0] == 3
    for i in range(5):                                    # DNS tunnel
        ask(f"{os.urandom(16).hex()}.exfil.test")
    assert ask(f"{os.urandom(16).hex()}.exfil.test")[0] == 3
    assert ask("normal.exfil.test")[0] == 3               # whole domain blocked for this device
    db.flush()
    kinds = {a["kind"] for a in db.alerts()}
    assert "dns_tunnel" in kinds


# ------------------------------------------------------------------ nft ruleset
def test_nft_render_both_backends():
    from guardian.gateway.nft import NftGateway
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg["mode"] = "gateway"
    gw = NftGateway(cfg, ListManager(cfg), None)
    gw.backend = "nft"
    t = gw.render()
    assert t.count("queue num 0") == 4 and "bypass" not in t      # fail closed by default
    assert 'iifname != { "eth1" } return' in t and "meta nfproto ipv6 drop" in t
    assert "dnat ip to 192.168.50.1:53" in t
    gw.backend = "xt"
    t2 = gw.render()
    assert "queue" not in t2 and "meta mark set 0x20 accept" in t2


# ------------------------------------------------------------------ replay tool
def test_replay_tool(tmp_path):
    from scapy.all import wrpcap, Ether, IP as SIP
    from dnslib import DNSRecord, RR
    import sys as _s
    _s.path.insert(0, os.path.join(ROOT, "tools"))
    import replay as rp
    kid, site, vps = "192.168.1.23", "93.184.216.34", "45.32.1.1"
    q = DNSRecord.question("www.example.com")
    a = q.reply()
    a.add_answer(*RR.fromZone(f"www.example.com. 300 A {site}"))
    raw = [udp("192.168.1.1", kid, 53, 40000, a.pack()),
           tcp(kid, site, 41000, 443, 100, 0x02),
           tcp(kid, site, 41000, 443, 101, 0x18, client_hello("www.example.com")),
           tcp(kid, vps, 41001, 443, 100, 0x02),
           udp(kid, vps, 41002, 51820, b"\x01\x00\x00\x00" + os.urandom(144))]
    pcap = str(tmp_path / "c.pcap")
    wrpcap(pcap, [Ether() / SIP(r) for r in raw])
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg["lists_cache_dir"] = str(tmp_path / "c")
    lines = []
    out = rp.replay(pcap, "kids", cfg=cfg, out=lines.append)
    kinds = {v.kind for _, v in out["blocked"]}
    assert kinds == {"no_dns", "blocked_udp"}
    assert len(out["allowed"]) == 1
    assert any("www.example.com" in l for l in lines)
