"""Torrent detection, confidence scoring and the countermeasure defences."""
import os
import struct
import time

import pytest
from conftest import Conn, ROOT, client_hello, tcp, udp

from guardian.alerts import AlertSink
from guardian.confidence import ConfidenceScorer
from guardian.config import load_config
from guardian.db import DB
from guardian.identity import Identity
from guardian.lists import ListManager
from guardian.policy import Policy
from guardian.protocols import classify_torrent_udp, identify_tcp_stream, is_torrent_http, parse_ip

KID, VPS = "192.168.50.23", "45.32.1.1"
BT = b"\x13BitTorrent protocol" + b"\x00" * 8 + os.urandom(40)
DHT_PING = b"d1:ad2:id20:" + os.urandom(20) + b"e1:q4:ping1:t2:aa1:y1:qe"
UTP_SYN = bytes([0x41, 0x00]) + os.urandom(6) + b"\x00\x00\x00\x00" + os.urandom(8)
UDP_TRACKER = bytes.fromhex("0000041727101980") + b"\x00\x00\x00\x00" + os.urandom(4)


# ------------------------------------------------------------------ torrent signatures
def test_torrent_signatures():
    assert classify_torrent_udp(DHT_PING) == "BitTorrent DHT"
    assert classify_torrent_udp(UTP_SYN) == "BitTorrent uTP"
    assert classify_torrent_udp(UDP_TRACKER) == "BitTorrent UDP tracker"
    assert classify_torrent_udp(os.urandom(200).replace(b"d", b"x")[:1] + b"junk" * 10) is None
    assert classify_torrent_udp(b"\x00\x01\x00\x00\x21\x12\xa4\x42" + os.urandom(12)) is None   # STUN
    assert identify_tcp_stream(BT) == "BitTorrent peer connection"
    assert is_torrent_http("/announce?info_hash=%12%34&peer_id=x")
    assert not is_torrent_http("/index.html")


def test_torrent_blocked_everywhere(env):
    env.dnscache.record(KID, ["relay.example"], [(VPS, 300)])
    v = Conn(env.insp, KID, VPS, 443).open_and_send(BT)
    assert v.kind == "torrent" and v.action == "reset"                 # disguised on 443
    v = Conn(env.insp, KID, VPS, 80, sport=41001).open_and_send(
        b"GET /announce?info_hash=abc&port=6881 HTTP/1.1\r\nHost: relay.example\r\n\r\n")
    assert v.kind == "torrent"                                          # HTTP tracker
    assert env.insp.inspect(udp(KID, VPS, 6881, 6881, DHT_PING)).kind == "torrent"
    env.policy.forced_group = "consoles"                                # UDP allowed, torrents not
    assert env.insp.inspect(udp(KID, VPS, 6882, 51413, UTP_SYN)).kind == "torrent"
    assert env.insp.inspect(udp(KID, VPS, 6883, 3074, os.urandom(60))).action == "accept"


def test_torrent_peer_fanout(env):
    for i in range(30):
        env.insp.inspect(tcp(KID, f"81.2.{i}.9", 40000 + i, 20000 + i, 1, 0x02))
    a = [x for x in env.alerts.memory if x["kind"] == "torrent_peers"]
    assert len(a) == 1 and "25 different peers" in a[0]["detail"]


def test_passive_torrent_observe(env):
    env.insp.observe(udp(KID, VPS, 6881, 6881, DHT_PING))
    a = [x for x in env.alerts.memory if x["kind"] == "torrent"]
    assert a and a[0]["action"] == "seen (monitor mode)"


# ------------------------------------------------------------------ other inspector defences
def test_whatsapp_protocol_exempt(env):
    env.dnscache.record(KID, ["g.whatsapp.net"], [("157.240.1.53", 300)])
    v = Conn(env.insp, KID, "157.240.1.53", 443).open_and_send(b"WA\x06\x02" + os.urandom(60))
    assert v.action == "accept"
    env.dnscache.record(KID, ["fake.example"], [(VPS, 300)])
    assert Conn(env.insp, KID, VPS, 443).open_and_send(b"WA\x06\x02" + os.urandom(60)).kind == "protocol_violation"


def test_marked_fine_destination_skips_checks(env):
    assert Conn(env.insp, KID, VPS, 443).syn().kind == "no_dns"
    env.insp.allow_ips.add(VPS)
    assert Conn(env.insp, KID, VPS, 443, sport=41000).syn().action == "accept"


def gateway_env(env):
    env.cfg["mode"] = "gateway"
    from guardian.inspector import FlowLabels, Inspector
    env.insp = Inspector(env.cfg, env.policy, env.lists, env.dnscache, env.alerts, FlowLabels())
    return env.insp


def test_gateway_probe_and_port_scan(env):
    insp = gateway_env(env)
    gw = env.cfg["gateway"]["lan_ip"]
    assert insp.inspect(tcp(KID, gw, 40000, 22, 1, 0x02)).action == "drop"
    assert [a["kind"] for a in env.alerts.memory] == ["gateway_probe"]
    for p in (21, 23, 25, 80, 139, 445, 3389, 5900):
        insp.inspect(tcp(KID, gw, 40001, p, 1, 0x02))
    assert "port_scan" in [a["kind"] for a in env.alerts.memory]


def test_hidden_router_ttl(env):
    insp = gateway_env(env)
    env.dnscache.record(KID, ["site.example"], [(VPS, 300)])
    import struct as st
    for i in range(6):
        raw = bytearray(tcp(KID, VPS, 42000 + i, 443, 1, 0x02))
        raw[8] = 62                       # 64 - device's NAT hop - the Pi's own hop
        insp.inspect(bytes(raw))
    assert "hidden_router" in [a["kind"] for a in env.alerts.memory]
    env.alerts.memory.clear()
    for i in range(6):                    # a normal device: TTL 63 after the Pi's hop
        raw = bytearray(tcp("192.168.50.24", VPS, 43000 + i, 443, 1, 0x02))
        raw[8] = 63
        insp.inspect(bytes(raw))
    assert "hidden_router" not in [a["kind"] for a in env.alerts.memory]


# ------------------------------------------------------------------ confidence
def test_confidence_scoring_and_calibration(tmp_path):
    db = DB(str(tmp_path / "g.db"))
    sc = ConfidenceScorer(db)
    sink = AlertSink(db, scorer=sc)
    c0, why = sc.score("no_dns", "kid")
    assert c0 == 50 and "typical" in why[0]
    assert sc.score("evasion", "kid")[0] == 95
    assert sc.score("new_device", "kid")[0] is None
    # history: other techniques by the same device raise confidence
    sink.emit("vpn_server", device_id="kid", dst="1.2.3.4", detail="x")
    sink.emit("blocked_udp", device_id="kid", dst="1.2.3.5", detail="x")
    c1, why1 = sc.score("no_dns", "kid")
    assert c1 == 62 and any("2 other techniques" in w for w in why1)
    # reviews: parent says 4 of 5 no_dns alerts were false positives -> confidence drops
    for i in range(5):
        a = sink.emit("no_dns", device_id=f"d{i}", dst=f"9.9.9.{i}", detail="x")
    ids = [r["id"] for r in db.query("SELECT id FROM alerts WHERE kind='no_dns'")]
    for i, aid in enumerate(ids):
        db.review_alert(aid, "fp" if i < 4 else "tp")
    sc.reload()
    c2, why2 = sc.score("no_dns", "other-device")
    assert c2 < 40 and any("4 were false positives" in w for w in why2)
    db.flush()
    row = db.query_one("SELECT confidence, category FROM alerts WHERE kind='vpn_server'")
    assert row["confidence"] == 85 and row["category"] == "vpn"


# ------------------------------------------------------------------ LAN watch
@pytest.fixture
def lan(tmp_path):
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg["mode"] = "gateway"
    cfg["categories"], cfg["ip_lists"] = {}, {}
    cfg["lists_cache_dir"] = str(tmp_path / "c")
    cfg["gateway"]["dhcp_leases"] = str(tmp_path / "leases")
    db = DB(str(tmp_path / "g.db"))
    lists = ListManager(cfg)
    lists.load()
    alerts = AlertSink(db)
    policy = Policy(cfg, db, lists, Identity(cfg), alerts)
    from guardian.lanwatch import LanWatch
    changes = []
    lw = LanWatch(cfg, db, policy, policy.identity, alerts, on_change=lambda: changes.append(1))
    lw.own_macs = {"02:00:00:00:00:01"}
    lw.pinned_calls = []
    import guardian.lanwatch as m
    m.system.pin_neighbor = lambda ip, mac, dev: lw.pinned_calls.append((ip, mac))
    lw._corrective_arp = lambda: lw.pinned_calls.append(("corrective", None))

    class L:
        pass
    o = L()
    o.cfg, o.db, o.policy, o.alerts, o.lw, o.changes = cfg, db, policy, alerts, lw, changes
    o.kinds = lambda: [r["kind"] for r in db.query("SELECT kind FROM alerts ORDER BY id")]
    return o


def dhcp_request(mac, prl, host, vendor=b"android-dhcp-14"):
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether
    chaddr = bytes.fromhex(mac.replace(":", "")) + b"\x00" * 10
    return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=chaddr) /
            DHCP(options=[("message-type", "request"), ("param_req_list", prl), ("vendor_class_id", vendor),
                          ("hostname", host), "end"]))


def test_arp_spoof_of_gateway(lan):
    from scapy.all import ARP, Ether
    pkt = Ether(src="aa:aa:aa:aa:aa:01") / ARP(op=2, hwsrc="aa:aa:aa:aa:aa:01", psrc=lan.cfg["gateway"]["lan_ip"],
                                               pdst="192.168.50.20")
    lan.lw.handle(pkt)
    assert lan.kinds() == ["arp_spoof"]
    assert ("corrective", None) in lan.lw.pinned_calls


def test_ip_spoof_pins_real_owner(lan):
    from scapy.all import ARP, Ether
    lan.db.upsert_device_seen("bb:bb:bb:bb:bb:20", "bb:bb:bb:bb:bb:20", "192.168.50.20")
    lan.db.flush()
    pkt = Ether(src="aa:aa:aa:aa:aa:01") / ARP(op=2, hwsrc="aa:aa:aa:aa:aa:01", psrc="192.168.50.20")
    lan.lw.handle(pkt)
    assert lan.kinds() == ["ip_spoof"]
    assert ("192.168.50.20", "bb:bb:bb:bb:bb:20") in lan.lw.pinned_calls
    # a device announcing its OWN address is normal
    lan.lw.handle(Ether(src="bb:bb:bb:bb:bb:20") / ARP(op=2, hwsrc="bb:bb:bb:bb:bb:20", psrc="192.168.50.20"))
    assert lan.kinds() == ["ip_spoof"]


def test_rogue_dhcp_server(lan):
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether
    offer = (Ether(src="aa:aa:aa:aa:aa:01") / IP(src="192.168.50.66") / UDP(sport=67, dport=68) /
             BOOTP(op=2) / DHCP(options=[("message-type", "offer"), ("router", "192.168.50.66"), "end"]))
    lan.lw.handle(offer)
    assert lan.kinds() == ["rogue_dhcp"]
    lan.lw.handle(Ether(src="02:00:00:00:00:01") / IP() / UDP(sport=67, dport=68) / BOOTP(op=2) /
                  DHCP(options=[("message-type", "offer"), "end"]))       # the Pi's own offer
    assert lan.kinds() == ["rogue_dhcp"]


def test_spoofed_parent_mac_is_quarantined(lan):
    dad = "cc:cc:cc:cc:cc:01"
    lan.db.update_device(dad, name="Dad's phone", group="adults", set_group=True)
    lan.policy.reload()
    lan.lw.handle(dhcp_request(dad, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43], b"Dads-phone"))
    assert lan.kinds() == []                                   # first sighting: learn it
    lan.lw.handle(dhcp_request(dad, [1, 121, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 252], b"Dads-phone",
                               vendor=b"MSFT 5.0"))            # a Windows laptop wearing Dad's MAC
    assert lan.kinds() == ["mac_spoof"]
    lan.policy.reload()
    assert lan.policy.is_suspect(dad) and lan.policy.group_name(dad) == "quarantine"
    assert lan.changes
    # the real phone renews again -> two devices taking turns on one MAC
    lan.lw.handle(dhcp_request(dad, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43], b"Dads-phone"))
    assert lan.kinds()[-1] == "mac_clone"


def test_new_mac_keeps_kids_group_but_never_gains_adult(lan):
    kid_old, kid_new, dad, impostor = "dd:00:00:00:00:01", "dd:00:00:00:00:02", "cc:00:00:00:00:01", "ee:00:00:00:00:01"
    lan.db.update_device(kid_old, name="Sam's laptop", group="kids", set_group=True)
    lan.db.update_device(dad, name="Dad's laptop", group="adults", set_group=True)
    lan.policy.reload()
    prl = [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]
    lan.lw.handle(dhcp_request(kid_old, prl, b"SAMS-LAPTOP", b"MSFT 5.0"))
    lan.lw.handle(dhcp_request(dad, [1, 3, 6, 15, 119, 252], b"DADS-MBP", b""))
    lan.lw.handle(dhcp_request(kid_new, prl, b"SAMS-LAPTOP", b"MSFT 5.0"))   # randomised MAC
    lan.policy.reload()
    assert lan.policy.configured_group(kid_new) == "kids"
    lan.lw.handle(dhcp_request(impostor, [1, 3, 6, 15, 119, 252], b"DADS-MBP", b""))   # copies Dad
    lan.policy.reload()
    assert lan.policy.configured_group(impostor) == "quarantine"               # NOT adults
    assert lan.kinds() == ["mac_change", "mac_change"]


def test_rogue_ra_and_torrent_lan(lan):
    from scapy.all import IP, UDP, Ether, Raw
    from scapy.layers.inet6 import ICMPv6ND_RA, IPv6
    lan.lw.handle(Ether(src="aa:aa:aa:aa:aa:01") / IPv6(src="fe80::1", dst="ff02::1") / ICMPv6ND_RA())
    lan.lw.handle(Ether(src="aa:aa:aa:aa:aa:01") / IP(src="192.168.50.23", dst="239.192.152.143") /
                  UDP(sport=6771, dport=6771) / Raw(b"BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\n"))
    assert lan.kinds() == ["rogue_ra", "torrent_lan"]


def test_static_ip(lan, tmp_path):
    (tmp_path / "leases").write_text(f"{int(time.time()) + 3600} ab:00:00:00:00:01 192.168.50.101 tablet *\n")
    lan.db.upsert_device_seen("ab:00:00:00:00:01", "ab:00:00:00:00:01", "192.168.50.77")
    lan.db.flush()
    lan.policy.identity.refresh(force=True)
    lan.lw.check_static_ips()
    lan.lw.check_static_ips()
    assert lan.kinds() == ["static_ip"]


# ------------------------------------------------------------------ resolver: custom DNS
def test_custom_dns_detected_via_redirect_port(tmp_path):
    from dnslib import DNSRecord
    from test_components import StubUpstream, make_stack
    from guardian.dnscache import DnsCache
    from guardian.resolver import DnsTunnelDetector, GuardianResolver, QueryStats
    from guardian.schedule import Scheduler
    up = StubUpstream()
    cfg, db, lists, alerts, policy = make_stack(tmp_path)
    cfg["mode"] = "gateway"
    cfg["dns"].update(upstreams=["127.0.0.1"], upstream_port=up.port, redirect_port=5354)
    res = GuardianResolver(cfg, policy, lists, DnsCache(), db, alerts, Scheduler(db, policy), QueryStats(),
                           DnsTunnelDetector({}, alerts))

    class Srv:
        server_address = ("0.0.0.0", 5354)

    class H:
        client_address = ("192.168.50.9", 3333)
        server = Srv()
    res.resolve(DNSRecord.question("a.test"), H())
    H.server = type("S", (), {"server_address": ("0.0.0.0", 53)})()
    res.resolve(DNSRecord.question("b.test"), H())
    db.flush()
    assert [r["kind"] for r in db.alerts() if r["kind"] != "new_device"] == ["custom_dns"]


# ------------------------------------------------------------------ health API end to end (monitor mode)
def test_health_api(tmp_path):
    import httpx
    from fastapi.testclient import TestClient
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg.update(database=str(tmp_path / "g.db"), lists_cache_dir=str(tmp_path / "c"))
    cfg["categories"], cfg["ip_lists"] = {}, {}
    from guardian.app import Guardian
    from guardian.webapp import create_app
    g = Guardian(cfg)
    g.monitor = g.detector = None
    app = create_app(g)
    c = TestClient(app, client=("127.0.0.1", 5000))
    H = {"X-Guardian": "1"}
    assert c.post("/api/setup", json={"password": "longpassword"}, headers=H).status_code == 200
    g.db.update_device("kid", name="Sam", group="kids", set_group=True)
    g.policy.reload()
    g.alerts.emit("arp_spoof", device_id="kid", detail="x")
    g.alerts.emit("torrent", device_id="kid", dst="5.5.5.5", detail="x")
    g.alerts.emit("no_dns", device_id="kid", dst="6.6.6.6", detail="x")
    g.db.flush()
    h = c.get("/api/health").json()
    card = next(d for d in h["devices"] if d["device_id"] == "kid")
    assert card["status"] == "tampering" and card["attempts"] == 3 and card["techniques"] == 3
    assert h["totals"]["tamper"] == 1 and h["totals"]["torrent"] == 1
    assert sum(h["hourly"]["dns"]) == 1
    assert any(chk["name"] == "Enforcement" and chk["level"] == "warn" for chk in h["checks"])
    # review: 'not a bypass' on the direct-IP alert allowlists the destination for the inspector
    aid = next(a["id"] for a in c.get("/api/alerts").json()["alerts"] if a["kind"] == "no_dns")
    r = c.post(f"/api/alerts/{aid}/review", json={"verdict": "fp"}, headers=H).json()
    assert "6.6.6.6" in r["note"] and "6.6.6.6" in g.inspector.allow_ips
    assert c.get("/api/health").json()["reviews"]["fp"] == 1
    # brute force alert after 3 wrong passwords
    c2 = TestClient(app, client=("192.168.50.23", 5000))
    for _ in range(3):
        c2.post("/api/login", json={"password": "nope"}, headers=H)
    g.db.flush()
    assert any(a["kind"] == "dashboard_bruteforce" for a in g.db.alerts())
