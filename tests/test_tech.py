"""Targeting VPN/Tor technology rather than server lists."""
import os
import ssl
import time

import pytest
from conftest import ROOT, Conn, client_hello, tcp

from guardian.config import load_config
from guardian.protocols import looks_like_tor_sni, parse_client_hello
from guardian.reputation import Reputation, on_hosting_platform

KID, NEWVPN, NEWVPN2 = "192.168.50.23", "45.77.1.1", "45.77.2.2"


def vpn_app_hello(sni):
    """A ClientHello from a 'VPN app' with its own TLS stack (different JA4 from a browser)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256")
    out = ssl.MemoryBIO()
    o = ctx.wrap_bio(ssl.MemoryBIO(), out, server_hostname=sni)
    try:
        o.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


@pytest.mark.parametrize("sni,tor", [
    ("www.k3jd6a2bq7x.com", True), ("www.bcdfghjklmn.net", True), ("www.qzx4mt7wpl.com", True),
    ("www.facebook.com", False), ("www.wikipedia.com", False), ("www.google.com", False),
    ("cdn.k3jd6a2bq7x.com", False), ("www.k3jd6a2bq7x.org", False),
])
def test_tor_sni_shape(sni, tor):
    assert looks_like_tor_sni(sni) is tor


def test_hosting_platforms():
    assert on_hosting_platform("my-node.workers.dev")
    assert on_hosting_platform("ec2-3-1-2-3.compute.amazonaws.com")
    assert not on_hosting_platform("www.bbc.co.uk")


@pytest.fixture
def rep(env):
    env.lists.popular = {"bbc.co.uk", "example-popular.com", "amazonaws.com"}
    r = Reputation(env.cfg, None, env.lists)
    env.insp.reputation = r
    return r


def test_known_destinations(rep):
    assert rep.known("www.youtube.com")[0]                       # known service
    assert rep.known("news.bbc.co.uk")[0]                        # popular
    assert not rep.known("ec2-3-1-2-3.compute.amazonaws.com")[0]  # popular parent, but anyone can host there
    ok, why = rep.known("my-node.workers.dev")
    assert not ok and "self-hosting" in why
    assert not rep.known("tiny-vps.example")[0]
    rep.mark_familiar("tiny-vps.example")                        # an adult uses it
    assert rep.known("www.tiny-vps.example") == (True, "used by an adult in the house")


def test_learned_fingerprint_blocks_new_servers(env, rep):
    for name, ip in (("relay-one.example", NEWVPN), ("relay-two.example", NEWVPN2), ("news.bbc.co.uk", "93.1.1.1")):
        env.dnscache.record(KID, [name], [(ip, 300)])
    ja4 = parse_client_hello(vpn_app_hello("relay-one.example")).ja4
    assert Conn(env.insp, KID, NEWVPN, 443).open_and_send(vpn_app_hello("relay-one.example")).action == "accept"
    assert rep.learn_bad(ja4, "the tunnel to relay-one.example", "tunnel_behaviour")
    v = Conn(env.insp, KID, NEWVPN2, 443, sport=41000).open_and_send(vpn_app_hello("relay-two.example"))
    assert v.kind == "vpn_fingerprint" and "relay-one" in v.reason          # same app, brand-new server
    browser = Conn(env.insp, KID, NEWVPN2, 443, sport=41001).open_and_send(client_hello("relay-two.example"))
    assert browser.action == "accept"                                      # different software: fine
    assert any(a["kind"] == "vpn_fingerprint" and a["ref"] == ja4 for a in env.alerts.memory)


def test_browser_fingerprints_are_never_learned(env, rep):
    env.dnscache.record(KID, ["news.bbc.co.uk"], [("93.1.1.1", 300)])
    Conn(env.insp, KID, "93.1.1.1", 443).open_and_send(client_hello("news.bbc.co.uk"))   # normal browsing
    ja4 = parse_client_hello(client_hello("x")).ja4
    assert not rep.learn_bad(ja4, "anything", "test")
    assert rep.bad_label(ja4) is None


def test_no_sni_teaches_fingerprint(env, rep):
    env.dnscache.record(KID, ["relay-one.example"], [(NEWVPN, 300)])
    v = Conn(env.insp, KID, NEWVPN, 443).open_and_send(vpn_app_hello(None))
    assert v.kind == "no_sni"
    assert rep.bad_label(parse_client_hello(vpn_app_hello(None)).ja4)


def test_tor_relay_list_and_handshake(env, rep, tmp_path):
    (tmp_path / "tor.txt").write_text("51.15.9.9\n")
    env.cfg["ip_lists"]["tor"] = {"files": [str(tmp_path / "tor.txt")]}
    env.lists.load()
    env.lists.popular = {"bbc.co.uk"}
    assert Conn(env.insp, KID, "51.15.9.9", 443).syn().kind == "tor"
    env.policy.forced_group = "consoles"            # log-mode DNS check: the Tor handshake shape still catches it
    v = Conn(env.insp, KID, "62.1.2.3", 443, sport=41000).open_and_send(client_hello("www.k3jd6a2bq7x.com"))
    assert v.kind == "tor" and v.action == "reset"


# ------------------------------------------------------------------ unknown destinations + detector
@pytest.fixture
def mon(tmp_path):
    import test_activity as ta
    o = ta.build_stack(tmp_path)
    o.guard.lists.popular = {"bbc.co.uk"}
    o.cfg["vpn"].update(unknown_min_bytes=15_000_000)
    o.guard.unknown_min_bytes = 15_000_000
    o.rep = Reputation(o.cfg, o.db, o.guard.lists, guard=o.guard)
    o.guard.reputation = o.rep
    return o


def stream(o, domain, ip, sport, seconds=20, rate=1_000_000):
    """A steady, two-way-ish tunnel: not shaped like a download, so only the unknown-destination check applies."""
    import test_activity as ta
    o.dnscache.record("192.168.50.23", [domain], [(ip, 300)])
    tup = ("tcp", "192.168.50.23", sport, ip, 443)
    up = down = pu = pd = 0
    for i in range(seconds // 2):
        up, down, pu, pd = up + rate // 2, down + rate * 2, pu + 900, pd + 1800
        o.be.samples = [ta.FlowSample(f"u{sport}", tup, up, down, pu, pd)]
        o.mon.ingest(o.be.samples, ta.T0 + 900 + i * 2)
    return o.mon.active[f"u{sport}"]


def test_heavy_traffic_to_unknown_site_held(mon):
    rec = stream(mon, "node.unknown-relay.example", "45.8.8.8", 52000)
    assert rec.unk_state == "held" and mon.killed
    row = mon.db.downloads(status="pending")[0]
    assert row["kind"] == "unknown" and row["site"] == "unknown-relay.example"
    ok = stream(mon, "media.bbc.co.uk", "93.2.2.2", 52001)
    assert ok.unk_state == "known"


def test_hosting_platform_tunnel_held(mon):
    rec = stream(mon, "my-vless.workers.dev", "104.21.1.1", 52002)
    assert rec.unk_state == "held"
    assert "self-hosting platform" in mon.db.downloads(status="pending")[0]["reasons"]


def test_unknown_policy_downgrades_without_popularity(mon):
    mon.guard.lists.popular = set()
    rec = stream(mon, "node.unknown-relay.example", "45.8.8.8", 52003)
    assert rec.unk_state == "alerted" and not mon.killed


def test_detector_faster_on_unknown_and_learns_fingerprint(mon):
    from guardian.detector import Detector
    from guardian.resolver import QueryStats
    mon.cfg["detector"].update(min_duration=300, min_bytes=10_000_000, unknown_min_duration=60,
                               unknown_min_bytes=2_000_000, learning_days=0, silence_min_bytes=1_000_000)
    det = Detector(mon.cfg, mon.db, mon.mon, QueryStats(), mon.guard.lists, mon.alerts, reputation=mon.rep)
    import test_activity as ta
    mon.dnscache.record("192.168.50.23", ["relay.unknown-vpn.example"], [("45.9.1.1", 300)])
    tup = ("tcp", "192.168.50.23", 53000, "45.9.1.1", 443)
    mon.mon.labels.set(tup, domain="relay.unknown-vpn.example", domain_src="sni", ja4="t12d0200h2_badbadbadbad_cafecafecafe")
    for i in range(40):          # 80 s at ~0.1 MB/s = ~8 MB: under the 15 MB hold, over the early-detector bar
        mon.be.samples = [ta.FlowSample("t1", tup, 5000 * i, 200_000 * i, 50 * i, 300 * i)]
        mon.mon.ingest(mon.be.samples, ta.T0 + 2000 + i * 2)
    res = det.evaluate(now=ta.T0 + 2000 + 78)
    assert res and res[0]["dst"] == "45.9.1.1"
    assert mon.rep.bad_label("t12d0200h2_badbadbadbad_cafecafecafe")


# ------------------------------------------------------------------ escalation
def test_escalation_names_tool_and_pauses(tmp_path):
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg.update(database=str(tmp_path / "g.db"), lists_cache_dir=str(tmp_path / "c"))
    cfg["categories"], cfg["ip_lists"] = {}, {}
    from guardian.app import Guardian
    g = Guardian(cfg)
    g.db.update_device("kid", group="kids", set_group=True)
    g.policy.reload()
    g.alerts.emit("tor", device_id="kid", dst="1.1.1.1", detail="x")
    g.alerts.emit("protocol_violation", device_id="kid", dst="2.2.2.2", detail="x")
    assert not g.scheduler.is_paused("kid", "kids")[0]
    g.alerts.emit("no_sni", device_id="kid", dst="3.3.3.3", detail="x", base=80)
    g.db.flush()
    tool = [a for a in g.db.alerts() if a["kind"] == "bypass_tool"]
    assert tool and "Tor Browser" in tool[0]["detail"] and "paused" in tool[0]["action"]
    assert g.scheduler.is_paused("kid", "kids")[0]
