"""Activity analysis and the download guard."""
import os
import random

import pytest
from conftest import ROOT, Conn, tcp

from guardian.activity import classify_flow, features, summarize
from guardian.alerts import AlertSink
from guardian.config import load_config
from guardian.db import DB
from guardian.dnscache import DnsCache
from guardian.downloads import DownloadGuard
from guardian.flows import FlowSample
from guardian.flows.monitor import FlowMonitor
from guardian.identity import Identity
from guardian.inspector import FlowLabels
from guardian.lists import ListManager
from guardian.policy import Policy

T0 = 1_800_000_000.0


def ticks(n, fn, dt=2.0):
    """fn(i) -> (up_bytes, down_bytes, up_pkts, down_pkts) per tick."""
    return [(T0 + i * dt, dt, *fn(i)) for i in range(n)]


def game(i):            # ~30 small packets/s each way
    return (60 * 90, 60 * 120, 60, 60)


def video(i):           # 4 MB burst every 5th tick, quiet between
    return (20_000, 4_000_000, 40, 2800) if i % 5 == 0 else (300, 500, 2, 2)


def download(i):        # steady 3 MB/s one-way
    return (40_000, 6_000_000, 700, 4200)


def call(i):            # symmetrical ~150 kB/s
    return (300_000, 320_000, 300, 310)


def browse(i):
    return (2_000, 15_000, 10, 15) if i % 3 == 0 else (0, 0, 0, 0)


@pytest.mark.parametrize("proto,service,fn,want", [
    ("udp", None, game, "gaming"),
    ("udp", "roblox", game, "gaming"),
    ("tcp", "youtube", video, "video"),
    ("tcp", None, video, "video"),                  # unknown site, but plays like a video
    ("tcp", "mega.nz", download, "download"),
    ("udp", None, call, "call"),
    ("tcp", "bbc.co.uk", browse, "browsing"),
])
def test_classify_shapes(proto, service, fn, want):
    t = ticks(15, fn)
    f = features(t, t[-1][0])
    a = classify_flow(proto, service, f)
    assert a is not None and a.cls == want, (a, f)


def test_idle_flow_is_none():
    t = ticks(10, lambda i: (0, 0, 0, 0))
    assert classify_flow("tcp", None, features(t, t[-1][0])) is None


def test_headline_game_with_youtube_background():
    tg, tv = ticks(15, game), ticks(15, video)
    flows = [(classify_flow("udp", "roblox", features(tg, tg[-1][0])), "roblox", 200_000, "game.roblox.com"),
             (classify_flow("tcp", "youtube", features(tv, tv[-1][0])), "youtube", 12_000_000, "rr1.googlevideo.com")]
    s = summarize(flows)
    assert s["headline"] == "Likely playing Roblox with YouTube in the background"
    assert s["activity"] == "gaming" and s["background"] == ["video"] and s["confidence"] >= 70


def test_unknown_game_server_is_not_named():
    tg = ticks(15, game)
    s = summarize([(classify_flow("udp", "vps.example", features(tg, tg[-1][0])), "vps.example", 1e5, "vps.example")])
    assert s["headline"] == "Likely playing an online game"


def test_headline_download_and_idle():
    td = ticks(15, download)
    s = summarize([(classify_flow("tcp", "mega.nz", features(td, td[-1][0])), "mega.nz", 9e7, "mega.nz")])
    assert s["headline"] == "Likely downloading a file from mega.nz"
    assert summarize([])["headline"] == "Idle"


# ------------------------------------------------------------------ download guard
@pytest.fixture
def stack(tmp_path):
    (tmp_path / "filehost.txt").write_text("mega.nz\nmediafire.com\n")
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg["mode"] = "gateway"
    cfg["lists_cache_dir"] = str(tmp_path / "c")
    cfg["categories"] = {"filehost": {"files": [str(tmp_path / "filehost.txt")]}}
    cfg["ip_lists"] = {}
    cfg["flows"]["poll_interval"] = 2
    db = DB(str(tmp_path / "g.db"))
    lists = ListManager(cfg)
    lists.load()
    alerts = AlertSink(db)
    policy = Policy(cfg, db, lists, Identity(cfg), alerts)
    policy.forced_group = "kids"
    killed = []
    guard = DownloadGuard(cfg, db, lists, alerts, kill_flow=lambda *a: killed.append(a))

    class Backend:
        name = "fake"
        samples = []

        def start(self):
            pass

        def snapshot(self):
            return list(self.samples)
    be = Backend()
    labels = FlowLabels()
    dnscache = DnsCache()
    mon = FlowMonitor(cfg, db, policy, dnscache, labels, be)
    mon.downloads = guard

    class S:
        pass
    o = S()
    o.cfg, o.db, o.guard, o.killed, o.be, o.mon, o.dnscache, o.policy, o.alerts = \
        cfg, db, guard, killed, be, mon, dnscache, policy, alerts
    return o


def run_download(o, domain, ip, port=443, seconds=12, rate=3_000_000, sport=50000):
    o.dnscache.record("192.168.50.23", [domain], [(ip, 300)])
    tup = ("tcp", "192.168.50.23", sport, ip, port)
    up = down = pu = pd = 0
    for i in range(seconds // 2):
        up += 30_000
        down += rate * 2
        pu += 500
        pd += 2900
        o.be.samples = [FlowSample(f"k{sport}", tup, up, down, pu, pd)]
        o.mon.ingest(o.be.samples, T0 + i * 2)
    return o.mon.active[f"k{sport}"]


def test_suspicious_download_held_and_cut(stack):
    rec = run_download(stack, "dl.mega.nz", "31.216.145.5")
    assert rec.dl_state == "held"
    assert stack.killed and stack.killed[0][:2] == ("tcp", "192.168.50.23")
    pending = stack.db.downloads(status="pending")
    assert len(pending) == 1 and pending[0]["site"] == "mega.nz" and pending[0]["score"] >= 50
    assert stack.guard.held_for(rec.device_id, "other.mega.nz")
    stack.db.flush()
    assert any(a["kind"] == "download_held" for a in stack.db.alerts())
    live = stack.mon.live_view(rec.device_id)
    assert live["now"]["activity"] == "download" and live["series"]


def test_trusted_download_allowed(stack):
    rec = run_download(stack, "steamcdn.steamcontent.com", "23.1.2.3", sport=50001)
    assert rec.dl_state == "allowed" and not stack.killed
    assert stack.db.downloads(status="allowed")[0]["site"] == "steamcontent.com"


def test_unknown_site_allowed_but_recorded(stack):
    rec = run_download(stack, "files.example.org", "93.1.2.3", sport=50002)
    assert rec.dl_state == "allowed"                    # 10 points < 50: not suspicious enough
    stack.cfg["groups"]["kids"]["downloads"] = "review_all"
    rec2 = run_download(stack, "files.example.net", "93.1.2.4", sport=50003)
    assert rec2.dl_state == "held"                      # review_all holds anything untrusted


def test_approve_and_deny(stack):
    rec = run_download(stack, "dl.mega.nz", "31.216.145.5")
    rid = stack.db.downloads(status="pending")[0]["id"]
    stack.guard.approve(rid)
    assert not stack.guard.held_for(rec.device_id, "mega.nz")
    rec2 = run_download(stack, "dl2.mega.nz", "31.216.145.6", sport=50010)
    assert rec2.dl_state == "approved"                  # not held again
    rec3 = run_download(stack, "x.mediafire.com", "199.91.1.1", sport=50011)
    rid3 = stack.db.downloads(status="pending")[0]["id"]
    assert stack.guard.deny(rid3)["site"] == "mediafire.com"
    assert stack.db.get_download(rid3)["status"] == "denied"


def test_http_executable_held_inline(env):
    from guardian.downloads import DownloadGuard
    g = DownloadGuard(env.cfg | {"mode": "gateway"}, None, env.lists, env.alerts)
    env.insp.downloads = g
    env.dnscache.record("192.168.50.23", ["plain.example"], [("93.1.1.1", 300)])
    v = Conn(env.insp, "192.168.50.23", "93.1.1.1", 80).open_and_send(
        b"GET /downloads/FreeRobux-Setup.exe HTTP/1.1\r\nHost: plain.example\r\n\r\n")
    assert v.action == "reset" and "FreeRobux-Setup.exe" in v.reason
    a = [x for x in env.alerts.memory if x["kind"] == "download_held"][0]
    assert ".exe file" in a["detail"] and a["confidence"] >= 50
    # the whole site is held for this device until a parent decides ...
    held = Conn(env.insp, "192.168.50.23", "93.1.1.1", 80, sport=41000).open_and_send(
        b"GET /cat.jpg HTTP/1.1\r\nHost: plain.example\r\n\r\n")
    assert held.kind == "download_held"
    # ... other sites are unaffected, and ordinary files aren't held
    env.dnscache.record("192.168.50.23", ["other.example"], [("93.1.1.2", 300)])
    ok = Conn(env.insp, "192.168.50.23", "93.1.1.2", 80, sport=41001).open_and_send(
        b"GET /cat.jpg HTTP/1.1\r\nHost: other.example\r\n\r\n")
    assert ok.action == "accept"


def test_holds_and_approvals_survive_restart(stack):
    rec = run_download(stack, "dl.mega.nz", "31.216.145.5")
    rid = stack.db.downloads(status="pending")[0]["id"]
    fresh = DownloadGuard(stack.cfg, stack.db, stack.guard.lists, stack.alerts)     # gateway restarted
    assert fresh.held_for(rec.device_id, "dl.mega.nz") == rid                      # still held
    stack.guard.approve(rid)
    again = DownloadGuard(stack.cfg, stack.db, stack.guard.lists, stack.alerts)
    assert not again.held_for(rec.device_id, "mega.nz")
    assert (rec.device_id, "mega.nz") in again.approved                            # approval remembered


def run_video(o, domain, ip, sport, seconds=16):
    """1.5 MB bursts every 3rd 2-second tick: the shape of a video player."""
    o.dnscache.record("192.168.50.23", [domain], [(ip, 300)])
    tup = ("tcp", "192.168.50.23", sport, ip, 443)
    up = down = pu = pd = 0
    for i in range(seconds // 2):
        if i % 3 == 0:
            up, down, pu, pd = up + 20_000, down + 1_500_000, pu + 300, pd + 1100
        o.be.samples = [FlowSample(f"v{sport}", tup, up, down, pu, pd)]
        o.mon.ingest(o.be.samples, T0 + 500 + i * 2)
    return o.mon.active[f"v{sport}"]


def test_unknown_video_held_known_video_not(stack):
    from guardian.adult import AdultGuard
    stack.cfg["adult"]["video_sites"] = ["vimeo.com", "vimeocdn.com"]
    stack.guard.adult = AdultGuard(stack.cfg, stack.guard.lists, stack.alerts)
    rec = run_video(stack, "stream.unknown-tube.example", "45.9.9.9", 51000)
    assert rec.activity.cls == "video" and rec.dl_state == "held"
    row = stack.db.downloads(status="pending")[0]
    assert row["kind"] == "video" and row["site"] == "unknown-tube.example"
    assert stack.guard.held_for(rec.device_id, "unknown-tube.example")
    ok = run_video(stack, "player.vimeocdn.com", "151.101.9.9", 51001)
    assert ok.dl_state == "known_video"


def test_unknown_video_standard_mode_only_alerts(stack):
    from guardian.adult import AdultGuard
    stack.cfg["groups"]["kids"]["adult_protection"] = "standard"
    stack.guard.adult = AdultGuard(stack.cfg, stack.guard.lists, stack.alerts)
    rec = run_video(stack, "stream.unknown-tube.example", "45.9.9.9", 51002)
    assert rec.dl_state == "alerted" and not stack.killed
    stack.db.flush()
    assert any(a["kind"] == "video_held" for a in stack.db.alerts())
