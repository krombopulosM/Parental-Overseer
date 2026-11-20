"""The Devices table's actions: block until unblocked, forget, "this device", and
that the page ships the table script."""
import os
import time

from conftest import ROOT
from guardian.config import load_config
from guardian.schedule import FOREVER

H = {"X-Guardian": "1"}
KID, ME = "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:01"


def _app(tmp_path):
    from fastapi.testclient import TestClient
    from guardian.app import Guardian
    from guardian.webapp import create_app
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg.update(database=str(tmp_path / "g.db"), lists_cache_dir=str(tmp_path / "c"), mode="monitor")
    cfg["ip_lists"] = {}
    cfg["__base__"] = str(tmp_path)
    g = Guardian(cfg)
    g.monitor = g.detector = None
    now = time.time()
    for mac, ip, grp in ((KID, "192.168.1.31", "kids"), (ME, "192.168.1.20", "adults")):
        g.db.execute("INSERT INTO devices (device_id, mac, ip, group_name, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
                     (mac, mac, ip, grp, now - 100, now))
    g.policy.identity.learn("192.168.1.20", ME)
    g.policy.reload()
    c = TestClient(create_app(g), client=("127.0.0.1", 5000))
    assert c.post("/api/setup", json={"password": "longpassword"}, headers=H).status_code == 200
    return g, c


def _dev(c, did):
    return next(d for d in c.get("/api/devices").json()["devices"] if d["device_id"] == did)


def test_block_all_traffic_until_unblocked(tmp_path):
    g, c = _app(tmp_path)
    assert c.post(f"/api/devices/{KID}/pause", json={"minutes": -1}, headers=H).status_code == 200
    d = _dev(c, KID)
    assert d["paused"] and d["blocked_all"] and d["paused_reason"] == "blocked until you unblock it"
    assert g.db.get_device(KID)["paused_until"] >= FOREVER
    assert g.scheduler.is_paused(KID, "kids", now=time.time() + 400 * 86400)[0]      # never runs out
    assert KID in g._compute_sets()[1]                                                 # in the firewall's paused set
    c.post(f"/api/devices/{KID}/pause", json={"minutes": 0}, headers=H)
    d = _dev(c, KID)
    assert not d["paused"] and not d["blocked_all"]
    c.post(f"/api/devices/{KID}/pause", json={"minutes": 30}, headers=H)
    d = _dev(c, KID)
    assert d["paused"] and not d["blocked_all"] and d["paused_reason"].startswith("paused until ")


def test_forget_device(tmp_path):
    g, c = _app(tmp_path)
    c.post(f"/api/devices/{KID}", json={"name": "Sam's iPad"}, headers=H)
    c.post(f"/api/devices/{KID}/pause", json={"minutes": -1}, headers=H)
    assert c.delete(f"/api/devices/{KID}", headers=H).status_code == 200
    assert KID not in [d["device_id"] for d in c.get("/api/devices").json()["devices"]]
    assert not g.scheduler.is_paused(KID, g.cfg["default_group"])[0]
    assert g.policy.group_name(KID) == g.cfg["default_group"]                          # back to the default if seen again
    assert c.delete(f"/api/devices/{KID}", headers=H).status_code == 404


def test_devices_says_which_is_this_device(tmp_path):
    from fastapi.testclient import TestClient
    g, c = _app(tmp_path)
    assert c.get("/api/devices").json()["you"] != ME                                   # 127.0.0.1 isn't a LAN device
    lan = TestClient(c.app, client=("192.168.1.20", 5000))
    lan.cookies = c.cookies
    body = lan.get("/api/devices").json()
    assert body["you"] == ME
    assert {"blocked_all", "first_seen"} <= set(body["devices"][0])


def test_page_loads_the_device_table(tmp_path):
    g, c = _app(tmp_path)
    assert '<script src="/static/devices.js"></script>' in c.get("/").text
    r = c.get("/static/devices.js")
    assert r.status_code == 200 and "views.devices" in r.text and "contextmenu" in r.text
