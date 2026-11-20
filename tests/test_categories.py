"""Granular site categories: each group blocks its own set (adult yes, gambling no...),
and one device can be allowed or blocked a category on top of its group's choice."""
import os
import time

from conftest import ROOT
from guardian.config import load_config

H = {"X-Guardian": "1"}
SAM, MIA = "aa:bb:cc:00:00:31", "aa:bb:cc:00:00:32"


def _app(tmp_path):
    from fastapi.testclient import TestClient
    from guardian.app import Guardian
    from guardian.webapp import create_app
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg.update(database=str(tmp_path / "g.db"), lists_cache_dir=str(tmp_path / "c"), mode="monitor")
    cfg["ip_lists"] = {}
    cfg["__data__"] = str(tmp_path)            # config.local.yaml goes here; built-in lists stay found
    g = Guardian(cfg)
    g.monitor = g.detector = None
    g.lists.load()
    now = time.time()
    for mac, ip in ((SAM, "192.168.1.31"), (MIA, "192.168.1.32")):
        g.db.execute("INSERT INTO devices (device_id, mac, ip, group_name, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
                     (mac, mac, ip, "kids", now, now))
    g.policy.reload()
    c = TestClient(create_app(g), client=("127.0.0.1", 5000))
    assert c.post("/api/setup", json={"password": "longpassword"}, headers=H).status_code == 200
    return g, c


def _blocked(g, mac, ip, name):
    return g.policy.decide(g.policy.context(ip, mac), name).block


def test_group_categories_switch_independently(tmp_path):
    g, c = _app(tmp_path)
    cats = c.get("/api/categories").json()
    keys = {x["key"] for x in cats["categories"]}
    assert {"adult", "torrent"} <= keys and not keys & {"vpn", "tor", "proxy", "doh", "bypass"}
    kids = next(x for x in cats["groups"] if x["name"] == "kids")
    assert "adult" in kids["categories"] and "torrent" in kids["categories"]
    # allow gambling for kids, keep adult blocked
    r = c.post("/api/categories", json={"group": "kids", "category": "torrent", "blocked": False}, headers=H)
    assert r.status_code == 200 and "torrent" not in r.json()["categories"]
    assert not _blocked(g, SAM, "192.168.1.31", "thepiratebay.org")
    assert _blocked(g, SAM, "192.168.1.31", "pornhub.com")
    # saved for the next start
    import yaml
    with open(tmp_path / "config.local.yaml") as fh:
        saved = yaml.safe_load(fh)["groups"]["kids"]["categories"]
    assert "torrent" not in saved and "adult" in saved
    assert c.post("/api/categories", json={"group": "kids", "category": "nonsense", "blocked": True},
                  headers=H).status_code == 400


def test_one_child_allowed_what_another_isnt(tmp_path):
    g, c = _app(tmp_path)
    assert _blocked(g, SAM, "192.168.1.31", "thepiratebay.org") and _blocked(g, MIA, "192.168.1.32", "thepiratebay.org")
    r = c.post(f"/api/devices/{SAM}", json={"category_overrides": {"torrent": "allow"}}, headers=H)
    assert r.status_code == 200
    assert not _blocked(g, SAM, "192.168.1.31", "thepiratebay.org")          # Sam: allowed
    assert _blocked(g, MIA, "192.168.1.32", "thepiratebay.org")              # Mia: still blocked
    # and the other way: block something the group allows, for one child only
    c.post("/api/categories", json={"group": "kids", "category": "filehost", "blocked": False}, headers=H)
    c.post(f"/api/devices/{MIA}", json={"category_overrides": {"filehost": "block"}}, headers=H)
    devs = {d["device_id"]: d for d in c.get("/api/devices").json()["devices"]}
    assert devs[SAM]["category_overrides"] == {"torrent": "allow"} and "torrent" not in devs[SAM]["categories"]
    assert devs[MIA]["category_overrides"] == {"filehost": "block"} and "filehost" in devs[MIA]["categories"]
    # back to the group's setting
    c.post(f"/api/devices/{SAM}", json={"category_overrides": {"torrent": None}}, headers=H)
    assert _blocked(g, SAM, "192.168.1.31", "thepiratebay.org")
    assert c.post(f"/api/devices/{SAM}", json={"category_overrides": {"torrent": "maybe"}},
                  headers=H).status_code == 400


def test_copied_identity_gets_no_allowances(tmp_path):
    g, c = _app(tmp_path)
    c.post(f"/api/devices/{SAM}", json={"category_overrides": {"adult": "allow"}}, headers=H)
    assert not _blocked(g, SAM, "192.168.1.31", "pornhub.com")
    g.db.set_suspect(SAM, True)                                         # its MAC looks copied
    g.policy.reload()
    assert _blocked(g, SAM, "192.168.1.31", "pornhub.com")


def test_adult_layers_follow_the_adult_category(tmp_path):
    from guardian.adult import AdultGuard
    g, c = _app(tmp_path)
    a = AdultGuard(g.cfg, g.lists)
    ctx = g.policy.context("192.168.1.31", SAM)
    assert a.mode(ctx) != "off" and a.check_name(ctx, "xxx-tube.example")
    assert a.safesearch_target("www.google.com", ctx) == "forcesafesearch.google.com"
    c.post(f"/api/devices/{SAM}", json={"category_overrides": {"adult": "allow"}}, headers=H)
    ctx = g.policy.context("192.168.1.31", SAM)
    assert a.mode(ctx) == "off" and a.check_name(ctx, "xxx-tube.example") is None
    assert a.safesearch_target("www.google.com", ctx) == "forcesafesearch.google.com"   # search: separate switch
    c.post(f"/api/devices/{SAM}", json={"category_overrides": {"unsafe_search": "allow"}}, headers=H)
    assert a.safesearch_target("www.google.com", g.policy.context("192.168.1.31", SAM)) is None
    assert a.unknown_video_policy(g.cfg["groups"]["kids"], g.policy.categories_for(SAM)) == "off"
    assert a.unknown_video_policy(g.cfg["groups"]["kids"], g.policy.categories_for(MIA)) != "off"
