"""First-run setup wizard: settings layer and API."""
import os

import pytest
import yaml

from conftest import ROOT
from guardian import settings
from guardian.config import load_config

H = {"X-Guardian": "1"}


def _cfg(tmp_path, mode="monitor"):
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg.update(database=str(tmp_path / "g.db"), lists_cache_dir=str(tmp_path / "c"), mode=mode)
    cfg["ip_lists"] = {}
    cfg["__base__"] = str(tmp_path)          # config.local.yaml goes here, not into the repo
    return cfg


@pytest.fixture
def client(tmp_path):
    from fastapi.testclient import TestClient
    from guardian.app import Guardian
    from guardian.webapp import create_app
    g = Guardian(_cfg(tmp_path))
    g.monitor = g.detector = None
    c = TestClient(create_app(g), client=("127.0.0.1", 5000))
    assert c.post("/api/setup", json={"password": "longpassword"}, headers=H).status_code == 200
    restarts = []
    g.restart = lambda delay=1.0: restarts.append(delay)
    return g, c, restarts


def test_validate_categories_protections_and_choices(tmp_path):
    cfg = _cfg(tmp_path)
    v = settings.validate({"categories": ["adult", "nonsense", "bypass"], "downloads": "review_all",
                           "protections": {"tor": False, "non_web": "games"}}, cfg)
    assert v["categories"] == ["adult"]          # VPN/Tor/proxy sites follow the protection switches
    assert v["protections"] == {"tor": False, "non_web": "games"}
    with pytest.raises(ValueError):
        settings.validate({"protections": {"tor": "maybe"}}, cfg)
    with pytest.raises(ValueError):
        settings.validate({"protections": {"teleport": True}}, cfg)
    with pytest.raises(ValueError):
        settings.validate({"downloads": "maybe"}, cfg)
    with pytest.raises(ValueError):
        settings.validate({"dns_port": 80}, cfg)
    gw = _cfg(tmp_path, "gateway")
    assert "dns_port" not in settings.validate({"dns_port": 5310, "web_host": "0.0.0.0"}, gw)


def test_apply_writes_local_config_and_applies_live(tmp_path):
    cfg = _cfg(tmp_path)
    groups_obj = cfg["groups"]["kids"]
    res = settings.apply(cfg, {**settings.PRESETS["light"]["values"], "dns_port": 5310, "retention_days": 14})
    assert res["restart_required"] == ["dns_port"]
    assert cfg["downloads"]["policy"] == "off"
    assert cfg["adult"]["mode"] == "standard"
    assert cfg["retention_days"] == 14
    assert cfg["dns"]["listen_port"] != 5310                 # needs the restart first
    assert cfg["groups"]["kids"] is groups_obj                # updated in place
    assert cfg["groups"]["quarantine"]["categories"] == ["adult", "gambling", "torrent"]
    assert cfg["protections"]["vpn"] is True
    assert cfg["adult"]["family_dns"]
    local = yaml.safe_load(open(tmp_path / "config.local.yaml"))
    assert local["dns"]["listen_port"] == 5310
    assert local["downloads"]["policy"] == "off"
    # a fresh load of a config in that directory picks the local file up
    (tmp_path / "config.yaml").write_text(open(os.path.join(ROOT, "config.yaml")).read())
    again = load_config(str(tmp_path / "config.yaml"))
    assert again["dns"]["listen_port"] == 5310 and again["downloads"]["policy"] == "off"
    settings.apply(cfg, {"family_dns": False})
    assert cfg["adult"]["family_dns"] == []
    assert yaml.safe_load(open(tmp_path / "config.local.yaml"))["retention_days"] == 14   # kept


def test_wizard_flow(client):
    g, c, restarts = client
    assert c.get("/api/session").json()["setup_complete"] is False
    g.db.update_device("aa:bb:cc:00:00:01")
    w = c.get("/api/wizard").json()
    assert w["complete"] is False and "strict" in w["presets"]
    assert any(cat["key"] == "adult" for cat in w["categories"])
    assert w["environment"]["checks"] and w["environment"]["mode"] == "monitor"
    assert w["values"]["adult_mode"] in ("strict", "standard", "off")

    r = c.post("/api/wizard/apply", headers=H, json={
        "values": {**settings.PRESETS["balanced"]["values"], "categories": ["adult", "gambling"]},
        "devices": [{"device_id": "aa:bb:cc:00:00:01", "name": "Sam's tablet", "group": "kids"}],
        "bedtime": {"enabled": True, "start": "21:00", "end": "07:00", "days": "sun,mon,tue,wed,thu",
                    "groups": ["kids", "adults"]},
    })
    assert r.status_code == 200, r.text
    assert r.json()["restart_required"] == []
    assert c.get("/api/session").json()["setup_complete"] is True
    # applied to the running components
    assert g.downloads.default_policy == "review_suspicious"
    assert g.adult.unknown_video == "alert"
    assert g.resolver.adult is g.adult and g.inspector.adult is g.adult and g.downloads.adult is g.adult
    assert g.cfg["groups"]["kids"]["categories"] == ["adult", "gambling"]
    dev = g.db.get_device("aa:bb:cc:00:00:01")
    assert dev["name"] == "Sam's tablet" and dev["group_name"] == "kids"
    scheds = g.db.list_schedules()
    assert [(s["target"], s["start"]) for s in scheds] == [("kids", "21:00")]   # never schedules adults off

    # running it again replaces the wizard's bedtime instead of adding another
    c.post("/api/wizard/apply", headers=H, json={"values": {}, "bedtime": {"enabled": True, "start": "20:30",
                                                                          "end": "07:00", "groups": ["kids"]}})
    scheds = g.db.list_schedules()
    assert len(scheds) == 1 and scheds[0]["start"] == "20:30"
    assert c.get("/api/wizard").json()["bedtime"]["start"] == "20:30"
    c.post("/api/wizard/apply", headers=H, json={"values": {}, "bedtime": {"enabled": False}})
    assert g.db.list_schedules() == []


def test_wizard_restart_and_validation(client):
    g, c, restarts = client
    r = c.post("/api/wizard/apply", headers=H, json={"values": {"dns_port": 5310}})
    assert r.json()["restart_required"] == ["dns_port"]
    assert c.post("/api/wizard/apply", headers=H, json={"values": {"adult_mode": "loose"}}).status_code == 400
    assert c.post("/api/system/restart", headers=H).status_code == 200
    assert restarts == [1.0]


def test_wizard_needs_login_and_skip(client):
    g, c, _ = client
    from fastapi.testclient import TestClient
    anon = TestClient(c.app, client=("192.168.1.9", 5000))
    assert anon.get("/api/wizard").status_code == 401
    assert anon.post("/api/wizard/apply", headers=H, json={}).status_code == 401
    assert c.post("/api/wizard/skip", headers=H).status_code == 200
    assert c.get("/api/session").json()["setup_complete"] is True


def test_sessions_survive_restart_but_not_password_change(tmp_path):
    from guardian.auth import Auth
    from guardian.db import DB
    db = DB(str(tmp_path / "a.db"))
    a = Auth(db)
    a.set_password("longpassword")
    tok = a.login("longpassword", "10.0.0.5")
    assert tok and tok not in (db.get_setting("sessions") or "")     # only a hash is stored
    assert Auth(db).check(tok)                                        # a restarted service still knows it
    b = Auth(db)
    b.logout(tok)
    assert not Auth(db).check(tok)
    tok2 = b.login("longpassword", "10.0.0.5")
    b.set_password("anotherpassword")
    assert not Auth(db).check(tok2)
    db.close()


def test_protections_api(client):
    g, c, _ = client
    p = c.get("/api/protections").json()
    assert {d["key"] for d in p["definitions"]} >= {"vpn", "tor", "non_web"}
    consoles = next(x for x in p["groups"] if x["name"] == "consoles")
    assert consoles["overrides"]["non_web"] == "games" and consoles["effective"]["tor"] is True
    # house-wide Tor off, then back on for consoles only
    r = c.post("/api/protections", headers=H, json={"group": "all", "key": "tor", "value": False})
    assert r.status_code == 200 and r.json()["global"]["tor"] is False
    r = c.post("/api/protections", headers=H, json={"group": "consoles", "key": "tor", "value": True})
    eff = {x["name"]: x["effective"] for x in r.json()["groups"]}
    assert eff["consoles"]["tor"] is True and eff["kids"]["tor"] is False
    r = c.post("/api/protections", headers=H, json={"group": "consoles", "key": "tor", "value": None})
    assert next(x for x in r.json()["groups"] if x["name"] == "consoles")["effective"]["tor"] is False
    assert c.post("/api/protections", headers=H, json={"group": "adults", "key": "tor", "value": True}).status_code == 400
    assert c.post("/api/protections", headers=H, json={"group": "all", "key": "tor", "value": None}).status_code == 400
    # the wizard carries them too
    w = c.get("/api/wizard").json()
    assert w["values"]["protections"]["tor"] is False and w["protections"]
