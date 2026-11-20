"""The ready-made card: settings left on the card, which port is which, and
choosing the dashboard password from the home network right after start-up."""
import os

import pytest

from conftest import ROOT
from guardian import appliance as ap
from guardian.auth import Auth
from guardian.config import load_config
from guardian.db import DB

H = {"X-Guardian": "1"}


def test_settings_file_is_one_fixed_block():
    raw = ap.render_settings()
    assert len(raw) == ap.SETTINGS_SIZE and raw.startswith(ap.MARKER.encode())
    full = ap.render_settings({"password_hash": "x" * 200, "dashboard_name": "smiths", "lan_ip": "10.9.0.1",
                               "ssh_public_key": "ssh-ed25519 " + "A" * 68 + " me@laptop"})
    assert len(full) == ap.SETTINGS_SIZE
    vals = ap.parse_settings(full)
    assert vals["dashboard_name"] == "smiths" and vals["lan_ip"] == "10.9.0.1" and "ssh_public_key" in vals
    assert ap.parse_settings(raw) == {}                                  # the empty template sets nothing


def test_apply_settings_sets_password_and_wipes_it_from_the_card(tmp_path):
    db = DB(str(tmp_path / "g.db"))
    card = tmp_path / ap.SETTINGS_FILE
    card.write_bytes(ap.render_settings({"password_hash": Auth.make_hash("correct horse"),
                                         "dashboard_name": "Smiths", "lan_ip": "10.20.0.1/16"}))
    local = tmp_path / "config.local.yaml"
    done = ap.apply_settings(str(card), db, str(local))
    assert "password" in done and Auth(db).verify("correct horse")
    after = card.read_bytes()
    assert len(after) == ap.SETTINGS_SIZE and b"pbkdf2" not in after          # the hash doesn't stay on the card
    assert ap.parse_settings(after)["dashboard_name"] == "Smiths"             # the rest does
    cfg = ap.read_local(str(local))
    assert cfg["web"]["local_name"] == "smiths"
    assert cfg["appliance"] == {"lan_ip": "10.20.0.1", "lan_prefix": 16}
    assert ap.apply_settings(str(card), db, str(local)) == []                 # nothing new the second time
    db.close()


def test_bad_settings_are_ignored(tmp_path):
    db = DB(str(tmp_path / "g.db"))
    card = tmp_path / ap.SETTINGS_FILE
    card.write_bytes(ap.render_settings({"dashboard_name": "not a name!", "lan_ip": "8.8.8.8"}))
    assert ap.apply_settings(str(card), db, str(tmp_path / "l.yaml")) == []
    card.write_bytes(ap.render_settings({"password_hash": "pbkdf2_sha256$1$aa$bb"}))
    with pytest.raises(ValueError):
        ap.apply_settings(str(card), db, str(tmp_path / "l.yaml"))
    assert not Auth(db).has_password()
    db.close()


@pytest.mark.parametrize("wired,route,configured,want", [
    (["eth0", "eth1"], "eth0", None, ("eth0", "eth1")),
    (["eth0", "eth1"], "eth1", None, ("eth1", "eth0")),          # cables swapped: still right
    (["eth0", "eth1"], None, None, ("eth0", "eth1")),            # router not up yet: built-in port is the internet side
    (["eth0"], "eth0", None, ("eth0", None)),                    # no USB adapter yet
    (["eth0", "eth1"], "eth0", ("eth1", "eth0"), ("eth1", "eth0")),   # a previous choice is kept
    (["eth0", "eth2"], "eth0", ("eth0", "eth1"), ("eth0", "eth2")),   # ... unless its port went away
    ([], None, None, (None, None)),
])
def test_choose_roles(wired, route, configured, want):
    assert ap.choose_roles(wired, route, configured) == want


def test_wired_interfaces(tmp_path):
    for n, wireless, device in (("lo", False, False), ("eth0", False, True), ("wlan0", True, True),
                                ("enx00e04c680001", False, True), ("veth1", False, False)):
        d = tmp_path / n
        d.mkdir()
        if wireless:
            (d / "wireless").mkdir()
        if device:
            (d / "device").mkdir()
    assert ap.wired_interfaces(str(tmp_path)) == ["eth0", "enx00e04c680001"]


def test_setup_window():
    cfg = {"mode": "gateway", "appliance": {"setup_window_minutes": 30},
           "gateway": {"lan_subnets": ["192.168.50.0/24"]}}
    assert ap.setup_from_network(cfg, "192.168.50.120", age=60)[0]
    late = ap.setup_from_network(cfg, "192.168.50.120", age=31 * 60)
    assert not late[0] and "Unplug its power" in late[1]
    assert not ap.setup_from_network(cfg, "203.0.113.9", age=60)[0]          # not from the internet side
    assert not ap.setup_from_network(cfg, "192.168.1.5", age=60)[0]          # not from the ISP router's network
    one_port = {"mode": "monitor", "appliance": {"setup_window_minutes": 30}}
    assert ap.setup_from_network(one_port, "192.168.1.5", age=60)[0]         # one port: the home network is private
    assert not ap.setup_from_network({"mode": "gateway"}, "192.168.50.120", age=1)[0]   # not a card: never


def test_dashboard_setup_from_the_home_network(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from guardian.app import Guardian
    from guardian.webapp import create_app
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg.update(database=str(tmp_path / "g.db"), lists_cache_dir=str(tmp_path / "c"), mode="monitor")
    cfg["ip_lists"] = {}
    cfg["__base__"] = str(tmp_path)
    cfg["appliance"] = {"setup_window_minutes": 30}
    g = Guardian(cfg)
    g.monitor = g.detector = None
    app = create_app(g)
    phone = TestClient(app, client=("192.168.1.23", 5000))
    monkeypatch.setattr(ap, "boot_age", lambda *a: 31 * 60.0)
    s = phone.get("/api/session").json()
    assert not s["setup_allowed"] and "Unplug" in s["setup_hint"]
    assert phone.post("/api/setup", json={"password": "longpassword"}, headers=H).status_code == 403
    monkeypatch.setattr(ap, "boot_age", lambda *a: 120.0)
    assert phone.get("/api/session").json()["setup_allowed"]
    assert phone.post("/api/setup", json={"password": "longpassword"}, headers=H).status_code == 200
    assert phone.get("/api/devices").status_code == 200                      # signed in
    other = TestClient(app, client=("192.168.1.24", 5000))
    assert other.post("/api/setup", json={"password": "x" * 12}, headers=H).status_code == 409   # only once


def test_ssh_key(tmp_path, monkeypatch):
    import pwd
    calls = []
    fake = pwd.struct_passwd(("pgadmin", "x", os.getuid(), os.getgid(), "", str(tmp_path), "/bin/sh"))
    monkeypatch.setattr(pwd, "getpwnam", lambda n: fake)
    assert not ap.enable_ssh_key("not a key", run=lambda *a, **k: calls.append(a))
    key = "ssh-ed25519 " + "A" * 68 + " parent@laptop"
    assert ap.enable_ssh_key(key, run=lambda *a, **k: calls.append(a))
    assert (tmp_path / ".ssh" / "authorized_keys").read_text() == key + "\n"
    assert calls and "ssh.service" in calls[0][0]
    assert not ap.enable_ssh_key(key, run=lambda *a, **k: calls.append(a))   # already there


def test_boot_sets_up_the_ports(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    boot = tmp_path / "boot"
    boot.mkdir()
    (boot / ap.SETTINGS_FILE).write_bytes(ap.render_settings({"password_hash": Auth.make_hash("pa55word!")}))
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(data))
    monkeypatch.setattr(ap, "BOOT_DIRS", (str(boot),))
    monkeypatch.setattr(ap, "wired_interfaces", lambda: ["eth0", "eth1"])
    monkeypatch.setattr(ap, "default_route_interface", lambda: "eth1")       # the router is on the USB port
    ran = []
    monkeypatch.setattr(ap, "_netsetup", lambda args: ran.append(args) or 0)
    monkeypatch.setattr(ap, "settle", lambda *a: None)
    rep = ap.boot(route_timeout=0)
    assert rep["mode"] == "gateway" and rep["wan"] == "eth1" and rep["lan"] == "eth0"
    assert ran == [["gateway", "eth1", "eth0", "192.168.50.1/24"]]
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    assert cfg["mode"] == "gateway" and cfg["gateway"]["wan_interface"] == "eth1"
    assert cfg["gateway"]["lan_subnets"] == ["192.168.50.0/24"]
    db = DB(os.path.join(str(data), cfg["database"]))
    assert Auth(db).verify("pa55word!")
    db.close()
    # the USB adapter is unplugged: one-port mode, no DHCP of our own
    monkeypatch.setattr(ap, "wired_interfaces", lambda: ["eth0"])
    monkeypatch.setattr(ap, "default_route_interface", lambda: "eth0")
    rep = ap.boot(route_timeout=0)
    assert rep["mode"] == "one_port" and rep["mode_changed"] and ran[-1] == ["one_port", "eth0"]
    assert load_config(os.path.join(ROOT, "config.yaml"))["mode"] == "monitor"
    assert ap.state(load_config(os.path.join(ROOT, "config.yaml")))["mode"] == "one_port"
    # back to two ports, but the adapter now has a different name: new ports, gateway must restart
    monkeypatch.setattr(ap, "wired_interfaces", lambda: ["eth0", "enx00e04c680001"])
    rep = ap.boot(route_timeout=0)
    assert rep["mode"] == "gateway" and rep["lan"] == "enx00e04c680001" and rep["changed"]
    # same again: nothing changed, no restart
    rep = ap.boot(route_timeout=0)
    assert not rep["changed"] and not rep["mode_changed"]
    # a port renamed while the gateway runs (eth1 -> usb1): the firewall must follow it
    monkeypatch.setattr(ap, "wired_interfaces", lambda: ["eth0", "usb1"])
    rep = ap.boot(route_timeout=0)
    assert rep["lan"] == "usb1" and rep["changed"]
