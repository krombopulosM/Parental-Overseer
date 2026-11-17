"""Diagnostics export and the log files behind it."""
import io
import json
import os
import subprocess
import sys
import zipfile

import pytest

from conftest import ROOT
from guardian import diagnostics
from guardian.config import load_config

H = {"X-Guardian": "1"}
KID_MAC, KID_IP, KID_NAME = "a4:5e:60:aa:bb:cc", "192.168.50.23", "Sam's iPad"


def _all_text(z: zipfile.ZipFile) -> str:
    return "\n".join(z.read(n).decode("utf-8", errors="replace") for n in z.namelist())


@pytest.fixture
def gw(tmp_path):
    from fastapi.testclient import TestClient
    from guardian.app import Guardian
    from guardian.webapp import create_app
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg.update(database=str(tmp_path / "g.db"), lists_cache_dir=str(tmp_path / "c"))
    cfg["ip_lists"] = {}
    cfg["__base__"] = str(tmp_path)
    os.makedirs(tmp_path / "logs")
    (tmp_path / "logs" / "gateway.log").write_text(
        f"2026-11-17 10:00:00 [42] [ready] serving\n2026-11-17 10:00:01 [42] ! saw {KID_MAC} at {KID_IP}\n")
    g = Guardian(cfg)
    g.monitor = g.detector = None
    c = TestClient(create_app(g), client=("127.0.0.1", 5000))
    assert c.post("/api/setup", json={"password": "longpassword"}, headers=H).status_code == 200
    g.db.update_device(KID_MAC, name=KID_NAME, group="kids", set_group=True)
    g.db.execute("UPDATE devices SET ip=?, hostname=?, mac=? WHERE device_id=?", (KID_IP, "Sams-iPad", KID_MAC, KID_MAC))
    g.alerts.emit("vpn_server", device_id=KID_MAC, client_ip=KID_IP, dst="185.159.157.5",
                  detail=f"{KID_NAME} ({KID_MAC}) tried 185.159.157.5")
    g.db.log_query(KID_MAC, KID_IP, "example.org", "A", "allowed", "")
    g.db.flush()
    return g, c


def _download(c, **opts):
    r = c.post("/api/diagnostics", json=opts, headers=H)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/zip"
    assert r.headers["content-disposition"].startswith('attachment; filename="parental-gateway-diagnostics-')
    return zipfile.ZipFile(io.BytesIO(r.content))


def test_bundle_contents_and_privacy(gw):
    g, c = gw
    z = _download(c, note="Sam's iPad can't load YouTube")
    names = set(z.namelist())
    for must in ("README.txt", "NOTE.txt", "summary.json", "status.json", "environment.json", "updates.json",
                 "config/effective.json", "config/protections.json", "database.json", "devices.json",
                 "rules.json", "alerts.json", "lists.json", "logs/gateway.log", "inspector.json"):
        assert must in names, must
    assert not any(n.startswith("activity/") for n in names)          # browsing left out by default
    text = _all_text(z)
    for secret in (KID_NAME, KID_MAC, KID_IP, "Sams-iPad", g.db.get_setting("admin_hash")):
        assert secret not in text, secret
    assert "admin_hash" not in json.loads(z.read("database.json"))["settings"]
    assert "185.159.157.5" in text                                      # public addresses kept: that's what got blocked
    devs = json.loads(z.read("devices.json"))
    kid = next(d for d in devs if d["group"] == "kids")
    assert kid["label"] == kid["name"] and kid["mac"].startswith("mac-") and kid["ip"].startswith("lan-ip-")
    # the same device keeps the same label everywhere
    assert kid["mac"] in z.read("logs/gateway.log").decode() and kid["label"] in z.read("NOTE.txt").decode()
    s = json.loads(z.read("summary.json"))
    assert s["made_by"] == "dashboard" and s["anonymised"] is True and s["version"]
    assert json.loads(z.read("database.json"))["quick_check"] == ["ok"]


def test_bundle_options(gw):
    g, c = gw
    z = _download(c, anonymise=False, activity=True, alerts=False)
    names = set(z.namelist())
    assert "activity/dns-queries.json" in names and "alerts.json" not in names
    text = _all_text(z)
    assert KID_NAME in text and KID_MAC in text
    assert g.db.get_setting("admin_hash") not in text                  # never, even un-anonymised


def test_endpoint_needs_sign_in_and_csrf_header(gw):
    g, c = gw
    from fastapi.testclient import TestClient
    anon = TestClient(c.app, client=("192.168.50.9", 5000))
    assert anon.post("/api/diagnostics", json={}, headers=H).status_code == 401
    assert c.post("/api/diagnostics", json={}).status_code == 403


def test_one_broken_part_does_not_stop_the_bundle(gw, monkeypatch):
    g, c = gw
    monkeypatch.setattr(g, "status", lambda: 1 / 0)
    z = _download(c)
    assert "status.json" not in z.namelist() and "summary.json" in z.namelist()
    assert "ZeroDivisionError" in z.read("collector-errors.txt").decode()


def test_redactor():
    r = diagnostics.Redactor(True, [{"name": "Mum's laptop", "hostname": "MUMS-PC"}], gateway_ip="192.168.50.1")
    out = r.text("Mum's laptop MUMS-PC 192.168.50.1 192.168.50.7 192.168.50.7 172.16.0.9 172.32.0.9 8.8.8.8 "
                 "AA-BB-CC-DD-EE-FF aa:bb:cc:dd:ee:ff https://user:tok3n@github.com/x.git v1.2.3.4.5")
    assert out.split()[:2] == ["device-1", "device-1"]
    assert "gateway-ip lan-ip-2 lan-ip-2 lan-ip-3 172.32.0.9 8.8.8.8" in out    # 172.32 isn't private
    assert out.count("mac-1") == 2                                                  # same MAC, two spellings
    assert "tok3n" not in out and "<credentials removed>@github.com" in out
    assert "v1.2.3.4.5" in out                                                       # not an address
    off = diagnostics.Redactor(False, [{"name": "Mum's laptop"}])
    assert off.text("Mum's laptop https://a:b@x.y") == "Mum's laptop https://<credentials removed>@x.y"


def test_command_line(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "config.local.yaml").write_text(f"database: {tmp_path / 'g.db'}\n")
    out = tmp_path / "out"
    out.mkdir()
    env = dict(os.environ, GUARDIAN_DATA_DIR=str(data))
    p = subprocess.run([sys.executable, os.path.join(ROOT, "run.py"), "--diagnostics", str(out)],
                       capture_output=True, text=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    files = list(out.iterdir())
    assert len(files) == 1 and files[0].suffix == ".zip" and "Diagnostics written to" in p.stdout
    z = zipfile.ZipFile(files[0])
    assert json.loads(z.read("summary.json"))["made_by"] == "command line"
    assert "status.json" not in z.namelist()                            # nothing running to ask


LOG_SCRIPT = r'''
import sys, threading, time, os
sys.path.insert(0, sys.argv[1])
from guardian import logs
logs.MAX_BYTES = 2000
path = logs.capture(sys.argv[2], "t")
print("hello", end="")
print(" world")
def boom():
    raise ValueError("background job broke")
t = threading.Thread(target=boom, name="lists"); t.start(); t.join()
sys.stderr.flush()
open(os.path.join(sys.argv[2], "before-rotation.txt"), "w").write(open(path).read())
for i in range(400):
    print(f"line {i} " + "x" * 40)
sys.stdout.flush()
'''


def test_log_capture_and_rotation(tmp_path):
    p = subprocess.run([sys.executable, "-c", LOG_SCRIPT, ROOT, str(tmp_path)], capture_output=True, text=True,
                       timeout=60)
    assert "hello world" in p.stdout                                    # still printed as before
    files = sorted(os.listdir(tmp_path / "logs"))
    assert files[0] == "t.log" and "t.log.1" in files and len(files) <= 4
    assert len((tmp_path / "logs" / "t.log").read_text()) < 4000            # rotated, not growing forever
    everything = (tmp_path / "before-rotation.txt").read_text()
    assert "hello world" in everything and "[log] t started" in everything
    assert "[crash] thread lists stopped: ValueError: background job broke" in everything
    assert "Traceback" in everything
    line = next(ln for ln in everything.splitlines() if "hello world" in ln)
    assert line[:4].isdigit() and line[19:21] == " [" and line.endswith("] hello world")    # time [pid] text
    assert any(" ! " in ln for ln in everything.splitlines() if "Traceback" in ln)    # stderr lines marked
