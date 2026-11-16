"""The dashboard's friendly address: family.local / family.home.arpa."""
import os

import pytest
from dnslib import DNSRecord

from conftest import ROOT
from guardian import localname, settings
from guardian.config import load_config
from guardian.dnscache import DnsCache
from guardian.resolver import DnsTunnelDetector, GuardianResolver, QueryStats
from guardian.schedule import Scheduler
from test_components import make_stack


def test_names_and_addresses():
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    assert localname.names(cfg) == ["family.local", "family.home.arpa", "family.home", "family.lan"]
    cfg["mode"] = "gateway"
    cfg["gateway"]["lan_ip"] = "192.168.50.1"
    a = localname.addresses(cfg, "192.168.50.23")
    assert a["primary"] == "http://family.local"              # port 80 is redirected on the Pi
    assert a["fallback"] == "http://family.home.arpa"
    assert a["ip"] == "http://192.168.50.1" and a["qr_url"] == a["fallback"]
    cfg["mode"], cfg["web"]["port"] = "monitor", 8090
    a = localname.addresses(cfg, "127.0.0.1")
    assert a["primary"] == "http://family.local:8090" and a["ip"] == "http://127.0.0.1:8090"
    cfg["web"]["local_name"] = "Not Valid!"
    assert localname.base_name(cfg) == "family"                # falls back rather than breaking


@pytest.mark.parametrize("name,ok", [("family", True), ("smith-home", True), ("home2", True), ("-x", False),
                                     ("a_b", False), ("x" * 40, False), ("", False), ("bad.name", False)])
def test_label_validation(name, ok):
    assert localname.valid_label(name) is ok


def test_qr_svg():
    svg = localname.qr_svg("http://family.home.arpa")
    assert svg.startswith("<svg") and "<path" in svg and 'viewBox="0 0 ' in svg


def test_resolver_answers_dashboard_names_even_when_paused(tmp_path):
    cfg, db, lists, alerts, policy = make_stack(tmp_path, group="kids")
    cfg["mode"] = "gateway"
    cfg["gateway"]["lan_ip"] = "192.168.50.1"
    cfg["dns"].update(upstreams=["127.0.0.1"], upstream_port=9)      # nothing upstream: must not be needed
    sched = Scheduler(db, policy)
    res = GuardianResolver(cfg, policy, lists, DnsCache(), db, alerts, sched, QueryStats(),
                           DnsTunnelDetector({}, alerts))

    class H:
        client_address = ("192.168.50.9", 5353)

    def ask(name, qt="A"):
        r = res.resolve(DNSRecord.question(name, qt), H())
        return r.header.rcode, [str(a.rdata) for a in r.rr]

    did = policy.context("192.168.50.9").device_id
    db.update_device(did)
    sched.pause(did, 60)
    assert ask("family.local") == (0, ["192.168.50.1"])
    assert ask("FAMILY.home.arpa.") == (0, ["192.168.50.1"])
    assert ask("family.lan") == (0, ["192.168.50.1"])
    assert ask("family.home.arpa", "AAAA") == (0, [])                 # no IPv6 address: empty, not an error
    assert ask("other.home.arpa")[0] == 3                             # paused device: everything else refused
    cfg["web"]["local_name"] = "smiths"
    assert ask("smiths.home.arpa") == (0, ["192.168.50.1"])
    assert ask("family.home.arpa")[0] == 3


def test_wizard_sets_name(tmp_path):
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg["__base__"] = str(tmp_path)
    r = settings.apply(cfg, {"local_name": "Smith-Home"})
    assert r["restart_required"] == [] and cfg["web"]["local_name"] == "smith-home"
    with pytest.raises(ValueError):
        settings.apply(cfg, {"local_name": "smith home"})


def test_firewall_serves_dashboard_on_port_80():
    from guardian.gateway.nft import NftGateway
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    gw = NftGateway(cfg, None, None, None)
    gw.backend = "nft"
    t = gw.render()
    assert f"tcp dport 80 dnat ip to {cfg['gateway']['lan_ip']}:{cfg['web']['port']}" in t
    assert "tcp dport 443 reject with tcp reset" in t


def test_mdns_publisher_without_avahi(monkeypatch):
    monkeypatch.setattr(localname.shutil, "which", lambda name: None)
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg["mode"] = "gateway"
    p = localname.MdnsPublisher(cfg)
    p.sync()
    st = p.status()
    assert st["running"] is False and "Avahi" in st["error"]
