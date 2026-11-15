"""Every anti-bypass protection can be switched off (house-wide or per group),
and switching one off opens only the route it covers."""
import os
import struct

import pytest
import yaml

from conftest import ROOT, Conn, client_hello, tcp, udp
from guardian import protections, settings
from guardian.config import load_config
from guardian.protections import on

KID = "192.168.50.23"
SITE_IP, VPS_IP, TOR_IP = "93.184.216.34", "45.32.1.1", "203.0.113.87"
WG = b"\x01\x00\x00\x00" + os.urandom(144)
DHT = b"d1:ad2:id20:" + b"a" * 20 + b"e1:q4:ping1:t2:aa1:y1:qe"


def resolve(env, name, ip, client=KID):
    env.dnscache.record(client, [name], [(ip, 300)])


@pytest.fixture
def penv(env, tmp_path):
    """The standard stack plus the split bypass lists and a Tor relay list."""
    (tmp_path / "vpn.txt").write_text("nordvpn.com\n")
    (tmp_path / "tor.txt").write_text("torproject.org\n")
    (tmp_path / "doh.txt").write_text("dns.google\n")
    (tmp_path / "tor-ips.txt").write_text(TOR_IP + "\n")
    env.cfg["categories"].update(vpn={"files": [str(tmp_path / "vpn.txt")]},
                                 tor={"files": [str(tmp_path / "tor.txt")]},
                                 doh={"files": [str(tmp_path / "doh.txt")]})
    env.cfg["ip_lists"]["tor"] = {"files": [str(tmp_path / "tor-ips.txt")]}
    env.lists.load()
    return env


def off(env, key, value=False, group=None):
    if group:
        env.cfg["groups"][group].setdefault("protections", {})[key] = value
    else:
        env.cfg["protections"][key] = value


# ------------------------------------------------------------------ config
def test_defaults_and_legacy_group_keys(tmp_path):
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    assert cfg["protections"] == protections.DEFAULTS
    assert on(cfg, cfg["groups"]["consoles"], "non_web") == "games"
    assert on(cfg, cfg["groups"]["consoles"], "direct_ip") == "log"
    assert on(cfg, cfg["groups"]["kids"], "tor") is True
    assert on(cfg, cfg["groups"]["adults"], "vpn") is False            # adults: nothing applies
    assert on(cfg, cfg["groups"]["adults"], "non_web") == "allow"
    # an older config with the per-group keys still means the same thing
    old = yaml.safe_load(open(os.path.join(ROOT, "config.yaml")))
    old["groups"]["kids"].update(allow_udp=True, require_sni=False, dns_consistency="log")
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(old))
    cfg = load_config(str(tmp_path / "config.yaml"))
    kids = cfg["groups"]["kids"]
    assert "allow_udp" not in kids
    assert (on(cfg, kids, "non_web"), on(cfg, kids, "hidden_names"), on(cfg, kids, "direct_ip")) == \
        ("games", False, "log")


# ------------------------------------------------------------------ site lists
def test_bypass_sites_follow_their_switch(penv):
    ctx = penv.policy.context(KID)
    for name in ("nordvpn.com", "torproject.org", "dns.google", "protonvpn.com"):
        assert penv.policy.decide(ctx, name).block, name
    off(penv, "tor")
    assert not penv.policy.decide(ctx, "torproject.org").block
    assert penv.policy.decide(ctx, "nordvpn.com").block                 # VPNs still blocked
    off(penv, "encrypted_dns")
    assert not penv.policy.decide(ctx, "dns.google").block
    off(penv, "vpn")
    assert penv.policy.decide(ctx, "protonvpn.com").block               # community list: proxies still on
    off(penv, "proxies")
    assert not penv.policy.decide(ctx, "protonvpn.com").block
    assert penv.policy.decide(ctx, "pornhub.com").block                 # other categories unaffected


def test_old_bypass_category_in_a_group_no_longer_forces_blocking(penv):
    penv.cfg["groups"]["quarantine"]["categories"].append("bypass")
    off(penv, "vpn")
    off(penv, "proxies")
    assert not penv.policy.decide(penv.policy.context(KID), "protonvpn.com").block


# ------------------------------------------------------------------ Tor
def test_tor_switch(penv):
    off(penv, "direct_ip", "off")                       # isolate the Tor checks from the DNS check
    v = Conn(penv.insp, KID, TOR_IP, 443).syn()
    assert (v.action, v.kind) == ("drop", "tor")        # relay list
    assert Conn(penv.insp, KID, VPS_IP, 443).open_and_send(client_hello("www.k3jd6a2bq7x.com")).kind == "tor"
    off(penv, "tor")
    assert Conn(penv.insp, KID, TOR_IP, 443, sport=40001).syn().action == "accept"
    assert Conn(penv.insp, KID, VPS_IP, 443, sport=40002).open_and_send(
        client_hello("www.k3jd6a2bq7x.com")).action == "accept"


# ------------------------------------------------------------------ VPN
def test_vpn_switch(penv):
    v = Conn(penv.insp, KID, "185.159.157.5", 443).syn()
    assert v.kind == "vpn_server"
    off(penv, "vpn")
    v = Conn(penv.insp, KID, "185.159.157.5", 443, sport=40001).syn()
    assert v.kind == "no_dns"                            # the direct-address check still applies
    off(penv, "direct_ip", "off")
    assert Conn(penv.insp, KID, "185.159.157.5", 443, sport=40002).syn().action == "accept"


def test_vpn_protocols_follow_vpn_switch_when_udp_allowed(penv):
    off(penv, "non_web", "games")
    assert penv.insp.inspect(udp(KID, VPS_IP, 50000, 51820, WG)).kind == "blocked_udp"
    off(penv, "vpn")
    assert penv.insp.inspect(udp(KID, VPS_IP, 50001, 51820, WG)).action == "accept"


def test_learned_vpn_fingerprint_follows_vpn_switch(penv):
    hello = client_hello("relay.unknown.example")
    from guardian.protocols import parse_client_hello
    ja4 = parse_client_hello(hello).ja4

    class Rep:
        def known(self, *a):
            return False, "unknown"

        def bad_label(self, j):
            return "a VPN app" if j == ja4 else None

        def learn_bad(self, *a):
            pass
    penv.insp.reputation = Rep()
    resolve(penv, "relay.unknown.example", VPS_IP)
    assert Conn(penv.insp, KID, VPS_IP, 443).open_and_send(hello).kind == "vpn_fingerprint"
    off(penv, "vpn")
    assert Conn(penv.insp, KID, VPS_IP, 443, sport=40001).open_and_send(hello).action == "accept"


# ------------------------------------------------------------------ tricks
def test_disguised_tunnels_switch(penv):
    resolve(penv, "relay.example", VPS_IP)
    assert Conn(penv.insp, KID, VPS_IP, 443).open_and_send(b"\x8a" + os.urandom(299)).kind == "protocol_violation"
    off(penv, "disguised_tunnels")
    assert Conn(penv.insp, KID, VPS_IP, 443, sport=40001).open_and_send(
        b"\x8a" + os.urandom(299)).action == "accept"
    # ...but a recognisable VPN protocol on 443 is still a VPN
    ovpn = struct.pack("!H", 14) + b"\x38" + os.urandom(13)
    assert Conn(penv.insp, KID, VPS_IP, 443, sport=40002).open_and_send(ovpn).kind == "protocol_violation"
    off(penv, "vpn")
    assert Conn(penv.insp, KID, VPS_IP, 443, sport=40003).open_and_send(ovpn).action == "accept"


def test_hidden_names_switch(penv):
    resolve(penv, "relay.example", VPS_IP)
    resolve(penv, "cloudflare-ech.com", SITE_IP)
    assert Conn(penv.insp, KID, VPS_IP, 443).open_and_send(client_hello(None)).kind == "no_sni"
    assert Conn(penv.insp, KID, SITE_IP, 443).open_and_send(client_hello("cloudflare-ech.com")).kind == "ech"
    off(penv, "hidden_names")
    assert Conn(penv.insp, KID, VPS_IP, 443, sport=40001).open_and_send(client_hello(None)).action == "accept"
    assert Conn(penv.insp, KID, SITE_IP, 443, sport=40002).open_and_send(
        client_hello("cloudflare-ech.com")).action == "accept"


def test_direct_ip_choices(penv):
    assert Conn(penv.insp, KID, VPS_IP, 443).syn().kind == "no_dns"
    n = len(penv.alerts.memory)
    off(penv, "direct_ip", "log")
    assert Conn(penv.insp, KID, "45.32.1.2", 443).syn().action == "accept"
    assert len(penv.alerts.memory) == n + 1 and penv.alerts.memory[-1]["kind"] == "no_dns"
    off(penv, "direct_ip", "off")
    assert Conn(penv.insp, KID, "45.32.1.3", 443).syn().action == "accept"
    assert len(penv.alerts.memory) == n + 1


def test_proxies_switch_covers_http_connect(penv):
    resolve(penv, "proxy.example", VPS_IP)
    req = b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n"
    assert Conn(penv.insp, KID, VPS_IP, 80).open_and_send(req).kind == "http_proxy"
    off(penv, "proxies")
    assert Conn(penv.insp, KID, VPS_IP, 80, sport=40001).open_and_send(req).kind != "http_proxy"


# ------------------------------------------------------------------ other traffic
def test_non_web_allow_still_checks_signatures(penv):
    off(penv, "non_web", "allow")
    assert Conn(penv.insp, KID, VPS_IP, 25).syn().action == "accept"            # e.g. mail
    assert Conn(penv.insp, KID, VPS_IP, 1194).syn().kind == "blocked_port"      # OpenVPN port: VPN on
    assert Conn(penv.insp, KID, VPS_IP, 9001).syn().kind == "blocked_port"      # Tor port: Tor on
    assert penv.insp.inspect(udp(KID, VPS_IP, 6881, 6881, DHT)).kind == "torrent"
    off(penv, "vpn")
    off(penv, "tor")
    off(penv, "torrents")
    assert Conn(penv.insp, KID, VPS_IP, 1194, sport=40001).syn().action == "accept"
    assert Conn(penv.insp, KID, VPS_IP, 9001, sport=40002).syn().action == "accept"
    assert penv.insp.inspect(udp(KID, VPS_IP, 6882, 6882, DHT)).action == "accept"


def test_web_only_drops_other_ports_quietly_when_their_protection_is_off(penv):
    off(penv, "vpn")
    v = Conn(penv.insp, KID, VPS_IP, 1194).syn()
    assert v.action == "drop" and v.kind == "port"          # still not allowed, just not called a VPN
    assert "blocked_port" not in penv.kinds()


def test_torrent_switch_on_web_ports(penv):
    resolve(penv, "peer.example", VPS_IP)
    hs = b"\x13BitTorrent protocol" + b"\x00" * 8 + os.urandom(40)
    assert Conn(penv.insp, KID, VPS_IP, 443).open_and_send(hs).kind == "torrent"
    off(penv, "torrents")
    off(penv, "disguised_tunnels")
    assert Conn(penv.insp, KID, VPS_IP, 443, sport=40001).open_and_send(hs).action == "accept"


def test_network_attack_reports_switch(penv):
    penv.insp.lan_ip = "192.168.50.1"
    assert Conn(penv.insp, KID, "192.168.50.1", 22).syn().action == "drop"
    assert "gateway_probe" in penv.kinds()
    off(penv, "network_attacks")
    assert Conn(penv.insp, KID, "192.168.50.1", 22, sport=40001).syn().action == "drop"   # still refused
    assert penv.kinds().count("gateway_probe") == 1                                        # not reported


# ------------------------------------------------------------------ per-group overrides
def test_group_override_beats_house_wide(penv):
    off(penv, "tor", False)                                  # house-wide off...
    off(penv, "tor", True, group="quarantine")               # ...but on for new devices
    off(penv, "direct_ip", "off")
    assert Conn(penv.insp, KID, TOR_IP, 443).syn().kind == "tor"
    penv.policy.forced_group = "kids"
    assert Conn(penv.insp, KID, TOR_IP, 443, sport=40001).syn().action == "accept"
    off(penv, "tor", None, group="quarantine")               # back to the house-wide setting
    penv.policy.forced_group = None
    assert Conn(penv.insp, KID, TOR_IP, 443, sport=40002).syn().action == "accept"


def test_set_group_protection_persists_null_as_inherit(tmp_path):
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg["__base__"] = str(tmp_path)
    settings.set_group_protection(cfg, "consoles", "non_web", None)
    assert on(cfg, cfg["groups"]["consoles"], "non_web") == "block"      # config.yaml said games
    local = yaml.safe_load(open(tmp_path / "config.local.yaml"))
    assert local["groups"]["consoles"]["protections"]["non_web"] is None
    (tmp_path / "config.yaml").write_text(open(os.path.join(ROOT, "config.yaml")).read())
    again = load_config(str(tmp_path / "config.yaml"))
    assert on(again, again["groups"]["consoles"], "non_web") == "block"
    settings.set_group_protection(cfg, "kids", "tor", False)
    assert on(cfg, cfg["groups"]["kids"], "tor") is False
    with pytest.raises(ValueError):
        settings.set_group_protection(cfg, "adults", "tor", True)       # unfiltered
    with pytest.raises(ValueError):
        settings.set_group_protection(cfg, "kids", "non_web", "sometimes")


def test_nft_ruleset_supports_open_groups_and_per_group_lists():
    from guardian.gateway.nft import NftGateway
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    gw = NftGateway(cfg, None, None, None)
    gw.backend = "nft"
    t = gw.render()
    assert "set open_macs" in t and "ether saddr @open_macs jump udp_inspect" in t
    bad = t[t.index("chain bad_dest"):t.index("chain web")]
    assert "return" in bad and "drop" not in bad
