"""The Windows engine (WinDivert) with a simulated driver: same inspector, same
verdicts as the Pi, plus DNS answered in-engine and resets sent to the client."""
import os
import struct
import time

import pytest
from dnslib import DNSRecord

from conftest import ROOT, client_hello, tcp, udp
from guardian.gateway import windivert as wd

PC_IP, PC_MAC = "192.168.1.50", "aa:bb:cc:dd:ee:01"
PHONE = "192.168.137.23"
SITE, VPS = "93.184.216.34", "45.32.1.1"
SYN, PSH_ACK = 0x02, 0x18


class FakeHandle:
    def __init__(self, filt, layer, drop):
        self.filt, self.layer, self.drop = filt, layer, drop
        self.sent = []                 # (raw, outbound, iface)
        self.closed = False

    def recv(self):                    # the engine's loop isn't used in these tests
        time.sleep(3600)

    def send(self, raw, outbound, iface):
        self.sent.append((raw, outbound, iface))

    def close(self):
        self.closed = True


@pytest.fixture
def win(env, monkeypatch):
    """A Windows gateway on the standard test stack, this PC filtered (default group)."""
    from guardian.resolver import DnsTunnelDetector, GuardianResolver, QueryStats

    class Sched:
        def is_paused(self, *a):
            return False, ""
    env.cfg["mode"] = "gateway"
    env.cfg["dns"]["upstreams"] = ["192.0.2.53"]          # unreachable: answers here never need it
    env.cfg["adult"]["family_dns"] = []
    res = GuardianResolver(env.cfg, env.policy, env.lists, env.dnscache, None, env.alerts, Sched(), QueryStats(),
                           DnsTunnelDetector({}, env.alerts))
    handles = {}

    def opener(filt, layer="network", drop=False):
        h = FakeHandle(filt, layer, drop)
        handles[(layer, drop, filt[:20])] = h
        return h
    gw = wd.WindowsGateway(env.cfg, env.lists, None, env.insp, resolver=res, identity=env.policy.identity,
                           policy=env.policy, opener=opener)
    monkeypatch.setattr(gw, "_discover", lambda: (setattr(gw, "local_ips", {PC_IP, "192.168.137.1"}),
                                                  setattr(gw, "local_mac", PC_MAC),
                                                  env.policy.identity.learn(PC_IP, PC_MAC)))
    gw.setup()
    gw._pool = _Sync()                                    # answer DNS inline for the tests
    env.gw, env.res = gw, res
    env.h = lambda name: gw.handles[name]
    yield env
    gw.teardown()


class _Sync:
    def submit(self, fn, *a):
        fn(*a)


def resolve(env, name, ip, client=PC_IP):
    env.dnscache.record(client, [name], [(ip, 300)])


def push(env, name, raw, outbound=True, iface=(7, 0)):
    h = env.h(name)
    before = len(h.sent)
    env.gw.on_packet(name, h, raw, outbound, iface)
    return h.sent[before:]


def injected(env):
    return env.h("dns").sent


def test_handles_opened_with_the_right_filters(win):
    names = sorted(win.gw.handles)
    assert names == ["dns", "forward", "ipv6", "local"]               # hotspot up, PC filtered
    assert win.h("forward").layer == "forward" and "192.168.137.0" in win.h("forward").filt
    assert win.h("ipv6").drop is True                                 # IPv6 dropped in the driver
    assert "(tcp.DstPort != 53 or ip.DstAddr != 192.0.2.53)" in win.h("local").filt   # our own upstream queries pass
    assert "udp.DstPort == 53" in win.h("dns").filt and "192.168.137.1" in win.h("dns").filt


def test_allowed_site_passes_and_stops_being_inspected(win):
    resolve(win, "www.example.com", SITE)
    syn = tcp(PC_IP, SITE, 40000, 443, 5000, SYN)
    assert push(win, "local", syn) == [(syn, True, (7, 0))]
    hello = tcp(PC_IP, SITE, 40000, 443, 5001, PSH_ACK, client_hello("www.example.com"))
    assert push(win, "local", hello)[0][0] == hello
    for i in range(12):                                               # after the first packets: straight through
        push(win, "local", tcp(PC_IP, SITE, 40000, 443, 6000 + i, PSH_ACK, b"x"))
    fl = win.gw.flows[("tcp", PC_IP, 40000, SITE, 443)]
    assert fl.passed and win.insp.stats["packets"] <= win.gw.inspect_pkts + 1


def test_direct_ip_is_reset_back_to_the_pc(win):
    win.cfg["protections"]["direct_ip"] = "strict"
    syn = tcp(PC_IP, VPS, 40001, 443, 5000, SYN)
    assert push(win, "local", syn) == []                              # not sent on
    raw, outbound, iface = injected(win)[-1]
    p = wd.parse(raw)
    assert (p.src, p.dst, p.sport, p.dport) == (VPS, PC_IP, 443, 40001)
    assert p.flags & wd.TCP_RST and p.ack == 5001 and outbound is False   # delivered to this PC
    assert "no_dns" in win.kinds()


def test_vpn_protocol_and_server_blocked(win):
    wg = udp(PC_IP, VPS, 50000, 51820, b"\x01\x00\x00\x00" + os.urandom(144))
    assert push(win, "local", wg) == []
    assert win.gw.stats["drop"] >= 1
    assert push(win, "local", tcp(PC_IP, "185.159.157.5", 40002, 443, 1, SYN)) == []   # listed VPN server
    assert "vpn_server" in win.kinds()


def test_dns_answered_in_engine_with_filtering(win):
    q = DNSRecord.question("pornhub.com").pack()
    pkt = udp(PC_IP, "8.8.8.8", 53000, 53, q)                        # even to someone else's DNS server
    out = push(win, "dns", pkt)
    assert len(out) == 1 and out[0][0] != pkt                         # the query isn't passed on; only our reply
    raw, outbound, _ = injected(win)[-1]
    p = wd.parse(raw)
    assert (p.src, p.dst, p.sport, p.dport) == ("8.8.8.8", PC_IP, 53, 53000) and outbound is False
    ans = DNSRecord.parse(p.payload)
    assert ans.header.rcode == 3                                      # blocked: NXDOMAIN
    # the dashboard name is answered without any upstream
    push(win, "dns", udp(PC_IP, "8.8.8.8", 53001, 53, DNSRecord.question("family.home.arpa").pack()))
    ans = DNSRecord.parse(wd.parse(injected(win)[-1][0]).payload)
    assert len(ans.rr) == 1 and ans.header.rcode == 0                  # answered here, no upstream needed


def test_hotspot_device_dns_and_traffic(win, monkeypatch):
    monkeypatch.setattr(win.policy.identity, "mac_for", lambda ip: "66:77:88:99:aa:bb" if ip == PHONE else None)
    # its lookup to the hotspot's address comes in on the dns handle; the answer goes out to it
    push(win, "dns", udp(PHONE, "192.168.137.1", 41000, 53, DNSRecord.question("pornhub.com").pack()),
         outbound=False)
    raw, outbound, _ = injected(win)[-1]
    assert wd.parse(raw).dst == PHONE and outbound is True
    assert DNSRecord.parse(wd.parse(raw).payload).header.rcode == 3
    # forwarded traffic: same inspector (strict direct-address check: reset back to the phone)
    win.cfg["protections"]["direct_ip"] = "strict"
    assert push(win, "forward", tcp(PHONE, VPS, 42000, 443, 9, SYN)) == []
    rst = wd.parse(injected(win)[-1][0])
    assert rst.dst == PHONE and rst.flags & wd.TCP_RST and injected(win)[-1][1] is True
    # no reaching the home network from the hotspot
    assert push(win, "forward", tcp(PHONE, "192.168.1.1", 42001, 80, 9, SYN)) == []
    assert win.gw.stats["private_dst"] == 1 and PHONE in win.gw.seen_hotspot_clients


def test_adults_pc_is_not_diverted(win):
    win.policy.forced_group = "adults"
    win.gw.sync_device_sets(set(), set(), set(), set())
    assert "local" not in win.gw.handles and "ipv6" not in win.gw.handles and "dns" in win.gw.handles
    win.policy.forced_group = None
    win.gw.sync_device_sets(set(), set(), set(), set())
    assert "local" in win.gw.handles


def test_paused_and_killed_flows(win):
    resolve(win, "www.example.com", SITE)
    win.gw.paused = {PC_MAC}
    assert push(win, "local", tcp(PC_IP, SITE, 40010, 443, 1, SYN)) == []
    assert win.gw.stats["paused"] == 1
    win.gw.paused = set()
    assert push(win, "local", tcp(PC_IP, SITE, 40011, 443, 1, SYN))
    win.gw.kill_flow("tcp", PC_IP, 40011, SITE, 443)                  # e.g. a download held for review
    assert push(win, "local", tcp(PC_IP, SITE, 40011, 443, 2, PSH_ACK, b"more")) == []
    win.gw.block_ip(SITE, 60, "test")
    assert SITE in win.insp.dyn_blocked


def test_packet_builders_checksums():
    raw = wd.build_udp("10.0.0.1", "10.0.0.2", 53, 5000, b"hello")
    assert wd._csum(raw[:20]) == 0                                    # IP header checksum valid
    pseudo = raw[12:20] + struct.pack("!BBH", 0, 17, 13)
    assert wd._csum(pseudo + raw[20:]) == 0                           # UDP checksum valid
    rst = wd.build_tcp_rst("10.0.0.2", "10.0.0.1", 443, 40000, 7, 8)
    pseudo = rst[12:20] + struct.pack("!BBH", 0, 6, 20)
    assert wd._csum(rst[:20]) == 0 and wd._csum(pseudo + rst[20:]) == 0


def test_app_picks_the_windows_engine(tmp_path, monkeypatch):
    import sys
    from guardian.app import Guardian
    from guardian.config import load_config
    monkeypatch.setattr(sys, "platform", "win32")
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    cfg.update(mode="gateway", database=str(tmp_path / "g.db"), lists_cache_dir=str(tmp_path / "c"))
    cfg["ip_lists"] = {}
    g = Guardian(cfg)
    assert type(g.gateway).__name__ == "WindowsGateway" and g.lanwatch is None
    assert g.resolver.up_tcp is True                                  # upstream DNS over TCP on Windows
    assert g.downloads.kill_flow == g.gateway.kill_flow
    from guardian import localname
    assert localname.port_suffix(cfg) == ":8080"                      # no port-80 redirect on Windows
    g.db.close()


def test_windows_check_runs_end_to_end_with_a_simulated_driver(tmp_path, monkeypatch):
    """Not proof that Windows blocks (only a real PC can show that) - proof that the
    check's own code runs start to finish, reports, and switches the filter off."""
    import json as _json
    import sys
    from guardian import environment, wincheck
    from guardian.gateway import windivert
    opened = []

    class Fake(FakeHandle):
        def __init__(self, filt, layer="network", drop=False):
            super().__init__(filt, layer, drop)
            opened.append(self)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(environment, "is_admin", lambda: True)
    monkeypatch.setattr(windivert, "available", lambda: (True, ""))
    monkeypatch.setattr(windivert, "DivertHandle", Fake)
    monkeypatch.setattr(wincheck, "_resolve", lambda n: ["93.184.216.34"] if n == "example.com" else "refused (11001)")
    monkeypatch.setattr(wincheck, "_tls", lambda ip, sni, timeout=6: "reset")
    monkeypatch.setattr(wincheck, "_flushdns", lambda: None)

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(wincheck.urllib.request, "urlopen", lambda *a, **k: Resp())
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GUARDIAN_DATA_DIR", raising=False)
    wincheck.RESULTS.clear()
    code = wincheck.run(os.path.join(ROOT, "config.yaml"))
    report = _json.loads((tmp_path / "windows-check-report.txt").read_text())
    names = [r["check"] for r in report["results"]]
    assert "normal site resolves" in names and "adult site doesn't resolve" in names
    assert report["environment"]["handles"] and all(h.closed for h in opened if h.filt != "false")
    assert code in (0, 1)
    os.environ.pop("GUARDIAN_DATA_DIR", None)


def test_filters_use_only_what_windivert_accepts(win):
    """WinDivert's filter language can negate a single test ("not tcp", "!loopback")
    but not a bracketed group: "not (a and b)" makes the driver refuse to open
    (WinError 87). Checked against WinDivert 2.2's own filter compiler."""
    import re
    filters = dict(win.gw.filters())
    filters["ipv6"] = ("outbound and !loopback and ipv6", "network", True)
    for name, (filt, _layer, _drop) in filters.items():
        assert not re.search(r"(\bnot|!)\s*\(", filt), f"{name}: negated group in {filt}"
        assert filt.count("(") == filt.count(")"), name
    local = filters["local"][0]
    assert "(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255)" in local
    assert "(tcp.DstPort != 53 or ip.DstAddr != 192.0.2.53)" in local          # our own upstream DNS


def test_open_failure_names_the_filter(env, monkeypatch):
    def opener(filt, layer="network", drop=False):
        raise OSError(87, "The parameter is incorrect")
    env.cfg["mode"] = "gateway"
    gw = wd.WindowsGateway(env.cfg, env.lists, None, env.insp, identity=env.policy.identity,
                           policy=env.policy, opener=opener)
    monkeypatch.setattr(gw, "_discover", lambda: (setattr(gw, "local_ips", {PC_IP}), setattr(gw, "local_mac", PC_MAC)))
    with pytest.raises(RuntimeError, match="couldn't open the dns packet filter"):
        gw.setup()
