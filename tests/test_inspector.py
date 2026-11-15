"""Bypass scenarios against the verdict engine. KID is an unknown device, so it
lands in the default 'quarantine' group (filtered, no UDP, strict DNS checks)."""
import os
import struct

from conftest import Conn, client_hello, split_records, tcp, udp

KID = "192.168.50.23"
SITE_IP, VPS_IP, SHARED_IP = "93.184.216.34", "45.32.1.1", "151.101.1.1"


def resolve(env, name, ip, client=KID):
    env.dnscache.record(client, [name], [(ip, 300)])


def test_normal_https_allowed(env):
    resolve(env, "www.example.com", SITE_IP)
    c = Conn(env.insp, KID, SITE_IP, 443)
    assert c.open_and_send(client_hello("www.example.com")).action == "accept"
    lab = env.insp.labels.get(("tcp", KID, c.sport, SITE_IP, 443))
    assert lab["domain"] == "www.example.com" and lab["ja4"].startswith("t13")
    assert env.kinds() == []


def test_direct_ip_without_dns_is_reset(env):
    v = Conn(env.insp, KID, VPS_IP, 443).syn()
    assert (v.action, v.kind) == ("reset", "no_dns")


def test_blocked_site_via_shared_ip(env):
    # IP legitimately resolved for an allowed name, but the TLS name is a blocked site
    resolve(env, "cdn.allowed.test", SHARED_IP)
    v = Conn(env.insp, KID, SHARED_IP, 443).open_and_send(client_hello("pornhub.com"))
    assert (v.action, v.kind) == ("reset", "dns_bypass_site")


def test_reality_style_sni_spoof(env):
    # VPS resolved via its own name, handshake pretends to be microsoft.com
    resolve(env, "my-vps.example", VPS_IP)
    v = Conn(env.insp, KID, VPS_IP, 443).open_and_send(client_hello("www.microsoft.com"))
    assert (v.action, v.kind) == ("reset", "sni_mismatch")


def test_vpn_domain_in_sni(env):
    resolve(env, "account.protonvpn.com", SHARED_IP)
    v = Conn(env.insp, KID, SHARED_IP, 443).open_and_send(client_hello("account.protonvpn.com"))
    assert v.kind == "bypass_domain"


def test_mullvad_udp2tcp_on_443(env):
    resolve(env, "relay.example", VPS_IP)
    frame = struct.pack("!H", 148) + b"\x01\x00\x00\x00" + os.urandom(144)
    v = Conn(env.insp, KID, VPS_IP, 443).open_and_send(frame)
    assert (v.action, v.kind) == ("reset", "protocol_violation")
    assert "udp2tcp" in v.reason


def test_shadowsocks_style_random_bytes_on_443(env):
    resolve(env, "relay.example", VPS_IP)
    v = Conn(env.insp, KID, VPS_IP, 443).open_and_send(b"\x8a" + os.urandom(299))
    assert v.kind == "protocol_violation" and "obfuscated" in v.reason


def test_openvpn_tcp_on_443(env):
    resolve(env, "relay.example", VPS_IP)
    v = Conn(env.insp, KID, VPS_IP, 443).open_and_send(struct.pack("!H", 14) + b"\x38" + os.urandom(13))
    assert v.kind == "protocol_violation" and "OpenVPN" in v.reason


def test_tls_without_sni(env):
    resolve(env, "relay.example", VPS_IP)
    v = Conn(env.insp, KID, VPS_IP, 443).open_and_send(client_hello(None))
    assert v.kind == "no_sni"


def test_ech_front(env):
    resolve(env, "cloudflare-ech.com", SHARED_IP)
    v = Conn(env.insp, KID, SHARED_IP, 443).open_and_send(client_hello("cloudflare-ech.com"))
    assert v.kind == "ech"


def test_vpn_and_doh_ip_lists(env):
    assert Conn(env.insp, KID, "185.159.157.10", 443).syn().kind == "vpn_server"
    assert Conn(env.insp, KID, "9.9.9.9", 443).syn().kind == "doh_server"


def test_split_hello_out_of_order_still_inspected(env):
    resolve(env, "www.example.com", SITE_IP)
    hello = client_hello("www.example.com")
    c = Conn(env.insp, KID, SITE_IP, 443)
    c.syn(), c.ack()
    mid = len(hello) // 2
    assert c.send(hello[mid:], offset=mid).action == "accept"     # later half first
    assert c.send(hello[:mid], offset=0).action == "accept"
    assert env.insp.labels.get(("tcp", KID, c.sport, SITE_IP, 443))["domain"] == "www.example.com"


def test_split_hello_hides_blocked_site(env):
    resolve(env, "cdn.allowed.test", SHARED_IP)
    hello = split_records(client_hello("pornhub.com"), 3)          # TLS record fragmentation
    c = Conn(env.insp, KID, SHARED_IP, 443)
    c.syn(), c.ack()
    verdicts = [c.send(hello[i:i + 40], offset=i).action for i in range(0, 80, 40)]
    assert verdicts == ["accept", "accept"]
    v = c.send(hello[80:], offset=80)
    assert v.kind == "dns_bypass_site"


def test_tiny_segments_past_window_are_blocked(env):
    resolve(env, "www.example.com", SITE_IP)
    hello = client_hello("www.example.com")
    c = Conn(env.insp, KID, SITE_IP, 443)
    c.syn(), c.ack()
    v = None
    for i in range(0, 20):
        v = c.send(hello[i:i + 1], offset=i)
        if v.action != "accept":
            break
    assert v.kind == "evasion"


def test_server_speaks_first(env):
    resolve(env, "relay.example", VPS_IP)
    c = Conn(env.insp, KID, VPS_IP, 443)
    c.syn()
    v = None
    for _ in range(5):
        v = c.ack()
    assert v.kind == "server_first"


def test_http_rules(env):
    resolve(env, "plain.example", SITE_IP)
    ok = Conn(env.insp, KID, SITE_IP, 80, sport=41000).open_and_send(
        b"GET / HTTP/1.1\r\nHost: plain.example\r\n\r\n")
    assert ok.action == "accept"
    proxy = Conn(env.insp, KID, SITE_IP, 80, sport=41001).open_and_send(
        b"CONNECT vpn.example:443 HTTP/1.1\r\nHost: vpn.example\r\n\r\n")
    assert proxy.kind == "http_proxy"
    junk = Conn(env.insp, KID, SITE_IP, 80, sport=41002).open_and_send(b"\x05\x01\x00")
    assert junk.kind == "protocol_violation"


def test_udp_blocked_for_kids_with_vpn_alerts(env):
    wg = udp(KID, VPS_IP, 50000, 51820, b"\x01\x00\x00\x00" + os.urandom(144))
    v = env.insp.inspect(wg)
    assert v.action == "drop" and v.kind == "blocked_udp" and "WireGuard" in v.reason
    quic = udp(KID, SITE_IP, 50001, 443, bytes([0xC3]) + struct.pack("!I", 1) + os.urandom(1200))
    assert env.insp.inspect(quic).action == "drop"
    assert env.kinds().count("blocked_udp") == 1           # QUIC drops are silent


def test_vpn_port_attempt(env):
    v = Conn(env.insp, KID, VPS_IP, 1194).syn()
    assert v.action == "drop" and v.kind == "blocked_port"


def test_consoles_udp(env):
    env.policy.forced_group = "consoles"
    game = udp(KID, VPS_IP, 3074, 3074, os.urandom(100))
    assert env.insp.inspect(game).action == "accept"
    wg = udp(KID, VPS_IP, 50000, 33333, b"\x01\x00\x00\x00" + os.urandom(144))
    assert env.insp.inspect(wg).kind == "blocked_udp"
    sid = os.urandom(8)
    assert env.insp.inspect(udp(KID, VPS_IP, 50002, 1300, b"\x38" + sid + b"\x00" * 5)).action == "accept"
    v = env.insp.inspect(udp(KID, VPS_IP, 50002, 1300, b"\x28" + sid + os.urandom(20)))
    assert v.kind == "blocked_udp" and "OpenVPN" in v.reason
    stun = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + os.urandom(12)
    assert env.insp.inspect(udp(KID, VPS_IP, 50003, 19302, stun)).action == "accept"
    dtls = b"\x16\xfe\xfd" + os.urandom(60)
    assert env.insp.inspect(udp(KID, VPS_IP, 50003, 19302, dtls)).action == "accept"   # WebRTC
    assert env.insp.inspect(udp(KID, VPS_IP, 50004, 4433, dtls)).kind == "blocked_udp"  # VPN DTLS


def test_trusted_device_untouched(env):
    env.policy.forced_group = "adults"
    assert Conn(env.insp, KID, VPS_IP, 443).syn().action == "accept"
    assert env.insp.inspect(udp(KID, VPS_IP, 1, 51820, b"\x01\x00\x00\x00" + os.urandom(144))).action == "accept"


def test_log_mode_allows_but_alerts(env):
    env.policy.forced_group = "consoles"           # dns_consistency: log
    assert Conn(env.insp, KID, VPS_IP, 443).syn().action == "accept"
    assert "no_dns" in env.kinds()


def test_exempt_destination(env):
    assert Conn(env.insp, KID, "17.57.144.10", 443).syn().action == "accept"
