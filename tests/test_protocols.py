import os
import struct

from conftest import client_hello, split_records, tcp, udp

from guardian.protocols import (NEED_MORE, classify_udp, identify_tcp_stream, openvpn_confirm,
                                parse_client_hello, parse_http_request, parse_ip)


def test_parse_real_client_hello():
    ch = parse_client_hello(client_hello("www.example.com"))
    assert ch.sni == "www.example.com"
    assert ch.alpn == ["h2", "http/1.1"]
    assert 0x0304 in ch.versions
    assert ch.ja4.startswith("t13d") and ch.ja4.count("_") == 2
    assert len(ch.ja3) == 32


def test_client_hello_without_sni():
    ch = parse_client_hello(client_hello(None))
    assert ch.sni is None
    assert ch.ja4[3] == "i"


def test_partial_hello_needs_more():
    hello = client_hello("example.org")
    for cut in (1, 4, 5, 40, len(hello) - 1):
        assert parse_client_hello(hello[:cut]) is NEED_MORE


def test_hello_split_across_tls_records():
    hello = client_hello("split.example.net")
    ch = parse_client_hello(split_records(hello, 7))
    assert ch.sni == "split.example.net" and ch.record_count == 2


def test_non_tls_rejected():
    assert parse_client_hello(b"SSH-2.0-OpenSSH_9.6\r\n") is None
    assert parse_client_hello(os.urandom(64).replace(b"\x16", b"\x17", 1)[:1] + b"x" * 10) is None


def test_http_parsing():
    r = parse_http_request(b"GET /a HTTP/1.1\r\nHost: Example.COM:8080\r\nUA: x\r\n\r\n")
    assert r.method == "GET" and r.host == "example.com"
    assert parse_http_request(b"GE") is NEED_MORE
    assert parse_http_request(b"GET / HTTP/1.1\r\nHost: a") is NEED_MORE
    assert parse_http_request(b"\x05\x01\x00") is None
    assert parse_http_request(b"HELLO world\r\n\r\n") is None
    assert parse_http_request(b"CONNECT vpn.example:443 HTTP/1.1\r\nHost: vpn.example\r\n\r\n").method == "CONNECT"


def test_udp_signatures():
    wg_init = b"\x01\x00\x00\x00" + os.urandom(144)
    assert classify_udp(wg_init, 51820) == "WireGuard"
    assert classify_udp(b"\x04\x00\x00\x00" + os.urandom(60), 9999) == "WireGuard"
    quic = bytes([0xC3]) + struct.pack("!I", 1) + os.urandom(1200)
    assert classify_udp(quic, 443) == "QUIC"
    stun = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + os.urandom(12)
    assert classify_udp(stun, 3478) == "STUN"
    sid = os.urandom(8)
    p1 = b"\x38" + sid + b"\x00" + b"\x00\x00\x00\x00"
    p2 = b"\x28" + sid + os.urandom(20)
    assert classify_udp(p1, 1194) == "OpenVPN?"
    assert openvpn_confirm(p1, p2)
    assert not openvpn_confirm(p1, b"\x28" + os.urandom(28))


def test_identify_disguised_streams():
    wg = b"\x01\x00\x00\x00" + os.urandom(144)
    assert "udp2tcp" in identify_tcp_stream(struct.pack("!H", 148) + wg)
    assert identify_tcp_stream(b"SSH-2.0-x") == "SSH"
    assert "OpenVPN" in identify_tcp_stream(struct.pack("!H", 14) + b"\x38" + os.urandom(13))
    assert "obfuscated" in identify_tcp_stream(os.urandom(300))


def test_parse_ip_roundtrip():
    p = parse_ip(tcp("10.0.0.2", "1.2.3.4", 1234, 443, 77, 0x02, b""))
    assert (p.src, p.dst, p.sport, p.dport, p.seq, p.syn_only) == ("10.0.0.2", "1.2.3.4", 1234, 443, 77, True)
    q = parse_ip(udp("10.0.0.2", "1.2.3.4", 5, 53, b"abc"))
    assert q.is_udp and q.payload == b"abc"
