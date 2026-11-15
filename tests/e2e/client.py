"""Bypass attempts, run from inside a LAN namespace (kid / parent / console).
Each check prints one JSON line: {"name", "ok", "got"}.

    python client.py <suite>
"""
import json
import os
import socket
import ssl
import struct
import sys
import time

from dnslib import DNSRecord

GW = "10.50.0.1"


def dns(name, server=GW, qtype="A"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(DNSRecord.question(name, qtype).pack(), (server, 53))
        r = DNSRecord.parse(s.recvfrom(4096)[0])
        return r.header.rcode, [str(a.rdata) for a in r.rr]
    except socket.timeout:
        return "timeout", []
    finally:
        s.close()


def tls(ip, sni, port=443, payload=b"GET", timeout=3):
    """'ok' (handshake + reply), 'reset', 'refused', 'timeout' or an error label."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.socket()
    raw.settimeout(timeout)
    try:
        raw.connect((ip, port))
        s = ctx.wrap_socket(raw, server_hostname=sni)
        s.sendall(payload)
        data = s.recv(100)
        return "ok" if data else "closed"
    except ConnectionResetError:
        return "reset"
    except ConnectionRefusedError:
        return "refused"
    except (socket.timeout, TimeoutError):
        return "timeout"
    except ssl.SSLError as e:
        return "reset" if "EOF" in str(e) or "reset" in str(e).lower() else f"ssl:{e.reason}"
    except OSError as e:
        return f"os:{e.errno}"
    finally:
        raw.close()


def raw_tcp(ip, port, data, timeout=3, chunks=None):
    s = socket.socket()
    s.settimeout(timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        s.connect((ip, port))
        for part in (chunks or [data]):
            s.send(part)
            if chunks:
                time.sleep(0.05)
        got = s.recv(65536)
        return "echo" if got else "closed"
    except ConnectionResetError:
        return "reset"
    except ConnectionRefusedError:
        return "refused"
    except (socket.timeout, TimeoutError):
        return "timeout"
    except OSError as e:
        return f"os:{e.errno}"
    finally:
        s.close()


def http(ip, host, method="GET", target="/"):
    req = f"{method} {target} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((ip, 80))
        s.sendall(req)
        data = s.recv(100)
        return "200" if b" 200 " in data else ("closed" if not data else "other")
    except ConnectionResetError:
        return "reset"
    except (socket.timeout, TimeoutError):
        return "timeout"
    except OSError as e:
        return f"os:{e.errno}"
    finally:
        s.close()


def udp(ip, port, payload, timeout=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (ip, port))
        return "echo" if s.recvfrom(65536)[0] == payload else "other"
    except socket.timeout:
        return "timeout"
    finally:
        s.close()


def client_hello(sni):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    out = ssl.MemoryBIO()
    obj = ctx.wrap_bio(ssl.MemoryBIO(), out, server_hostname=sni)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def split_records(hello, at):
    body = hello[5:]
    hdr = hello[:3]
    return hdr + struct.pack("!H", at) + body[:at] + hdr + struct.pack("!H", len(body) - at) + body[at:]


WG_INIT = b"\x01\x00\x00\x00" + os.urandom(144)
QUIC = bytes([0xC3]) + struct.pack("!I", 1) + os.urandom(1200)


class OneOf:
    def __init__(self, *vals):
        self.vals = [_norm(v) for v in vals]


def _norm(v):
    return json.loads(json.dumps(v))


def check(name, got, want):
    g = _norm(got)
    ok = g in want.vals if isinstance(want, OneOf) else g == _norm(want)
    print(json.dumps({"name": name, "ok": ok, "got": g,
                      "want": want.vals if isinstance(want, OneOf) else _norm(want)}), flush=True)


def suite_kid():
    RESET, DROPPED = "reset", "timeout"
    # Order matters: the direct-IP test runs before vps.test is ever looked up.
    check("direct IP to a VPS (no DNS lookup) -> TCP reset at connect", tls("198.51.100.77", "vps.test"), "refused")
    check("DNS: normal site resolves", dns("site.test"), (0, ["198.51.100.10"]))
    check("DNS: adult site blocked", dns("adult-site.test")[0], 3)
    check("DNS: VPN provider domain blocked", dns("protonvpn.com")[0], 3)
    check("DNS: asking 8.8.8.8 directly is redirected and still filtered", dns("adult-site.test", "8.8.8.8")[0], 3)
    check("DNS: redirected query still answers normal sites", dns("site.test", "8.8.8.8")[1], ["198.51.100.10"])
    check("DNS: Firefox DoH canary", dns("use-application-dns.net")[0], 3)
    check("DNS: HTTPS records stripped (no ECH keys)", dns("site.test", qtype="HTTPS"), (0, []))
    check("DNS: NULL records refused (DNS tunnel tools)", dns("x.site.test", qtype="NULL")[0], 5)
    check("HTTPS to an allowed site works", tls("198.51.100.10", "site.test"), "ok")
    dns("shared-cdn.test")
    check("blocked site behind a shared IP (hosts-file trick)", tls("198.51.100.10", "adult-site.test"), RESET)
    dns("vps.test")
    check("Reality-style handshake pretending to be microsoft.com", tls("198.51.100.77", "www.microsoft.com"), RESET)
    check("TLS without a server name", tls("198.51.100.77", None), RESET)
    dns("cloudflare-ech.com")
    check("Encrypted Client Hello front", tls("198.51.100.10", "cloudflare-ech.com"), RESET)
    dns("vpn-server.test")
    check("known VPN server IP (Proton/Mullvad list) -> silently dropped", tls("198.51.100.66", "vpn-server.test"), DROPPED)
    check("public DoH resolver 9.9.9.9 -> silently dropped", tls("9.9.9.9", "dns.quad9.net"), DROPPED)
    dns("raw.test")
    frame = struct.pack("!H", 148) + WG_INIT
    check("Mullvad udp2tcp (WireGuard framed in TCP/443)", raw_tcp("198.51.100.80", 443, frame), RESET)
    check("Shadowsocks-style random bytes on 443", raw_tcp("198.51.100.80", 443, b"\x8a" + os.urandom(299)), RESET)
    check("OpenVPN over TCP 443", raw_tcp("198.51.100.80", 443, struct.pack("!H", 14) + b"\x38" + os.urandom(13)), RESET)
    check("SSH on port 443", raw_tcp("198.51.100.80", 443, b"SSH-2.0-OpenSSH_9.6\r\n"), RESET)
    hello = client_hello("site.test")
    check("ClientHello dribbled in 1-byte TCP segments (DPI evasion)",
          raw_tcp("198.51.100.10", 443, None, chunks=[hello[i:i + 1] for i in range(30)] + [hello[30:]]), RESET)
    dns("shared-cdn.test")
    check("blocked site hidden by TLS record fragmentation",
          raw_tcp("198.51.100.10", 443, split_records(client_hello("adult-site.test"), 4)), RESET)
    check("control: fragmented records for an allowed site still work",
          raw_tcp("198.51.100.10", 443, split_records(client_hello("site.test"), 4)), "echo")
    dns("serverfirst.test")
    check("server-speaks-first protocol on 443 (SSH/VPN-like)", _server_first(), RESET)
    check("plain HTTP to an allowed site", http("198.51.100.10", "site.test"), "200")
    check("HTTP CONNECT proxy tunnel", http("198.51.100.10", "vps.test", "CONNECT", "vps.test:443"), RESET)
    check("HTTP Host header for a blocked site", http("198.51.100.10", "adult-site.test"), RESET)
    check("WireGuard handshake (UDP 51820)", udp("198.51.100.77", 51820, WG_INIT), DROPPED)
    check("QUIC / HTTP3 (UDP 443)", udp("198.51.100.77", 443, QUIC), DROPPED)
    check("other UDP (games) not allowed for kids", udp("198.51.100.77", 3074, b"game"), DROPPED)
    check("OpenVPN port TCP 1194", raw_tcp("198.51.100.77", 1194, b"x"), DROPPED)
    check("ISP router admin page (192.168.1.1)", http("192.168.1.1", "192.168.1.1"), DROPPED)
    check("dashboard from a kid's device", raw_tcp(GW, 8080, b"GET / HTTP/1.0\r\n\r\n"), DROPPED)


def _server_first():
    s = socket.socket()
    s.settimeout(4)
    got = 0
    try:
        s.connect(("198.51.100.78", 443))
        while True:
            d = s.recv(65536)
            if not d:
                return "closed"
            got += len(d)
            if got >= 32 * 4096:
                return "ok"
    except ConnectionResetError:
        return "reset"
    except (socket.timeout, TimeoutError):
        return "timeout"
    finally:
        s.close()


def suite_parent():
    check("parent: direct IP without DNS works", tls("198.51.100.77", "vps.test"), "ok")
    check("parent: WireGuard allowed", udp("198.51.100.77", 51820, WG_INIT), "echo")
    check("parent: ISP router admin page", http("192.168.1.1", "192.168.1.1"), "200")
    check("parent: dashboard reachable", raw_tcp(GW, 8080, b"GET / HTTP/1.0\r\n\r\n"), "echo")


def suite_console():
    check("console: game UDP allowed", udp("198.51.100.77", 3074, b"game-packet"), "echo")
    check("console: WireGuard still blocked", udp("198.51.100.77", 51820, WG_INIT), "timeout")
    check("console: QUIC still blocked", udp("198.51.100.77", 443, QUIC), "timeout")


def suite_kid_basic():
    dns("site.test")
    check("kid: HTTPS to allowed site", tls("198.51.100.10", "site.test"), "ok")


def suite_kid_paused():
    check("paused: DNS refused", dns("site.test")[0], 3)
    check("paused: HTTPS blocked", tls("198.51.100.10", "site.test"), OneOf("reset", "refused", "timeout", "os:113"))


def suite_tunnel():
    """A real TLS connection to a domain resolved through our DNS (passes every
    handshake check) that then behaves like a VPN: long-lived, heavy, and the
    device makes no further DNS lookups."""
    dns("tunnel.test")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("198.51.100.79", 443), timeout=5)
    s = ctx.wrap_socket(raw, server_hostname="tunnel.test")
    s.sendall(b"BULK")
    start, got, result = time.time(), 0, "never-blocked"
    s.settimeout(2)
    while time.time() - start < 45:
        try:
            d = s.recv(65536)
            if not d:
                result = "closed"
                break
            got += len(d)
        except (socket.timeout, TimeoutError):
            result = "stalled"
            break
        except (ConnectionResetError, ssl.SSLError, OSError):
            result = "reset"
            break
    elapsed = round(time.time() - start, 1)
    print(json.dumps({"name": f"tunnel cut off after {elapsed}s / {got // 1_000_000} MB", "ok": result in ("stalled", "reset", "closed") and elapsed > 4,
                      "got": result, "want": ["stalled", "reset"]}), flush=True)
    check("tunnel host blocked for new connections", tls("198.51.100.79", "tunnel.test"), OneOf("timeout", "reset", "refused"))


def suite_kid_failclosed():
    dns("site.test")
    check("inspector down: kid's web access fails closed", tls("198.51.100.10", "site.test"), OneOf("timeout", "reset", "refused"))


def suite_parent_failclosed():
    check("inspector down: parent unaffected", tls("198.51.100.77", "vps.test"), "ok")




# ---------------------------------------------------------------- torrents & countermeasures
DHT_PING = b"d1:ad2:id20:" + os.urandom(20) + b"e1:q4:ping1:t2:aa1:y1:qe"
BT_HS = b"\x13BitTorrent protocol" + b"\x00" * 8 + os.urandom(40)


def suite_kid_torrent():
    check("torrent site blocked in DNS", dns("thepiratebay.org")[0], 3)
    check("DHT bootstrap node blocked in DNS", dns("router.bittorrent.com")[0], 3)
    dns("raw.test")
    check("BitTorrent peer connection disguised on 443", raw_tcp("198.51.100.80", 443, BT_HS), "reset")
    dns("site.test")
    check("HTTP tracker announce", http("198.51.100.10", "site.test", "GET",
                                        "/announce?info_hash=%aa%bb&peer_id=-qB4620-&port=6881"), "reset")
    check("DHT ping (UDP 6881)", udp("198.51.100.77", 6881, DHT_PING), "timeout")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)          # encrypted client: no signature, many peers
    for i in range(1, 31):
        s.sendto(os.urandom(120), (f"198.51.101.{i}", 20000 + i))
    s.close()
    time.sleep(0.5)
    m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    m.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    m.sendto(b"BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nPort: 6881\r\nInfohash: " +
             os.urandom(20).hex().encode() + b"\r\n\r\n", ("239.192.152.143", 6771))
    m.close()


def suite_kid_sneaky():
    """Quieter countermeasures (no auto-pause)."""
    dns("site.test")
    for i in range(6):                     # traffic from a device hidden behind a NAT/hotspot
        s = socket.socket()
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 63)
        s.settimeout(2)
        try:
            s.connect(("198.51.100.10", 443))
        except OSError:
            pass
        s.close()
    check("SSH to the gateway", raw_tcp(GW, 22, b"SSH-2.0-x\r\n"), "timeout")


def suite_kid_scan():
    for p in (21, 23, 25, 80, 139, 445, 3389, 5900, 8443):
        raw_tcp(GW, p, b"x", timeout=0.5)


def _sendp(frame):
    from scapy.all import sendp
    sendp(frame, iface="eth0", verbose=False)


def suite_kid_l2_attacks():
    from scapy.all import ARP, BOOTP, DHCP, IP, UDP, Ether
    from scapy.layers.inet6 import ICMPv6ND_RA, IPv6
    me = open("/sys/class/net/eth0/address").read().strip()
    bc = "ff:ff:ff:ff:ff:ff"
    _sendp(Ether(src=me, dst=bc) / ARP(op=2, hwsrc=me, psrc=GW, hwdst=bc, pdst="10.50.0.20"))
    _sendp(Ether(src=me, dst=bc) / ARP(op=2, hwsrc=me, psrc="10.50.0.20", hwdst=bc, pdst=GW))
    _sendp(Ether(src=me, dst=bc) / IP(src="10.50.0.10", dst="255.255.255.255") / UDP(sport=67, dport=68) /
           BOOTP(op=2, yiaddr="10.50.0.99") / DHCP(options=[("message-type", "offer"), ("router", "10.50.0.10"),
                                                            ("name_server", "10.50.0.10"), "end"]))
    _sendp(Ether(src=me, dst="33:33:00:00:00:01") / IPv6(src="fe80::10", dst="ff02::1") / ICMPv6ND_RA())


def suite_kid_clone_parent():
    """The kid's laptop announces itself with the parent laptop's hardware address."""
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether
    me = open("/sys/class/net/eth0/address").read().strip()
    chaddr = bytes.fromhex("020000000020") + b"\x00" * 10
    _sendp(Ether(src=me, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") /
           UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=chaddr) /
           DHCP(options=[("message-type", "request"), ("param_req_list", [1, 121, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 252]),
                         ("vendor_class_id", b"MSFT 5.0"), ("hostname", b"PARENT-LAPTOP"), "end"]))


def suite_parent_dhcp():
    """The parent laptop's genuine DHCP request (learned as its fingerprint)."""
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether
    me = open("/sys/class/net/eth0/address").read().strip()
    chaddr = bytes.fromhex(me.replace(":", "")) + b"\x00" * 10
    _sendp(Ether(src=me, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") /
           UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=chaddr) /
           DHCP(options=[("message-type", "request"), ("param_req_list", [1, 3, 6, 15, 119, 252, 95, 44, 46]),
                         ("hostname", b"PARENT-LAPTOP"), "end"]))


def suite_parent_quarantined():
    check("cloned parent identity: treated as filtered until confirmed",
          tls("198.51.100.77", "vps.test"), "refused")


def suite_kid_paused_after_attack():
    check("attacking device auto-paused: web blocked", tls("198.51.100.10", "site.test"),
          OneOf("reset", "refused", "timeout", "os:113"))


# ---------------------------------------------------------------- activity & downloads
def _tls_stream(ip, sni, request, seconds, timeout=3):
    """Open TLS, send a request, read for up to `seconds`. Returns (result, bytes)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    got, start = 0, time.time()
    try:
        raw = socket.create_connection((ip, 443), timeout=timeout)
        s = ctx.wrap_socket(raw, server_hostname=sni)
        s.sendall(request)
        s.settimeout(timeout)
        while time.time() - start < seconds:
            d = s.recv(65536)
            if not d:
                return "closed", got
            got += len(d)
        return "complete", got
    except (socket.timeout, TimeoutError):
        return "stalled", got
    except (ConnectionResetError, ConnectionRefusedError):
        return "reset", got
    except ssl.SSLError as e:
        return ("reset" if "EOF" in str(e) or "reset" in str(e).lower() else f"ssl:{e.reason}"), got
    except OSError as e:
        return f"os:{e.errno}", got


def suite_console_play():
    """A game (steady small UDP packets) with YouTube playing in the background, ~25 s."""
    import threading
    dns("rr1---sn-abc.googlevideo.com")

    def game():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.05)
        end = time.time() + 25
        while time.time() < end:
            s.sendto(os.urandom(100), ("198.51.100.77", 3074))
            try:
                s.recvfrom(2048)
            except socket.timeout:
                pass
            time.sleep(1 / 30)
    t = threading.Thread(target=game)
    t.start()
    _tls_stream("198.51.100.81", "rr1---sn-abc.googlevideo.com", b"VIDEO", 25)
    t.join()


def suite_kid_download():
    dns("dl.mediafire.com")
    t0 = time.time()
    res, got = _tls_stream("198.51.100.82", "dl.mediafire.com", b"BULK", 40)
    check(f"download from a file-sharing site cut off after {time.time() - t0:.1f}s / {got / 1e6:.1f} MB",
          res, OneOf("stalled", "reset", "closed"))
    check("retry while held for review", tls("198.51.100.82", "dl.mediafire.com"), "reset")


def suite_kid_download_retry():
    dns("dl.mediafire.com")
    res, got = _tls_stream("198.51.100.82", "dl.mediafire.com", b"BULK", 6)
    check(f"after approval the download works ({got / 1e6:.0f} MB in 6 s)", res, "complete")


def suite_kid_http_exe():
    dns("plain.test")
    check("plain-HTTP .exe download stopped before it starts",
          http("198.51.100.10", "plain.test", "GET", "/files/FreeRobux-Setup.exe"), "reset")


def suite_kid_after_deny():
    check("denied download site now blocked for this device", dns("plain.test")[0], 3)


if __name__ == "__main__":
    globals()[f"suite_{sys.argv[1]}"]()
