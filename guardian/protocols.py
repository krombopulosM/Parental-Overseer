"""Wire-format parsers used by the inspector, the passive sniffer and the replay
tool. Pure functions over bytes: no sockets, no platform dependencies.

  * IPv4/IPv6 + TCP/UDP header parsing
  * TLS ClientHello: SNI, ALPN, ECH, versions, JA3 and JA4 fingerprints
  * HTTP request line + Host header
  * Signatures for VPN / tunnel protocols that try to hide on common ports
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import socket
import struct
from dataclasses import dataclass, field

NEED_MORE = "need_more"

# ---------------------------------------------------------------- IP / TCP / UDP

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class Packet:
    version: int
    src: str
    dst: str
    proto: int              # 6 tcp, 17 udp, 1 icmp, 58 icmpv6, ...
    sport: int = 0
    dport: int = 0
    seq: int = 0
    flags: int = 0
    payload: bytes = b""
    length: int = 0
    ttl: int = 0             # IPv4 TTL / IPv6 hop limit as received

    @property
    def is_tcp(self):
        return self.proto == 6

    @property
    def is_udp(self):
        return self.proto == 17

    @property
    def syn_only(self):
        return self.is_tcp and (self.flags & TCP_SYN) and not (self.flags & TCP_ACK)


def parse_ip(data: bytes) -> Packet | None:
    if not data:
        return None
    ver = data[0] >> 4
    if ver == 4:
        if len(data) < 20:
            return None
        ihl = (data[0] & 0x0F) * 4
        total = struct.unpack("!H", data[2:4])[0] or len(data)
        frag = struct.unpack("!H", data[6:8])[0]
        proto, ttl = data[9], data[8]
        src = socket.inet_ntop(socket.AF_INET, data[12:16])
        dst = socket.inet_ntop(socket.AF_INET, data[16:20])
        body = data[ihl:total]
        if frag & 0x1FFF:                       # non-first fragment: no L4 header
            return Packet(4, src, dst, proto, length=total, ttl=ttl)
    elif ver == 6:
        if len(data) < 40:
            return None
        proto, ttl = data[6], data[7]
        src = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
        total = 40 + struct.unpack("!H", data[4:6])[0]
        body = data[40:total]
        while proto in (0, 43, 60, 44) and len(body) >= 8:     # skip extension headers
            nxt = body[0]
            if proto == 44:
                if struct.unpack("!H", body[2:4])[0] & 0xFFF8:
                    return Packet(6, src, dst, nxt, length=total, ttl=ttl)
                hlen = 8
            else:
                hlen = (body[1] + 1) * 8
            proto, body = nxt, body[hlen:]
    else:
        return None
    pkt = Packet(ver, src, dst, proto, length=total, ttl=ttl)
    if proto == 6 and len(body) >= 20:
        pkt.sport, pkt.dport, pkt.seq = struct.unpack("!HHI", body[:8])
        off = (body[12] >> 4) * 4
        pkt.flags = body[13]
        pkt.payload = bytes(body[off:])
    elif proto == 17 and len(body) >= 8:
        pkt.sport, pkt.dport = struct.unpack("!HH", body[:4])
        pkt.payload = bytes(body[8:])
    return pkt


# ---------------------------------------------------------------- TLS ClientHello

def _is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


@dataclass
class ClientHello:
    legacy_version: int
    sni: str | None = None
    alpn: list = field(default_factory=list)
    ciphers: list = field(default_factory=list)
    extensions: list = field(default_factory=list)
    groups: list = field(default_factory=list)
    point_formats: list = field(default_factory=list)
    sig_algs: list = field(default_factory=list)
    versions: list = field(default_factory=list)
    has_ech: bool = False
    record_count: int = 1

    @property
    def sni_is_ip(self) -> bool:
        if not self.sni:
            return False
        try:
            ipaddress.ip_address(self.sni.strip("[]"))
            return True
        except ValueError:
            return False

    @property
    def ja3(self) -> str:
        parts = [str(self.legacy_version),
                 "-".join(str(c) for c in self.ciphers if not _is_grease(c)),
                 "-".join(str(e) for e in self.extensions if not _is_grease(e)),
                 "-".join(str(g) for g in self.groups if not _is_grease(g)),
                 "-".join(str(p) for p in self.point_formats)]
        return hashlib.md5(",".join(parts).encode()).hexdigest()

    @property
    def ja4(self) -> str:
        """JA4 TLS client fingerprint (FoxIO spec). Unlike JA3 it sorts the
        extension list, so it stays stable when browsers shuffle extensions."""
        vers = [v for v in self.versions if not _is_grease(v)]
        v = max(vers) if vers else self.legacy_version
        ver = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10",
               0x0300: "s3", 0x0002: "s2", 0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}.get(v, "00")
        ciphers = [c for c in self.ciphers if not _is_grease(c)]
        exts = [e for e in self.extensions if not _is_grease(e)]
        if self.alpn:
            a = self.alpn[0]
            if a and a[0].isalnum() and a[-1].isalnum() and a.isascii():
                alpn = a[0] + a[-1]
            elif a:
                h = a.encode("latin-1").hex()
                alpn = h[0] + h[-1]
            else:
                alpn = "00"
        else:
            alpn = "00"
        ja4_a = f"t{ver}{'d' if self.sni else 'i'}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{alpn}"
        ja4_b = hashlib.sha256(",".join(f"{c:04x}" for c in sorted(ciphers)).encode()).hexdigest()[:12] \
            if ciphers else "000000000000"
        ext_str = ",".join(f"{e:04x}" for e in sorted(x for x in exts if x not in (0x0000, 0x0010)))
        if self.sig_algs:
            ext_str += "_" + ",".join(f"{s:04x}" for s in self.sig_algs)
        ja4_c = hashlib.sha256(ext_str.encode()).hexdigest()[:12] if exts else "000000000000"
        return f"{ja4_a}_{ja4_b}_{ja4_c}"


def parse_client_hello(buf: bytes):
    """Parse a (possibly multi-record) TLS ClientHello from the start of a TCP
    stream. Returns ClientHello, NEED_MORE, or None if this isn't TLS."""
    if not buf:
        return NEED_MORE
    if buf[0] != 0x16:
        return None
    if len(buf) >= 2 and buf[1] != 0x03:
        return None
    if len(buf) >= 3 and buf[2] > 0x04:
        return None
    if len(buf) < 5:
        return NEED_MORE
    hs = bytearray()
    pos, records = 0, 0
    need = None
    while True:
        if len(buf) < pos + 5:
            return NEED_MORE
        if buf[pos] != 0x16 or buf[pos + 1] != 0x03:
            return None
        rlen = struct.unpack("!H", buf[pos + 3:pos + 5])[0]
        if rlen == 0 or rlen > 18432:
            return None
        if len(buf) < pos + 5 + rlen:
            return NEED_MORE
        hs += buf[pos + 5:pos + 5 + rlen]
        pos += 5 + rlen
        records += 1
        if need is None and len(hs) >= 4:
            if hs[0] != 0x01:                      # not a ClientHello
                return None
            need = 4 + int.from_bytes(hs[1:4], "big")
            if need > 65536:
                return None
        if need is not None and len(hs) >= need:
            break
        if records > 64:
            return None
    ch = _parse_hello_body(bytes(hs[4:need]))
    if ch is not None:
        ch.record_count = records
    return ch


def _parse_hello_body(b: bytes) -> ClientHello | None:
    try:
        p = 0
        legacy = struct.unpack("!H", b[p:p + 2])[0]
        p += 2 + 32
        sid_len = b[p]
        p += 1 + sid_len
        cs_len = struct.unpack("!H", b[p:p + 2])[0]
        p += 2
        if cs_len % 2 or p + cs_len > len(b):
            return None
        ciphers = [struct.unpack("!H", b[i:i + 2])[0] for i in range(p, p + cs_len, 2)]
        p += cs_len
        comp_len = b[p]
        p += 1 + comp_len
        ch = ClientHello(legacy_version=legacy, ciphers=ciphers)
        if p + 2 > len(b):
            return ch
        ext_total = struct.unpack("!H", b[p:p + 2])[0]
        p += 2
        end = min(len(b), p + ext_total)
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", b[p:p + 4])
            p += 4
            ed = b[p:p + elen]
            p += elen
            ch.extensions.append(etype)
            if etype == 0x0000 and ch.sni is None and len(ed) >= 5:
                q = 2
                while q + 3 <= len(ed):
                    ntype, nlen = ed[q], struct.unpack("!H", ed[q + 1:q + 3])[0]
                    q += 3
                    if ntype == 0:
                        ch.sni = ed[q:q + nlen].decode("ascii", "replace").strip().rstrip(".").lower()
                        break
                    q += nlen
            elif etype == 0x0010 and len(ed) >= 2:
                q = 2
                while q < len(ed):
                    ln = ed[q]
                    ch.alpn.append(ed[q + 1:q + 1 + ln].decode("latin-1"))
                    q += 1 + ln
            elif etype == 0x002b and ed:
                ch.versions = [struct.unpack("!H", ed[i:i + 2])[0] for i in range(1, 1 + ed[0], 2)]
            elif etype == 0x000a and len(ed) >= 2:
                n = struct.unpack("!H", ed[:2])[0]
                ch.groups = [struct.unpack("!H", ed[i:i + 2])[0] for i in range(2, 2 + n, 2)]
            elif etype == 0x000b and ed:
                ch.point_formats = list(ed[1:1 + ed[0]])
            elif etype == 0x000d and len(ed) >= 2:
                n = struct.unpack("!H", ed[:2])[0]
                ch.sig_algs = [struct.unpack("!H", ed[i:i + 2])[0] for i in range(2, 2 + n, 2)]
            elif etype in (0xfe0d, 0xffce):
                ch.has_ech = True
        return ch
    except (IndexError, struct.error):
        return None


# ---------------------------------------------------------------- HTTP

HTTP_METHODS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT",
                b"TRACE", b"PROPFIND", b"PROPPATCH", b"MKCOL", b"COPY", b"MOVE", b"LOCK",
                b"UNLOCK", b"REPORT", b"SEARCH", b"PURGE", b"MKCALENDAR", b"SUBSCRIBE",
                b"NOTIFY", b"M-SEARCH")


@dataclass
class HttpRequest:
    method: str
    target: str
    host: str | None


def parse_http_request(buf: bytes):
    """HttpRequest, NEED_MORE, or None if the stream doesn't start like HTTP."""
    sp = buf.find(b" ")
    head = buf[:sp] if sp != -1 else buf[:12]
    if sp == -1:
        if any(m.startswith(head) for m in HTTP_METHODS) and len(buf) < 12:
            return NEED_MORE
        return None
    if head not in HTTP_METHODS:
        return None
    end = buf.find(b"\r\n\r\n")
    if end == -1:
        if b"\n" in buf[:sp + 2100] and not buf.split(b"\r\n", 1)[0].rstrip().endswith(
                (b"HTTP/1.0", b"HTTP/1.1")):
            return None
        return NEED_MORE if len(buf) < 16384 else None
    lines = buf[:end].split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) < 3 or not parts[2].startswith(b"HTTP/"):
        return None
    host = None
    for line in lines[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"host":
            host = v.strip().decode("latin-1").lower()
            break
    if host:
        if host.startswith("["):
            host = host[1:host.find("]")]
        elif host.count(":") == 1:
            host = host.split(":")[0]
        host = host.rstrip(".")
    return HttpRequest(parts[0].decode(), parts[1].decode("latin-1"), host)


# ---------------------------------------------------------------- tunnel / VPN signatures

QUIC_VERSIONS = {0x00000001, 0x6B3343CF, 0xFF00001D, 0xFF00001C, 0xFF00001B, 0x709A50C4,
                 0x51303530, 0x51303436, 0x51303433, 0x54303530}
STUN_MAGIC = b"\x21\x12\xa4\x42"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def is_wireguard(p: bytes) -> bool:
    if len(p) < 32 or p[1:4] != b"\x00\x00\x00":
        return False
    t, n = p[0], len(p)
    return (t == 1 and n == 148) or (t == 2 and n == 92) or (t == 3 and n == 64) or \
           (t == 4 and n >= 32 and n % 16 == 0)


def classify_udp(p: bytes, dport: int) -> str | None:
    """Best-effort label for the first packets of a UDP flow."""
    if not p:
        return None
    if is_wireguard(p):
        return "WireGuard"
    if len(p) >= 5 and (p[0] & 0xC0) == 0xC0 and struct.unpack("!I", p[1:5])[0] in QUIC_VERSIONS:
        return "QUIC"
    if len(p) >= 20 and p[4:8] == STUN_MAGIC:
        return "STUN"
    if len(p) >= 13 and p[0] == 0x16 and p[1] == 0xFE and p[2] in (0xFF, 0xFD, 0xFC):
        return "DTLS"
    ike = p[4:] if dport == 4500 and p[:4] == b"\x00\x00\x00\x00" else p
    if len(ike) >= 28 and ike[17] in (0x20, 0x10) and ike[18] in (2, 4, 5, 34, 35, 36, 37):
        return "IPsec/IKE"
    if dport in (500, 4500):
        return "IPsec/IKE"
    if p[0] in (0x38, 0x50) and 14 <= len(p) <= 1024:
        return "OpenVPN?"            # confirmed by a second packet with the same session id
    return None


def openvpn_confirm(first: bytes, second: bytes) -> bool:
    """OpenVPN control packets carry the same 8-byte client session id."""
    return (len(first) >= 9 and len(second) >= 9 and first[0] in (0x38, 0x50)
            and (second[0] >> 3) in (4, 5, 7, 10) and first[1:9] == second[1:9])


# ---------------------------------------------------------------- BitTorrent

BT_HANDSHAKE = b"\x13BitTorrent protocol"
UDP_TRACKER_MAGIC = bytes.fromhex("0000041727101980")


def is_bittorrent_handshake(buf: bytes) -> bool:
    """Plain (unencrypted) peer-wire handshake. Needs only the first 20 bytes."""
    return buf[:20] == BT_HANDSHAKE[:len(buf[:20])] and len(buf) >= 20


def classify_torrent_udp(p: bytes) -> str | None:
    """DHT, uTP and UDP-tracker packets all have recognisable, unencrypted headers
    (even when the client encrypts its peer connections)."""
    if len(p) >= 16 and p[:8] == UDP_TRACKER_MAGIC and p[8:12] == b"\x00\x00\x00\x00":
        return "BitTorrent UDP tracker"
    if len(p) >= 12 and p[:4] in (b"d1:a", b"d1:r", b"d1:e", b"d1:q", b"d1:t", b"d1:v", b"d2:i", b"d2:r") \
            and (b"2:id20:" in p[:64] or b"1:y1:" in p or b"9:get_peers" in p or b"9:find_node" in p):
        return "BitTorrent DHT"
    # uTP SYN: type 4 / version 1, timestamp_difference must be 0 on a SYN
    if len(p) >= 20 and p[0] == 0x41 and p[1] in (0, 1, 2) and p[8:12] == b"\x00\x00\x00\x00":
        return "BitTorrent uTP"
    return None


def is_torrent_http(target: str) -> bool:
    t = target.lower()
    return t.startswith(("/announce", "/scrape")) or "info_hash=" in t


def identify_tcp_stream(buf: bytes) -> str:
    """Describe the opening bytes of a non-TLS, non-HTTP stream for an alert."""
    if not buf:
        return "no data"
    if buf.startswith(b"SSH-"):
        return "SSH"
    if is_bittorrent_handshake(buf):
        return "BitTorrent peer connection"
    if len(buf) >= 3:
        n = struct.unpack("!H", buf[:2])[0]
        if n == 148 and buf[2] == 1 and buf[3:6] == b"\x00\x00\x00":
            return "WireGuard over TCP (e.g. Mullvad udp2tcp obfuscation)"
        if buf[2] in (0x38, 0x50) and 14 <= n <= 1024 and n <= len(buf) - 2 + 1500:
            return "OpenVPN over TCP"
    if buf[:1] == b"\x05" and len(buf) <= 10:
        return "SOCKS5 proxy"
    if buf[:1] == b"\x04":
        return "SOCKS4 proxy"
    sample = buf[:512]
    # normalised entropy: random/encrypted bytes score close to 1.0, text ~0.6-0.75
    if len(sample) >= 32 and entropy(sample) / math.log2(min(len(sample), 256)) > 0.85:
        return "encrypted/obfuscated stream (Shadowsocks, obfs4, VLESS-style)"
    return "unrecognised protocol"
