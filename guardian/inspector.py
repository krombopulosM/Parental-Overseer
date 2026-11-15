"""The verdict engine. Given the first packets of a filtered device's connection,
decide: let it through, drop it, or reset it - and explain why.

Layered checks (any one is enough to stop a bypass):

  1. Destination lists   known VPN servers / encrypted-DNS resolvers / tunnel IPs
  2. DNS consistency     the device must have been handed this IP by our DNS
  3. Protocol conformance on web ports: 443 must open with a TLS ClientHello,
                         80 with an HTTP request. Disguised VPNs (Mullvad udp2tcp,
                         OpenVPN-TCP, Shadowsocks, obfs4, SSH...) fail here.
  4. TLS inspection      SNI must be present, allowed, not an ECH front, and
                         consistent with the DNS answer (stops Reality/fronting)
  5. UDP signatures      WireGuard / OpenVPN / IPsec / QUIC / DTLS-VPN
  6. Anti-evasion        handshakes split into tiny pieces or held back past the
                         inspection window are treated as hostile

It is a pure function of packets + shared state, so the same code runs inline
on the Pi (NFQUEUE), in the replay tool and in tests.
"""
from __future__ import annotations

import collections
import threading
import time
from dataclasses import dataclass

from .protocols import (NEED_MORE, TCP_FIN, TCP_RST, classify_udp, identify_tcp_stream,
                        openvpn_confirm, parse_client_hello, parse_http_request, parse_ip)
from .services import is_ip_literal, name_matches, registrable_domain

ACCEPT, DROP, RESET = "accept", "drop", "reset"

VPN_PORTS = {1194: "OpenVPN", 1195: "OpenVPN", 1196: "OpenVPN", 1197: "OpenVPN", 1198: "OpenVPN",
             51820: "WireGuard", 51821: "WireGuard", 500: "IPsec/IKE", 4500: "IPsec/IKE",
             1701: "L2TP", 1723: "PPTP", 9001: "Tor", 9030: "Tor", 9050: "Tor", 9150: "Tor",
             853: "DNS-over-TLS (Android Private DNS)", 8853: "DNS-over-QUIC",
             1080: "SOCKS proxy", 3128: "HTTP proxy", 8080: "HTTP proxy", 8888: "HTTP proxy",
             5001: "Mullvad udp2tcp", 2408: "Cloudflare WARP", 992: "SoftEther VPN",
             5555: "SoftEther VPN", 1443: "VPN over alt-TLS port", 8443: "alt HTTPS / VPN"}
WEB_PORTS = (80, 443)


@dataclass
class Verdict:
    action: str
    reason: str = ""
    kind: str | None = None


ALLOW = Verdict(ACCEPT)


class FlowLabels:
    """What the inspector learned about each connection (site name, fingerprint,
    verdict). The flow monitor reads this to label byte counts."""

    def __init__(self, cap: int = 100000):
        self._d: collections.OrderedDict = collections.OrderedDict()
        self._lock = threading.Lock()
        self.cap = cap

    def set(self, key, **info):
        with self._lock:
            cur = self._d.get(key)
            if cur is None:
                cur = {}
                self._d[key] = cur
                if len(self._d) > self.cap:
                    self._d.popitem(last=False)
            cur.update({k: v for k, v in info.items() if v is not None})

    def get(self, key):
        with self._lock:
            v = self._d.get(key)
            return dict(v) if v else None


class _Flow:
    __slots__ = ("created", "last", "base", "segs", "buffered", "pkts", "empty", "got_payload",
                 "verdict", "udp_first", "saw_stun")

    def __init__(self, now):
        self.created = self.last = now
        self.base = None
        self.segs: dict[int, bytes] = {}
        self.buffered = 0
        self.pkts = 0
        self.empty = 0
        self.got_payload = False
        self.verdict: Verdict | None = None
        self.udp_first = None
        self.saw_stun = False

    def assemble(self) -> bytes:
        out = b""
        for off in sorted(self.segs):
            if off > len(out):
                break
            seg = self.segs[off]
            if off + len(seg) > len(out):
                out += seg[len(out) - off:]
        return out


class Inspector:
    def __init__(self, cfg, policy, lists, dnscache, alerts, labels: FlowLabels | None = None):
        enf = cfg["enforcement"]
        self.cfg = cfg
        self.policy, self.lists, self.dnscache, self.alerts = policy, lists, dnscache, alerts
        self.labels = labels or FlowLabels()
        self.max_pkts = int(enf.get("inspect_packets", 10))
        self.ech_names = {n.lower() for n in enf.get("ech_public_names") or []}
        self.dyn_blocked: set[str] = set()
        self.flows: dict[tuple, _Flow] = {}
        self.stats = collections.Counter()
        self._since_gc = 0

    # ------------------------------------------------------------ entry point
    def inspect(self, raw: bytes, mac: str | None = None, now: float | None = None) -> Verdict:
        now = now or time.time()
        pkt = parse_ip(raw)
        if pkt is None or not (pkt.is_tcp or pkt.is_udp):
            return ALLOW
        self.stats["packets"] += 1
        ctx = self.policy.context(pkt.src, mac)
        if not ctx.filtered:
            return ALLOW
        self._since_gc += 1
        if self._since_gc > 2000:
            self._gc(now)

        proto = "tcp" if pkt.is_tcp else "udp"
        key = (proto, pkt.src, pkt.sport, pkt.dst, pkt.dport)

        # 1. destination lists (cheap, applies to everything)
        v = self._check_destination(ctx, pkt, key)
        if v:
            return v

        if pkt.is_tcp and pkt.dport in WEB_PORTS:
            return self._tcp_web(ctx, pkt, key, now)
        if pkt.is_udp and ctx.g.get("allow_udp"):
            return self._udp(ctx, pkt, key, now)
        return self._other_port(ctx, pkt, key)

    # ------------------------------------------------------------ helpers
    def _block(self, ctx, pkt, key, kind, detail, action=RESET, domain=None, alert=True,
               severity=None, flow: _Flow | None = None) -> Verdict:
        if pkt.is_udp and action == RESET:
            action = DROP
        v = Verdict(action, detail, kind)
        if flow is not None:
            flow.verdict = v
        self.stats[f"block:{kind}"] += 1
        self.labels.set(key, verdict="blocked", reason=detail, kind=kind)
        if alert and self.alerts:
            self.alerts.emit(kind, device_id=ctx.device_id, client_ip=ctx.ip, dst=pkt.dst,
                             domain=domain, detail=detail, severity=severity)
        return v

    def _check_destination(self, ctx, pkt, key) -> Verdict | None:
        hit = self.lists.ip_list_match(pkt.dst)
        if hit == "vpn":
            name = self.dnscache.best_name(ctx.ip, pkt.dst)
            return self._block(ctx, pkt, key, "vpn_server",
                               f"{pkt.dst}:{pkt.dport} is a known VPN/Tor server"
                               + (f" ({name})" if name else ""), action=DROP, domain=name)
        if hit == "doh":
            return self._block(ctx, pkt, key, "doh_server",
                               f"{pkt.dst}:{pkt.dport} is a public encrypted-DNS resolver",
                               action=DROP)
        if pkt.dst in self.dyn_blocked:
            return self._block(ctx, pkt, key, "tunnel_behaviour",
                               f"{pkt.dst} was blocked after tunnel-like behaviour",
                               action=DROP, alert=False)
        return None

    def _consistency_mode(self, ctx, dst) -> str:
        mode = ctx.g.get("dns_consistency", "off")
        if mode != "off" and dst in self.lists.exempt:
            return "off"
        return mode

    # ------------------------------------------------------------ TCP 80/443
    def _tcp_web(self, ctx, pkt, key, now) -> Verdict:
        fl = self.flows.get(key)
        if fl is None:
            fl = self.flows[key] = _Flow(now)
        fl.last = now
        fl.pkts += 1
        if fl.verdict is not None:
            return fl.verdict
        if pkt.flags & (TCP_RST | TCP_FIN) and not pkt.payload:
            return ALLOW

        if pkt.syn_only:
            fl.base = (pkt.seq + 1) & 0xFFFFFFFF
            mode = self._consistency_mode(ctx, pkt.dst)
            if mode != "off" and self.dnscache.resolved_by(ctx.ip, pkt.dst) is None:
                known = self.dnscache.names_for_ip(pkt.dst)
                detail = (f"Connected to {pkt.dst}:{pkt.dport} without looking it up through the "
                          f"gateway's DNS (hard-coded VPN/proxy address, private DNS, or a "
                          f"hosts-file entry)")
                if known:
                    detail += f"; that IP is known as {sorted(known)[0]}"
                if mode == "enforce":
                    return self._block(ctx, pkt, key, "no_dns", detail, flow=fl)
                self.alerts and self.alerts.emit("no_dns", device_id=ctx.device_id, client_ip=ctx.ip,
                                                 dst=pkt.dst, detail=detail, action="allowed (log mode)",
                                                 severity="low")
            return ALLOW

        if not pkt.payload:
            if fl.base is not None and not fl.got_payload:
                fl.empty += 1
                if fl.empty > 3:
                    return self._block(ctx, pkt, key, "server_first",
                                       f"Server spoke first on port {pkt.dport}; web traffic never "
                                       f"does this (SSH/VPN-style protocol)", flow=fl)
            return self._evasion_check(ctx, pkt, key, fl)

        fl.got_payload = True
        if fl.base is None:
            fl.base = pkt.seq
        rel = (pkt.seq - fl.base) & 0xFFFFFFFF
        if rel < 65536 and rel not in fl.segs:
            fl.segs[rel] = pkt.payload
            fl.buffered += len(pkt.payload)
        buf = fl.assemble()

        if pkt.dport == 443:
            res = parse_client_hello(buf)
            if res is None:
                return self._block(ctx, pkt, key, "protocol_violation",
                                   f"Port 443 traffic that isn't TLS: "
                                   f"{identify_tcp_stream(buf)}", flow=fl)
            if res is NEED_MORE:
                if fl.buffered > 32768:
                    return self._block(ctx, pkt, key, "protocol_violation",
                                       "Oversized/garbled TLS handshake", flow=fl)
                return self._evasion_check(ctx, pkt, key, fl)
            return self._decide_tls(ctx, pkt, key, fl, res)

        res = parse_http_request(buf)
        if res is None:
            return self._block(ctx, pkt, key, "protocol_violation",
                               f"Port 80 traffic that isn't HTTP: {identify_tcp_stream(buf)}", flow=fl)
        if res is NEED_MORE:
            return self._evasion_check(ctx, pkt, key, fl)
        return self._decide_http(ctx, pkt, key, fl, res)

    def _evasion_check(self, ctx, pkt, key, fl) -> Verdict:
        # Past this many packets the gateway stops sending the connection to us;
        # an unfinished handshake at that point is a deliberate attempt to slip past.
        if fl.pkts >= self.max_pkts:
            return self._block(ctx, pkt, key, "evasion",
                               f"Handshake still incomplete after {fl.pkts} packets (split into "
                               f"tiny pieces to dodge inspection)", flow=fl)
        return ALLOW

    def _name_checks(self, ctx, pkt, key, fl, name, what) -> Verdict:
        """Shared checks once we know the site name (TLS SNI or HTTP Host)."""
        d = self.policy.decide(ctx, name)
        if d.block:
            kind = "bypass_domain" if d.category == "bypass" else "dns_bypass_site"
            return self._block(ctx, pkt, key, kind,
                               f"{what} {name} is blocked ({d.reason}); reached without our DNS",
                               domain=registrable_domain(name), flow=fl)
        mode = self._consistency_mode(ctx, pkt.dst)
        if mode != "off":
            names = self.dnscache.resolved_by(ctx.ip, pkt.dst)
            if names and not name_matches(name, names):
                detail = (f"{what} says {name} but {pkt.dst} was looked up as "
                          f"{sorted(names)[0]} - disguised tunnel or domain fronting")
                if mode == "enforce":
                    return self._block(ctx, pkt, key, "sni_mismatch", detail, domain=name, flow=fl)
                self.alerts and self.alerts.emit("sni_mismatch", device_id=ctx.device_id,
                                                 client_ip=ctx.ip, dst=pkt.dst, domain=name,
                                                 detail=detail, action="allowed (log mode)",
                                                 severity="low")
        fl.verdict = ALLOW
        self.stats["allowed_web"] += 1
        return ALLOW

    def _decide_tls(self, ctx, pkt, key, fl, ch) -> Verdict:
        self.labels.set(key, domain=ch.sni, domain_src="sni", ja4=ch.ja4)
        if not ch.sni or ch.sni_is_ip:
            if ctx.g.get("require_sni") and pkt.dst not in self.lists.exempt:
                return self._block(ctx, pkt, key, "no_sni",
                                   f"TLS to {pkt.dst} without a site name"
                                   + (f" (used IP {ch.sni})" if ch.sni else "")
                                   + " - typical of VPN/proxy clients", flow=fl)
            fl.verdict = ALLOW
            return ALLOW
        if ch.sni in self.ech_names or registrable_domain(ch.sni) in self.ech_names:
            return self._block(ctx, pkt, key, "ech",
                               f"Encrypted Client Hello via {ch.sni} hides which site is being "
                               f"visited", domain=ch.sni, flow=fl)
        return self._name_checks(ctx, pkt, key, fl, ch.sni, "TLS server name")

    def _decide_http(self, ctx, pkt, key, fl, req) -> Verdict:
        self.labels.set(key, domain=req.host, domain_src="http")
        if req.method == "CONNECT":
            return self._block(ctx, pkt, key, "http_proxy",
                               f"HTTP CONNECT to {req.target} (proxy tunnel)", flow=fl)
        if not req.host or is_ip_literal(req.host):
            if ctx.g.get("require_sni") and pkt.dst not in self.lists.exempt:
                return self._block(ctx, pkt, key, "no_sni",
                                   f"HTTP request to {pkt.dst} without a site name", flow=fl)
            fl.verdict = ALLOW
            return ALLOW
        return self._name_checks(ctx, pkt, key, fl, req.host, "HTTP Host")

    # ------------------------------------------------------------ UDP (groups that allow it)
    def _udp(self, ctx, pkt, key, now) -> Verdict:
        fl = self.flows.get(key)
        if fl is None:
            fl = self.flows[key] = _Flow(now)
        fl.last = now
        fl.pkts += 1
        if fl.verdict is not None:
            return fl.verdict
        sig = classify_udp(pkt.payload, pkt.dport)
        if fl.pkts == 1:
            fl.udp_first = pkt.payload
        elif sig != "WireGuard" and fl.udp_first and openvpn_confirm(fl.udp_first, pkt.payload):
            sig = "OpenVPN"
        if sig == "STUN":
            fl.saw_stun = True
        self.labels.set(key, proto_hint=sig)
        if sig in ("WireGuard", "OpenVPN", "IPsec/IKE"):
            return self._block(ctx, pkt, key, "blocked_udp",
                               f"{sig} VPN handshake to {pkt.dst}:{pkt.dport}", flow=fl)
        if sig == "DTLS" and not fl.saw_stun:
            return self._block(ctx, pkt, key, "blocked_udp",
                               f"DTLS VPN (AnyConnect/OpenConnect-style) to {pkt.dst}:{pkt.dport}",
                               flow=fl)
        if sig == "QUIC":
            # Not an attack - just push browsers back to TCP where the site name is visible.
            fl.verdict = Verdict(DROP, "QUIC disabled for filtered devices", "quic")
            self.stats["quic_dropped"] += 1
            return fl.verdict
        return ALLOW

    # ------------------------------------------------------------ everything else (always dropped)
    def _other_port(self, ctx, pkt, key) -> Verdict:
        proto = "UDP" if pkt.is_udp else "TCP"
        sig = classify_udp(pkt.payload, pkt.dport) if pkt.is_udp else None
        if sig == "QUIC" or (pkt.is_udp and pkt.dport == 443 and sig is None):
            self.stats["quic_dropped"] += 1
            return Verdict(DROP, "QUIC disabled for filtered devices", "quic")
        label = sig if sig in ("WireGuard", "IPsec/IKE") else VPN_PORTS.get(pkt.dport)
        if sig == "OpenVPN?" and pkt.dport in VPN_PORTS:
            label = "OpenVPN"
        if label:
            kind = "blocked_udp" if pkt.is_udp and sig else "blocked_port"
            sev = "high" if sig in ("WireGuard", "IPsec/IKE") or label == "OpenVPN" else "medium"
            return self._block(ctx, pkt, key, kind, f"{label} attempt to {pkt.dst} ({proto} "
                               f"{pkt.dport}) blocked - only web traffic is allowed",
                               action=DROP, severity=sev)
        self.stats["other_port_dropped"] += 1
        self.labels.set(key, verdict="blocked", reason=f"{proto} port {pkt.dport} not allowed")
        return Verdict(DROP, f"{proto} port {pkt.dport} not allowed", "port")

    # ------------------------------------------------------------ housekeeping
    def _gc(self, now):
        self._since_gc = 0
        cutoff = now - 120
        self.flows = {k: f for k, f in self.flows.items() if f.last >= cutoff}
