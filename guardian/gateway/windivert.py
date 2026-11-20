"""The Windows gateway: the same inspector as the Raspberry Pi, fed by WinDivert.

On the Pi every device's traffic passes through the firewall, which hands the
first packets of each connection to the inspector. Windows has no nftables, so
here the WinDivert driver (https://reqrypt.org/windivert.html, via pydivert)
diverts packets to this program instead - the verdicts come from exactly the
same code (inspector.py, policy, protections, DNS filter):

  * this PC      - its own outgoing connections. Its DNS lookups are answered by
                   the gateway's DNS filter whatever server they were sent to.
  * its hotspot  - devices connected to Windows Mobile Hotspot (192.168.137.x by
                   default): their forwarded traffic and their DNS lookups.

What differs from the Pi:
  * No separate box: if this program stops, traffic flows unfiltered again
    (WinDivert lets packets through once the program is gone). For a child's
    own PC, run it as a service and give the child a standard (non-admin)
    account, so they can't stop it.
  * Only devices on this PC's hotspot are covered, not the whole house.
"""
from __future__ import annotations

import collections
import ipaddress
import socket
import struct
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

ACCEPT, DROP, RESET = "accept", "drop", "reset"
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                                                "100.64.0.0/10", "127.0.0.0/8")]
TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10


# ------------------------------------------------------------------ packets
def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _ip_header(src, dst, proto, length, ttl=64) -> bytes:
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + length, 0, 0x4000, ttl, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack("!H", _csum(h)) + h[12:]


def build_udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, length)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    c = _csum(pseudo + hdr + payload) or 0xFFFF
    return _ip_header(src, dst, 17, length) + hdr[:6] + struct.pack("!H", c) + payload


def build_tcp_rst(src: str, dst: str, sport: int, dport: int, seq: int, ack: int) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4,
                      TCP_RST | TCP_ACK, 0, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr))
    c = _csum(pseudo + hdr)
    return _ip_header(src, dst, 6, len(hdr)) + hdr[:16] + struct.pack("!H", c) + hdr[18:]


class Pkt:
    __slots__ = ("raw", "proto", "src", "dst", "sport", "dport", "flags", "seq", "ack", "plen", "payload")


def parse(raw: bytes) -> Pkt | None:
    """Just what the engine needs from an IPv4 TCP/UDP packet."""
    if len(raw) < 20 or raw[0] >> 4 != 4:
        return None
    ihl = (raw[0] & 0x0F) * 4
    total = struct.unpack("!H", raw[2:4])[0] or len(raw)
    p = Pkt()
    p.raw, p.proto = raw, raw[9]
    p.src, p.dst = socket.inet_ntoa(raw[12:16]), socket.inet_ntoa(raw[16:20])
    p.flags = p.seq = p.ack = 0
    if p.proto == 6 and len(raw) >= ihl + 20:
        p.sport, p.dport, p.seq, p.ack, off, p.flags = struct.unpack("!HHIIBB", raw[ihl:ihl + 14])
        start = ihl + (off >> 4) * 4
    elif p.proto == 17 and len(raw) >= ihl + 8:
        p.sport, p.dport = struct.unpack("!HH", raw[ihl:ihl + 4])
        start = ihl + 8
    else:
        return None
    p.payload = raw[start:total]
    p.plen = len(p.payload)
    return p


def _private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _PRIVATE) or a.is_multicast or ip == "255.255.255.255"


# ------------------------------------------------------------------ the driver (adapter)
class DivertHandle:
    """pydivert behind a tiny interface, so the engine can be tested without Windows."""

    def __init__(self, filt: str, layer: str = "network", drop: bool = False, priority: int = 0):
        import pydivert                                   # Windows only
        lay = pydivert.Layer.NETWORK_FORWARD if layer == "forward" else pydivert.Layer.NETWORK
        flags = pydivert.Flag.DROP if drop else pydivert.Flag.DEFAULT
        self._pd = pydivert
        self.w = pydivert.WinDivert(filt, layer=lay, priority=priority, flags=flags)
        self.w.open()

    def recv(self):
        p = self.w.recv()
        return bytes(p.raw), p.direction == self._pd.Direction.OUTBOUND, p.interface

    def send(self, raw: bytes, outbound: bool, interface):
        d = self._pd.Direction.OUTBOUND if outbound else self._pd.Direction.INBOUND
        self.w.send(self._pd.Packet(raw, interface, d), recalculate_checksum=True)

    def close(self):
        try:
            self.w.close()
        except Exception:
            pass


def available() -> tuple[bool, str]:
    if not sys.platform.startswith("win"):
        return False, "WinDivert is Windows-only"
    try:
        import pydivert  # noqa: F401
    except Exception as e:
        return False, f"pydivert isn't installed ({e}) - pip install -r requirements-windows.txt"
    return True, ""


# ------------------------------------------------------------------ the gateway
class _Flow:
    __slots__ = ("n", "passed", "killed", "last")

    def __init__(self):
        self.n, self.passed, self.killed, self.last = 0, False, False, time.time()


class WindowsGateway:
    backend = "windivert"

    def __init__(self, cfg, lists, db, inspector, resolver=None, identity=None, policy=None, opener=None):
        self.cfg, self.lists, self.db, self.inspector = cfg, lists, db, inspector
        self.resolver, self.identity, self.policy = resolver, identity, policy
        w = cfg.get("windows") or {}
        self.protect_pc = bool(w.get("protect_this_pc", True))
        self.hotspot_enabled = bool(w.get("hotspot", True))
        self.hotspot_ip = w.get("hotspot_ip") or "192.168.137.1"
        self.hotspot_net = ipaddress.ip_network(f"{self.hotspot_ip}/{int(w.get('hotspot_prefix', 24))}", strict=False)
        self.inspect_pkts = int(cfg["enforcement"].get("inspect_packets", 10))
        self._real_driver = opener is None
        self.opener = opener or (lambda filt, layer="network", drop=False: DivertHandle(filt, layer, drop))
        self.queue_num = 0                                # (the Pi's queue slot; unused here)
        self.handles: dict[str, object] = {}
        self.flows: dict[tuple, _Flow] = {}
        self.paused: set[str] = set()
        self.local_ips: set[str] = set()
        self.local_mac = None
        self.running = False
        self.stats = collections.Counter()
        self.seen_hotspot_clients: set[str] = set()
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="divert-dns")
        self.status = {"applied": False, "error": None, "backend": self.backend}
        inspector.lan_ip = None                          # no gateway-port probing here

    # ---------------------------------------------------- set-up
    def _discover(self):
        ips = set()
        try:
            ips.update(a for a in socket.gethostbyname_ex(socket.gethostname())[2] if not a.startswith("127."))
        except OSError:
            pass
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("192.0.2.1", 9))
                ips.add(s.getsockname()[0])
        except OSError:
            pass
        mac = ":".join(f"{(uuid.getnode() >> s) & 0xFF:02x}" for s in range(40, -8, -8))
        self.local_ips, self.local_mac = ips, mac
        if self.identity is not None:
            for ip in ips:
                self.identity.learn(ip, mac)              # this PC = one device, whatever adapter it uses
        return ips

    def hotspot_up(self) -> bool:
        return self.hotspot_ip in self.local_ips

    def _upstream_exclusions(self) -> str:
        ups = list(self.cfg["dns"].get("upstreams") or []) + list((self.cfg.get("adult") or {}).get("family_dns") or [])
        parts = [f"(tcp.DstPort == 53 and ip.DstAddr == {u})" for u in ups if _is_v4(u)]
        return (" and not (" + " or ".join(parts) + ")") if parts else ""

    def filters(self) -> dict[str, tuple[str, str, bool]]:
        """name -> (filter, layer, drop-in-kernel)."""
        f = {}
        lo, hi = self.hotspot_net.network_address, self.hotspot_net.broadcast_address
        dns = "outbound and !loopback and ip and udp.DstPort == 53"
        if self.hotspot_enabled:
            dns = f"({dns}) or (inbound and ip and udp.DstPort == 53 and ip.DstAddr == {self.hotspot_ip})"
        f["dns"] = (dns, "network", False)
        if self.protect_pc:
            not_lan = ("ip.DstAddr < 224.0.0.0 and not (ip.DstAddr >= 10.0.0.0 and ip.DstAddr <= 10.255.255.255)"
                       " and not (ip.DstAddr >= 172.16.0.0 and ip.DstAddr <= 172.31.255.255)"
                       " and not (ip.DstAddr >= 192.168.0.0 and ip.DstAddr <= 192.168.255.255)"
                       " and not (ip.DstAddr >= 169.254.0.0 and ip.DstAddr <= 169.254.255.255)")
            f["local"] = (f"outbound and !loopback and ip and {not_lan} and "
                          f"((tcp and (tcp.Syn or tcp.PayloadLength > 0)) or "
                          f"(udp and udp.DstPort != 53 and udp.DstPort != 123 and udp.DstPort != 67))"
                          + self._upstream_exclusions(), "network", False)
        if self.hotspot_enabled:
            f["forward"] = (f"ip and ip.SrcAddr >= {lo} and ip.SrcAddr <= {hi} and "
                            f"((tcp and (tcp.Syn or tcp.PayloadLength > 0)) or udp)", "forward", False)
        return f

    def setup(self, devices: dict | None = None):
        ok, why = available() if self._real_driver else (True, "")
        if not ok:
            self.status = {"applied": False, "error": why, "backend": self.backend}
            raise RuntimeError(why)
        self._discover()
        if devices:
            self.paused = set(devices.get("paused") or ())
        self.running = True
        self._open_all()
        threading.Thread(target=self._housekeeping, name="divert-housekeeping", daemon=True).start()
        self.status = {"applied": True, "error": None, "backend": self.backend, "applied_at": time.time(),
                       "protect_this_pc": self.protect_pc, "hotspot": self.hotspot_up(),
                       "hotspot_ip": self.hotspot_ip, "this_pc": sorted(self.local_ips),
                       "handles": sorted(self.handles)}

    def pc_filtered(self) -> bool:
        if self.policy is None or not self.local_ips:
            return True
        ip = sorted(self.local_ips)[0]
        return bool(self.policy.context(ip, self.local_mac).filtered) or (self.local_mac in self.paused)

    def _open_all(self):
        want = self.filters()
        pc_filtered = self.pc_filtered()
        if self.protect_pc and pc_filtered:
            # IPv6 isn't inspected (as on the Pi, where it's switched off): drop this PC's
            # public IPv6 in the driver itself, so Windows falls back to IPv4.
            want["ipv6"] = ("outbound and !loopback and ipv6 and (tcp or udp) and "
                            "ipv6.DstAddr >= 2000:: and ipv6.DstAddr <= 3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                            "network", True)
        for name in [n for n in ("local", "ipv6") if n in self.handles]:
            if not pc_filtered or name not in want:      # an adult's PC isn't slowed down at all
                self.handles.pop(name).close()
        for name, (filt, layer, drop) in want.items():
            if name in self.handles:
                continue
            if name == "forward" and not self.hotspot_up():
                continue                                  # opened when the hotspot comes on
            if name == "local" and not pc_filtered:
                continue
            try:
                h = self.opener(filt, layer=layer, drop=drop)
            except Exception as e:
                self.status["error"] = f"couldn't open the {name} packet filter: {e}"
                if name in ("dns", "local"):
                    raise
                continue
            self.handles[name] = h
            if not drop:
                threading.Thread(target=self._loop, args=(name, h), name=f"divert-{name}", daemon=True).start()
        self.status["handles"] = sorted(self.handles)

    def _housekeeping(self):
        while self.running:
            time.sleep(15)
            try:
                self._discover()
                self.status["hotspot"] = self.hotspot_up()
                self._open_all()
                cutoff = time.time() - 300
                with self._lock:
                    self.flows = {k: v for k, v in self.flows.items() if v.last >= cutoff}
            except Exception as e:
                print(f"[windivert] housekeeping: {e}")

    def teardown(self):
        self.running = False
        for h in self.handles.values():
            h.close()
        self.handles = {}

    # ---------------------------------------------------- the Pi's interface (what app.py calls)
    def sync_device_sets(self, trusted, paused, udp_ok, admin, open_=(), force=False):
        self.paused = set(paused)
        if self.running:
            self._open_all()                              # this PC changed group / was paused
        return set()

    def sync_ip_sets(self, force=False):
        return False                                      # the inspector reads the lists directly

    def block_ip(self, ip: str, seconds: int, reason: str, device_id=None):
        if self.db is not None:
            self.db.add_dyn_block(ip, reason, device_id, time.time() + seconds)
        self.inspector.dyn_blocked.add(ip)
        self._kill(lambda k: k[3] == ip)

    def unblock_ip(self, ip: str):
        if self.db is not None:
            self.db.remove_dyn_block(ip)
        self.inspector.dyn_blocked.discard(ip)

    def kill_device_flows(self, ip: str):
        self._kill(lambda k: k[1] == ip)

    def kill_flow(self, proto: str, src: str, sport: int, dst: str, dport: int):
        self._kill(lambda k: k == (proto, src, int(sport), dst, int(dport)))

    def _kill(self, match):
        with self._lock:
            for k, f in self.flows.items():
                if match(k):
                    f.killed, f.passed = True, False

    # ---------------------------------------------------- packets
    def _loop(self, name, h):
        while self.running and self.handles.get(name) is h:
            try:
                raw, outbound, iface = h.recv()
            except Exception as e:
                if self.running and self.handles.get(name) is h:
                    self.stats["recv_errors"] += 1
                    print(f"[windivert] {name}: {e}")
                    time.sleep(0.2)
                continue
            try:
                self.on_packet(name, h, raw, outbound, iface)
            except Exception as e:                        # one bad packet must not stop the loop
                self.stats["errors"] += 1
                if self.stats["errors"] < 20:
                    import traceback
                    traceback.print_exc()
                # fail open for a broken packet only if the policy says so
                if self.cfg["enforcement"].get("fail_open"):
                    h.send(raw, outbound, iface)

    def _client_kind(self, name, p, outbound) -> str:
        """'pc' = this computer is the client; 'hotspot' = a device on its hotspot."""
        if name == "forward":
            return "hotspot"
        if name == "dns" and not outbound:
            return "hotspot"
        return "pc"

    def on_packet(self, name, h, raw: bytes, outbound: bool, iface):
        self.stats["packets"] += 1
        p = parse(raw)
        if p is None:
            h.send(raw, outbound, iface)
            return
        kind = self._client_kind(name, p, outbound)
        if kind == "hotspot":
            self.seen_hotspot_clients.add(p.src)
        if p.proto == 17 and p.dport == 53:
            self.stats["dns"] += 1
            self._pool.submit(self._answer_dns, kind, p, iface)
            return                                        # answered by us; the original goes nowhere
        mac = self.local_mac if kind == "pc" else (self.identity.mac_for(p.src) if self.identity else None)
        key = ("tcp" if p.proto == 6 else "udp", p.src, p.sport, p.dst, p.dport)
        with self._lock:
            fl = self.flows.get(key)
            if fl is None:
                fl = self.flows[key] = _Flow()
            fl.last = time.time()
            fl.n += 1
        if fl.killed:
            return self._refuse(kind, p, iface)
        if fl.passed:
            h.send(raw, outbound, iface)
            return
        if mac and mac in self.paused:
            self.stats["paused"] += 1
            return self._refuse(kind, p, iface)
        if kind == "hotspot" and _private(p.dst) and p.dst != self.hotspot_ip and self.policy is not None:
            if self.policy.context(p.src, mac).filtered:  # no reaching the home network / router settings
                self.stats["private_dst"] += 1
                return
        v = self.inspector.inspect(raw, mac)
        if v.action == ACCEPT:
            limit = self.inspect_pkts if (p.proto == 6 and p.dport in (80, 443)) else 3
            if v.kind == "done" or fl.n >= limit:     # checked (usually after 2-3 packets): fast path
                fl.passed = True                          # like the Pi: only the first packets are inspected
            h.send(raw, outbound, iface)
        elif v.action == RESET:
            self.stats["reset"] += 1
            self._refuse(kind, p, iface)
        else:
            self.stats["drop"] += 1

    def _refuse(self, kind, p, iface):
        """Answer a blocked TCP connection with a reset so the app gives up at once."""
        if p.proto != 6 or p.flags & TCP_RST:
            return
        ack = p.seq + p.plen + (1 if p.flags & TCP_SYN else 0) + (1 if p.flags & TCP_FIN else 0)
        rst = build_tcp_rst(p.dst, p.src, p.dport, p.sport, p.ack if p.flags & TCP_ACK else 0, ack)
        self._inject_to_client(kind, rst, iface)

    def _inject_to_client(self, kind, raw, iface):
        h = self.handles.get("dns") or self.handles.get("local")
        if h is None:
            return
        # this PC: deliver it inbound; a hotspot device: send it out towards the device
        h.send(raw, kind != "pc", iface)

    def _answer_dns(self, kind, p, iface):
        from dnslib import DNSRecord
        try:
            req = DNSRecord.parse(p.payload)
        except Exception:
            self.stats["dns_bad"] += 1
            return

        class H:
            client_address = (p.src, p.sport)
        try:
            reply = self.resolver.resolve(req, H())
            data = reply.pack()
        except Exception as e:
            self.stats["dns_errors"] += 1
            print(f"[windivert] dns: {e}")
            return
        self._inject_to_client(kind, build_udp(p.dst, p.src, p.dport, p.sport, data), iface)


def _is_v4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False
