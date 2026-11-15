"""Passive defences against a skilled kid attacking the gateway itself.

Listens (read-only) on the LAN side for the tell-tale traffic of
countermeasures, and responds without ever granting more access:

  ARP      a device claiming the gateway's IP (ARP spoofing / MITM)      -> corrective ARP, auto-pause
           a device claiming another device's IP                        -> pin the real owner, auto-pause
  DHCP     a DHCP server that isn't the Pi (rogue DHCP)                 -> alert, auto-pause
           an adult's MAC with a different DHCP fingerprint (MAC spoof) -> treat as filtered until confirmed
           ... flipping between two fingerprints (two devices, one MAC) -> same, higher confidence
           a new MAC matching a known kid's device (MAC change)          -> keeps the kid's group
  IPv6 RA  a device advertising itself as a router                      -> alert, auto-pause
  LSD      a torrent client announcing itself on the LAN                 -> alert

The DHCP "fingerprint" is the list of options a device's operating system asks
for, plus its vendor string. It is very stable for a given device and differs
between operating systems, so a laptop pretending to be Dad's phone by copying
its MAC address still asks the DHCP server for a different set of options.
"""
from __future__ import annotations

import threading
import time

from .gateway import system
from .identity import norm_mac

BPF = "arp or (udp and (port 67 or port 68 or port 6771)) or (icmp6 and ip6[40] == 134)"


def _opt(options, name):
    for o in options:
        if isinstance(o, tuple) and o[0] == name:
            return o[1] if len(o) == 2 else list(o[1:])
    return None


def _text(v):
    if v is None:
        return ""
    if isinstance(v, bytes):
        return v.decode("latin-1", "replace")
    return str(v)


class LanWatch:
    def __init__(self, cfg, db, policy, identity, alerts, on_change=None):
        self.cfg, self.db, self.policy, self.identity, self.alerts = cfg, db, policy, identity, alerts
        self.on_change = on_change or (lambda: None)
        gw = cfg["gateway"]
        self.tm = cfg.get("tamper") or {}
        self.ifaces = list(gw.get("lan_interfaces") or [])
        self.lan_ip = gw.get("lan_ip")
        self.own_macs = {m for m in (system.iface_mac(i) for i in self.ifaces) if m}
        self.pins: dict[str, tuple[float, str]] = {}
        self.counters: dict[str, int] = {}
        self.running = False
        self.error = None
        self._static_alerted: dict[str, str] = {}
        self._defending = False

    # ------------------------------------------------------------ capture
    def start(self):
        def run():
            try:
                from scapy.all import sniff
                self.running = True
                sniff(iface=self.ifaces, filter=BPF, prn=self.handle, store=False)
            except Exception as e:
                self.error = str(e)
                print(f"[lanwatch] stopped: {e}")
            finally:
                self.running = False
        threading.Thread(target=run, name="lanwatch", daemon=True).start()

    def handle(self, pkt):
        from scapy.all import ARP, BOOTP, UDP, Ether
        from scapy.layers.inet6 import ICMPv6ND_RA
        try:
            if pkt.haslayer(ARP):
                self.on_arp(pkt[ARP], pkt[Ether].src if pkt.haslayer(Ether) else None)
            elif pkt.haslayer(BOOTP):
                self.on_dhcp(pkt)
            elif pkt.haslayer(ICMPv6ND_RA):
                self.on_ra(pkt)
            elif pkt.haslayer(UDP) and pkt[UDP].dport == 6771:
                self.on_lsd(pkt)
        except Exception as e:
            self.error = f"handler: {e}"

    def _count(self, name):
        self.counters[name] = self.counters.get(name, 0) + 1

    # ------------------------------------------------------------ helpers
    def _emit(self, kind, mac, ip, detail, action="detected", base=None, dst=None):
        return self.alerts.emit(kind, device_id=mac, client_ip=ip, detail=detail, action=action,
                                base=base, dst=dst)

    def _label(self, mac):
        d = self.db.get_device(mac) if mac else None
        if d:
            return d.get("name") or d.get("hostname") or mac
        return mac

    def _owner_of(self, ip, not_mac):
        """Who legitimately holds this IP right now (DHCP lease, else recent sighting)?"""
        lease_mac = self.identity.lease_owner(ip)
        if lease_mac and lease_mac != not_mac:
            return lease_mac
        row = self.db.query_one("SELECT mac FROM devices WHERE ip=? AND mac IS NOT NULL AND mac!=? "
                                "AND last_seen>=? ORDER BY last_seen DESC LIMIT 1",
                                (ip, not_mac, time.time() - 600))
        return row["mac"] if row else None

    def _corrective_arp(self):
        """Re-announce the gateway's real MAC so poisoned devices recover."""
        if self._defending:
            return
        self._defending = True

        def run():
            try:
                from scapy.all import ARP, Ether, sendp
                for iface in self.ifaces:
                    mac = system.iface_mac(iface)
                    if mac:
                        sendp(Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
                              ARP(op=2, hwsrc=mac, psrc=self.lan_ip, hwdst="ff:ff:ff:ff:ff:ff",
                                  pdst=self.lan_ip), iface=iface, count=5, inter=1, verbose=False)
            finally:
                self._defending = False
        threading.Thread(target=run, daemon=True).start()

    # ------------------------------------------------------------ ARP
    def on_arp(self, arp, eth_src=None):
        self._count("arp")
        mac = norm_mac(arp.hwsrc)
        ip = arp.psrc
        if not mac or mac in self.own_macs or not ip or ip == "0.0.0.0":
            return
        if ip == self.lan_ip:
            self._emit("arp_spoof", mac, None, dst=self.lan_ip,
                       detail=f"{self._label(mac)} announced that IT is the gateway ({self.lan_ip}). That "
                              f"is how traffic from other devices gets hijacked. The gateway re-announced "
                              f"its real address so other devices recover.",
                       action="countered")
            self._corrective_arp()
            return
        owner = self._owner_of(ip, mac)
        if owner:
            self._emit("ip_spoof", mac, ip, dst=ip,
                       detail=f"{self._label(mac)} claimed the address {ip}, which belongs to "
                              f"{self._label(owner)}. The gateway pinned {ip} to its real owner for "
                              f"{self.tm.get('repin_minutes', 10)} minutes.",
                       action="countered")
            for iface in self.ifaces:
                system.pin_neighbor(ip, owner, iface)
                self.pins[ip] = (time.time() + 60 * float(self.tm.get("repin_minutes", 10)), iface)
            self.identity.learn(ip, owner)

    def expire_pins(self):
        now = time.time()
        for ip, (until, iface) in list(self.pins.items()):
            if until < now:
                system.unpin_neighbor(ip, iface)
                del self.pins[ip]

    # ------------------------------------------------------------ DHCP
    def on_dhcp(self, pkt):
        from scapy.all import BOOTP, DHCP, Ether
        self._count("dhcp")
        b = pkt[BOOTP]
        options = pkt[DHCP].options if pkt.haslayer(DHCP) else []
        mtype = _opt(options, "message-type")
        if isinstance(mtype, str):          # scapy gives names for packets it built itself
            mtype = {"discover": 1, "offer": 2, "request": 3, "decline": 4, "ack": 5, "nak": 6,
                     "release": 7, "inform": 8}.get(mtype, 0)
        src_mac = norm_mac(pkt[Ether].src) if pkt.haslayer(Ether) else None
        if b.op == 2 or mtype in (2, 5, 6):                  # a server answering
            if src_mac and src_mac not in self.own_macs:
                known = self.db.get_device(src_mac)
                router = _opt(options, "router")
                dns = _opt(options, "name_server")
                self._emit("rogue_dhcp", src_mac, b.siaddr if b.siaddr != "0.0.0.0" else None,
                           base=90 if known else 70,
                           detail=f"{self._label(src_mac)} is handing out network settings (gateway "
                                  f"{_text(router) or '?'}, DNS {_text(dns) or '?'}) to other devices. "
                                  + ("" if known else "If this is your Wi-Fi access point, turn off its DHCP "
                                                      "server - everything must get its settings from the Pi."))
            return
        if mtype not in (1, 3, 8):                          # discover / request / inform
            return
        mac = norm_mac(":".join(f"{x:02x}" for x in bytes(b.chaddr)[:6]))
        if not mac or mac in self.own_macs:
            return
        prl = _opt(options, "param_req_list") or []
        if isinstance(prl, (bytes, bytearray)):
            prl = list(prl)
        fp = f"prl={','.join(str(x) for x in prl)};vc={_text(_opt(options, 'vendor_class_id'))}"
        host = _text(_opt(options, "hostname")) or None
        ip = _opt(options, "requested_addr") or (b.ciaddr if b.ciaddr != "0.0.0.0" else None)
        self.fingerprint(mac, fp, host, ip)

    def fingerprint(self, mac, fp, host, ip=None):
        known = self.db.get_fingerprint(mac)
        now = time.time()
        if known is None:
            self.db.save_fingerprint(mac, fp, host)
            if self.tm.get("carry_over_identity", True):
                self._carry_over(mac, fp, host, ip)
            return
        if known["fp"] == fp:
            self.db.save_fingerprint(mac, fp, host)
            return
        flip = known.get("prev_fp") == fp and known.get("changed") and now - known["changed"] < 86400
        self.db.save_fingerprint(mac, fp, host, prev_fp=known["fp"], changed=now)
        group = self.policy.configured_group(mac)
        if self.cfg["groups"][group]["filtered"]:
            return            # a filtered device changing OS gains nothing; don't nag
        kind = "mac_clone" if flip else "mac_spoof"
        conf, _ = self.alerts.scorer.score(kind, mac)
        quarantine = conf is not None and conf >= int(self.tm.get("auto_quarantine_confidence", 80))
        who = self._label(mac)
        detail = (f"Two different devices are taking turns using {who}'s hardware address ({mac})."
                  if flip else
                  f"A device using {who}'s hardware address ({mac}) identified itself differently from "
                  f"before (hostname '{host or '?'}', different DHCP options) - typical of a copied MAC.")
        if quarantine:
            self.db.set_suspect(mac, True)
            detail += (" Until you confirm it, this address gets the filtered policy. If it really is "
                       "your device (new OS or adapter), click \"It's me\".")
            self.on_change()
        self._emit(kind, mac, ip, detail=detail, action="treated as filtered" if quarantine else "detected")

    def _carry_over(self, mac, fp, host, ip):
        match = self.db.find_fingerprint_match(fp, host, mac)
        if not match:
            return
        old = match["mac"]
        old_group = self.policy.configured_group(old)
        filtered = self.cfg["groups"][old_group]["filtered"]
        row = self.db.get_device(mac)
        label = self._label(old)
        if filtered and (row is None or row.get("group_name") is None):
            old_row = self.db.get_device(old) or {}
            self.db.update_device(mac, name=(old_row.get("name") or None) if not (row or {}).get("name") else None,
                                  group=old_group, set_group=True)
            self.policy.reload()
            self.on_change()
            self._emit("mac_change", mac, ip,
                       detail=f"'{host}' came back with a new hardware address ({old} -> {mac}). Phones do "
                              f"this on their own ('private Wi-Fi address'), and so does a kid trying to "
                              f"escape their group. Either way it keeps {label}'s '{old_group}' settings.",
                       action=f"kept in {old_group}")
        elif not filtered:
            self._emit("mac_change", mac, ip, base=60,
                       detail=f"A new device copied the name and DHCP fingerprint of {label}, an "
                              f"'{old_group}' device. It was NOT given that access; it stays filtered "
                              f"until you assign it.",
                       action="stays filtered")

    # ------------------------------------------------------------ IPv6 RA / torrent LAN discovery
    def on_ra(self, pkt):
        from scapy.all import Ether
        self._count("ra")
        mac = norm_mac(pkt[Ether].src) if pkt.haslayer(Ether) else None
        if mac and mac not in self.own_macs:
            self._emit("rogue_ra", mac, None,
                       detail=f"{self._label(mac)} told the network it is an IPv6 router. Devices that "
                              f"believe it would send traffic through it instead of the gateway.")

    def on_lsd(self, pkt):
        from scapy.all import IP, UDP, Ether, Raw
        payload = bytes(pkt[UDP].payload) if pkt.haslayer(UDP) else b""
        if not payload.startswith(b"BT-SEARCH"):
            return
        self._count("lsd")
        mac = norm_mac(pkt[Ether].src) if pkt.haslayer(Ether) else None
        ip = pkt[IP].src if pkt.haslayer(IP) else None
        self._emit("torrent_lan", mac, ip,
                   detail=f"{self._label(mac)} is running a torrent client: it announced itself to "
                          f"other torrent clients on the home network (BitTorrent local peer discovery).")

    # ------------------------------------------------------------ manual IPs
    def check_static_ips(self):
        """Devices whose IP didn't come from the Pi's DHCP server."""
        if not self.identity.has_leases():
            return
        today = time.strftime("%Y-%m-%d")
        for d in self.db.query("SELECT device_id, mac, ip FROM devices WHERE mac IS NOT NULL AND ip IS NOT NULL "
                               "AND last_seen>=?", (time.time() - 600,)):
            lease_ip = self.identity.lease_ip(d["mac"])
            if lease_ip == d["ip"] or self._static_alerted.get(d["mac"]) == today:
                continue
            group = self.policy.configured_group(d["device_id"])
            if not self.cfg["groups"][group]["filtered"]:
                continue
            self._static_alerted[d["mac"]] = today
            self._emit("static_ip", d["mac"], d["ip"],
                       detail=f"{self._label(d['mac'])} is using {d['ip']}, which the gateway never gave "
                              f"it" + (f" (its lease is {lease_ip})" if lease_ip else " (no DHCP lease)")
                              + ". It's still filtered by its hardware address.")
