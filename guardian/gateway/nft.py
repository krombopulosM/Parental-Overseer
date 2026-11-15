"""The Raspberry Pi router: nftables ruleset + live set synchronisation.

Packet path for a device on the LAN:

  prerouting  mark by MAC:  0x1 trusted (adults) | 0x2 filtered (kids, unknown) | 0x3 paused
              DNS (any destination, port 53) is redirected to the gateway's resolver
  forward     paused -> rejected
              filtered -> 'filtered' chain:
                 VPN / DoH destination IPs, private ranges (ISP router UI) -> dropped
                 TCP 80/443 -> first N packets go to the inspector (NFQUEUE), then allowed
                 UDP 123 small NTP packets -> allowed
                 UDP (only groups with allow_udp) -> first packets inspected, then allowed
                 everything else -> first packet shown to the inspector for alerting, dropped
              trusted -> allowed
  postrouting masquerade out of the WAN port

Unknown MACs are filtered by default: only devices you mark as adults escape.
"""
from __future__ import annotations

import shutil
import threading
import time

from . import system

TABLE = "guardian"
M_TRUSTED, M_FILTERED, M_PAUSED, M_INSPECT, M_RESET = 0x1, 0x2, 0x3, 0x20, 0xDEAD
PRIVATE_V4 = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16"


def _q(names) -> str:
    return "{ " + ", ".join(f'"{n}"' for n in names) + " }"


class NftGateway:
    def __init__(self, cfg, lists, db, inspector=None):
        self.cfg, self.lists, self.db, self.inspector = cfg, lists, db, inspector
        gw, enf = cfg["gateway"], cfg["enforcement"]
        self.wan = gw["wan_interface"]
        self.lan = list(gw["lan_interfaces"])
        self.lan_ip = gw["lan_ip"]
        self.trusted_ifs = list(gw.get("trusted_interfaces") or [])
        self.ipv6 = bool(gw.get("ipv6"))
        self.web_port = int(cfg["web"]["port"])
        self.dns_port = int(cfg["dns"]["listen_port"])
        self.redirect_port = int(cfg["dns"].get("redirect_port") or self.dns_port)
        self.allow_wan_ssh = bool(gw.get("allow_wan_ssh", True))
        self.fail_open = bool(enf.get("fail_open", False))
        self.inspect_pkts = int(enf.get("inspect_packets", 10))
        self.backend = None
        self._sets: dict[str, frozenset] = {}
        self._admin_open = None
        self._lists_version = -1
        self._lock = threading.Lock()
        self.status = {"applied": False, "error": None}

    # ------------------------------------------------------------ backend
    def _queue_stmt(self) -> str:
        if self.backend == "nft":
            return "queue num 0" + (" bypass" if self.fail_open else "")
        # iptables picks these up in FORWARD and INPUT (the input chain has its own
        # priority, so "accept" here only hands the packet on to iptables)
        return f"meta mark set {M_INSPECT:#x} accept"       # iptables NFQUEUE picks it up

    def detect_backend(self) -> str:
        want = self.cfg["enforcement"].get("queue_backend", "auto")
        if want in ("nft", "xt"):
            return want
        probe = ("table inet guardian_probe {\n chain c {\n  type filter hook forward priority 0; "
                 "policy accept;\n  meta l4proto 253 queue num 31 bypass\n }\n}\n")
        ok = system.nft(probe, check=False).returncode == 0
        system.nft("delete table inet guardian_probe\n", check=False)
        if ok:
            return "nft"
        if shutil.which("iptables"):
            return "xt"
        raise RuntimeError("kernel has no nftables queue support and iptables is missing")

    # ------------------------------------------------------------ ruleset
    def render(self) -> str:
        lan = _q(self.lan)
        q = self._queue_stmt()
        prio = "filter - 10" if self.backend == "xt" else "filter"
        trusted_if = f"iifname {_q(self.trusted_ifs)} " if self.trusted_ifs else ""
        v6_drop = "" if self.ipv6 else "        meta nfproto ipv6 drop\n"
        wan_ssh = f'        iifname "{self.wan}" tcp dport 22 accept\n' if self.allow_wan_ssh else ""
        return f"""
table inet {TABLE} {{
    set trusted_macs {{ type ether_addr; }}
    set paused_macs  {{ type ether_addr; }}
    set udp_ok_macs  {{ type ether_addr; }}
    set admin_macs   {{ type ether_addr; }}
    set vpn_v4 {{ type ipv4_addr; flags interval; auto-merge; }}
    set vpn_v6 {{ type ipv6_addr; flags interval; auto-merge; }}
    set doh_v4 {{ type ipv4_addr; flags interval; auto-merge; }}
    set doh_v6 {{ type ipv6_addr; flags interval; auto-merge; }}
    set dyn_v4 {{ type ipv4_addr; flags timeout; }}
    set dyn_v6 {{ type ipv6_addr; flags timeout; }}

    chain mark_devices {{
        type filter hook prerouting priority mangle; policy accept;
        iifname != {lan} return
        ether saddr @paused_macs meta mark set {M_PAUSED:#x} return
        {trusted_if}ether saddr @trusted_macs meta mark set {M_TRUSTED:#x} return
        meta mark set {M_FILTERED:#x}
    }}

    chain dns_redirect {{
        type nat hook prerouting priority dstnat; policy accept;
        iifname {lan} meta l4proto {{ tcp, udp }} th dport 53 ip daddr != {self.lan_ip} dnat ip to {self.lan_ip}:{self.redirect_port}
        iifname {lan} meta l4proto {{ tcp, udp }} th dport 53 ip daddr {self.lan_ip} th dport != {self.dns_port} dnat ip to {self.lan_ip}:{self.dns_port}
    }}

    chain nat_out {{
        type nat hook postrouting priority srcnat; policy accept;
        oifname "{self.wan}" masquerade
    }}

    chain input {{
        type filter hook input priority {prio}; policy drop;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        meta l4proto {{ icmp, ipv6-icmp }} limit rate 20/second accept
        iifname {lan} meta l4proto {{ tcp, udp }} th dport {{ 53, {self.dns_port}, {self.redirect_port} }} accept
        iifname {lan} udp dport 67 accept
        iifname {lan} tcp dport {{ 22, {self.web_port} }} jump admin_access
        iifname "{self.wan}" udp sport 67 udp dport 68 accept
{wan_ssh}        iifname {lan} meta mark {M_FILTERED:#x} meta l4proto {{ tcp, udp }} ct original packets <= 1 {q}
    }}

    chain admin_access {{
    }}

    chain forward {{
        type filter hook forward priority {prio}; policy drop;
        ct state invalid drop
        meta mark {M_RESET:#x} meta l4proto tcp reject with tcp reset
        meta mark {M_RESET:#x} drop
        iifname {lan} meta mark {M_PAUSED:#x} reject with icmpx admin-prohibited
        iifname {lan} meta mark {M_FILTERED:#x} jump filtered
        ct state established,related accept
{v6_drop}        iifname {lan} meta mark {M_TRUSTED:#x} oifname "{self.wan}" accept
    }}

    chain filtered {{
{v6_drop}        oifname != "{self.wan}" drop
        ip daddr {{ {PRIVATE_V4} }} drop
        ip daddr @vpn_v4 jump bad_dest
        ip6 daddr @vpn_v6 jump bad_dest
        ip daddr @doh_v4 jump bad_dest
        ip6 daddr @doh_v6 jump bad_dest
        ip daddr @dyn_v4 drop
        ip6 daddr @dyn_v6 drop
        tcp dport {{ 80, 443 }} jump web
        udp dport 123 udp length <= 100 accept
        ether saddr @udp_ok_macs meta l4proto udp jump udp_inspect
        icmp type echo-request limit rate 5/second accept
        ct original packets <= 1 {q}
        drop
    }}

    chain bad_dest {{
        ct original packets <= 1 {q}
        drop
    }}

    chain web {{
        ct original packets <= {self.inspect_pkts} {q}
        accept
    }}

    chain udp_inspect {{
        ct original packets <= 3 {q}
        accept
    }}
}}
"""

    def _xt_rules(self, fail_open: bool | None = None) -> list[list[str]]:
        fail_open = self.fail_open if fail_open is None else fail_open
        bypass = ["--queue-bypass"] if fail_open else []
        return [  # listed bottom-up because each is inserted at position 1
            ["-m", "mark", "--mark", hex(M_INSPECT), "-j", "NFQUEUE", "--queue-num", "0", *bypass],
            ["-m", "mark", "--mark", hex(M_RESET), "-j", "DROP"],
            ["-p", "tcp", "-m", "mark", "--mark", hex(M_RESET), "-j", "REJECT", "--reject-with", "tcp-reset"],
        ]

    def _install_xt(self):
        # The fail-open/closed choice can change between runs: never leave the
        # other variant of the queue rule behind (a stale --queue-bypass rule in
        # front would quietly turn a fail-closed gateway into a fail-open one).
        stale = self._xt_rules(not self.fail_open)[0]
        for chain in ("FORWARD", "INPUT"):
            while system.run(["iptables", "-D", chain, *stale], check=False).returncode == 0:
                pass
            for rule in self._xt_rules():
                if system.run(["iptables", "-C", chain, *rule], check=False).returncode != 0:
                    system.run(["iptables", "-I", chain, "1", *rule])

    def _remove_xt(self):
        for chain in ("FORWARD", "INPUT"):
            for rule in self._xt_rules() + self._xt_rules(not self.fail_open)[:1]:
                while system.run(["iptables", "-D", chain, *rule], check=False).returncode == 0:
                    pass

    # ------------------------------------------------------------ lifecycle
    def setup(self):
        system.sysctl("net/netfilter/nf_conntrack_acct", "1")     # per-connection byte counters
        if not self.ipv6:
            system.sysctl("net/ipv6/conf/all/forwarding", "0")
        self.backend = self.detect_backend()
        system.nft(f"table inet {TABLE}\ndelete table inet {TABLE}\n" + self.render())
        if self.backend == "xt":
            self._install_xt()
        self._sets = {}
        self._admin_open = None
        self.sync_ip_sets(force=True)
        if self.db is not None:
            for b in self.db.dyn_blocks():
                self._add_dyn(b["ip"], int(b["expires"] - time.time()))
        # Only start routing once the rules are in place: the Pi boots with
        # forwarding off, so there is never an unfiltered window at startup.
        system.sysctl("net/ipv4/ip_forward", "1")
        self.status = {"applied": True, "error": None, "backend": self.backend,
                       "applied_at": time.time()}

    def teardown(self):
        if not self.cfg["gateway"].get("remove_rules_on_exit"):
            return
        system.nft(f"delete table inet {TABLE}\n", check=False)
        if self.backend == "xt":
            self._remove_xt()

    # ------------------------------------------------------------ set sync
    def _replace_set(self, name: str, elements, chunk: int = 2000) -> str:
        script = f"flush set inet {TABLE} {name}\n"
        elements = list(elements)
        for i in range(0, len(elements), chunk):
            script += f"add element inet {TABLE} {name} {{ {', '.join(elements[i:i + chunk])} }}\n"
        return script

    def sync_device_sets(self, trusted, paused, udp_ok, admin):
        """Push MAC sets; returns the MACs whose state changed (their flows get reset)."""
        want = {"trusted_macs": frozenset(trusted), "paused_macs": frozenset(paused),
                "udp_ok_macs": frozenset(udp_ok), "admin_macs": frozenset(admin)}
        changed_macs = set()
        script = ""
        with self._lock:
            for name, macs in want.items():
                if self._sets.get(name) != macs:
                    old = self._sets.get(name, frozenset())
                    if name != "admin_macs":
                        changed_macs |= old ^ macs
                    script += self._replace_set(name, sorted(macs))
                    self._sets[name] = macs
            admin_open = not want["admin_macs"] or not self.cfg["gateway"].get("admin_only_dashboard", True)
            if admin_open != self._admin_open:
                self._admin_open = admin_open
                script += f"flush chain inet {TABLE} admin_access\n"
                script += (f"add rule inet {TABLE} admin_access accept\n" if admin_open else
                           f"add rule inet {TABLE} admin_access ether saddr @admin_macs accept\n")
            if script:
                system.nft(script)
        return changed_macs

    def sync_ip_sets(self, force=False):
        if not force and self.lists.version == self._lists_version:
            return False
        script = ""
        for lname in ("vpn", "doh"):
            sets = [self.lists.ip_sets.get(n) for n in ((lname, "tor") if lname == "vpn" else (lname,))]
            v4 = sorted({c for s in sets if s for c in s.cidrs(4)})
            v6 = sorted({c for s in sets if s for c in s.cidrs(6)})
            script += self._replace_set(f"{lname}_v4", v4)
            script += self._replace_set(f"{lname}_v6", v6)
        with self._lock:
            system.nft(script)
            self._lists_version = self.lists.version
        return True

    # ------------------------------------------------------------ dynamic blocks
    def _add_dyn(self, ip: str, seconds: int):
        if seconds <= 0:
            return
        fam = "dyn_v6" if ":" in ip else "dyn_v4"
        system.nft(f"add element inet {TABLE} {fam} {{ {ip} timeout {seconds}s }}\n", check=False)
        if self.inspector is not None:
            self.inspector.dyn_blocked.add(ip)

    def block_ip(self, ip: str, seconds: int, reason: str, device_id=None):
        if self.db is not None:
            self.db.add_dyn_block(ip, reason, device_id, time.time() + seconds)
        self._add_dyn(ip, int(seconds))
        system.kill_flows(dst=ip)

    def unblock_ip(self, ip: str):
        if self.db is not None:
            self.db.remove_dyn_block(ip)
        fam = "dyn_v6" if ":" in ip else "dyn_v4"
        system.nft(f"delete element inet {TABLE} {fam} {{ {ip} }}\n", check=False)
        if self.inspector is not None:
            self.inspector.dyn_blocked.discard(ip)

    def kill_device_flows(self, ip: str):
        system.kill_flows(src=ip)
