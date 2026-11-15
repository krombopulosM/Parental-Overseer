"""Who is behind an IP address?

Policies attach to a device's MAC address (stable across DHCP renewals),
falling back to the IP when no MAC is visible (e.g. the local machine).
Hostnames come from the DHCP lease file on the Pi so the dashboard can show
"Emmas-iPhone" instead of a MAC.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time

_WIN_ARP = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\w+")


def norm_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    m = mac.strip().lower().replace("-", ":")
    if m in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or len(m) != 17:
        return None
    if m.startswith("01:00:5e") or m.startswith("33:33"):      # multicast
        return None
    return m


class Identity:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        gw = cfg.get("gateway", {})
        self.lan_ifaces = set(gw.get("lan_interfaces") or [])
        self.gateway_mode = cfg.get("mode") == "gateway"
        self.leases_path = gw.get("dhcp_leases")
        self._arp: dict[str, str] = {}
        self._names: dict[str, str] = {}
        self._lock = threading.Lock()
        self._last_refresh = 0.0
        self._misses: dict[str, float] = {}
        self._lease_by_ip: dict[str, str] = {}
        self._lease_by_mac: dict[str, str] = {}
        # /proc/net/arp is a cheap kernel read, so on Linux re-read it on almost
        # every miss (a new device's first DNS query can beat our last read);
        # Windows has to spawn `arp -a`, so throttle harder there.
        self._min_interval = 0.1 if sys.platform.startswith("linux") else 5.0

    # ---------------------------------------------------------------- refresh
    def refresh(self, force: bool = False):
        now = time.time()
        if not force and now - self._last_refresh < self._min_interval:
            return
        self._last_refresh = now
        arp = self._read_linux_arp() if sys.platform.startswith("linux") else self._read_windows_arp()
        names, lease_by_ip = self._read_leases()
        with self._lock:
            self._arp = arp
            self._names = names
            self._lease_by_ip = lease_by_ip
            self._lease_by_mac = {m: i for i, m in lease_by_ip.items()}

    def _read_linux_arp(self) -> dict:
        out = {}
        try:
            with open("/proc/net/arp", "r") as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) < 6 or parts[2] == "0x0":
                        continue
                    if self.gateway_mode and self.lan_ifaces and parts[5] not in self.lan_ifaces:
                        continue
                    mac = norm_mac(parts[3])
                    if mac:
                        out[parts[0]] = mac
        except OSError:
            pass
        return out

    def _read_windows_arp(self) -> dict:
        out = {}
        try:
            text = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
        except Exception:
            return out
        for line in text.splitlines():
            m = _WIN_ARP.match(line)
            if m:
                mac = norm_mac(m.group(2))
                if mac:
                    out[m.group(1)] = mac
        return out

    def _read_leases(self):
        names, by_ip = {}, {}
        if not self.leases_path or not os.path.exists(self.leases_path):
            return names, by_ip
        now = time.time()
        try:
            with open(self.leases_path, "r") as fh:
                for line in fh:                       # expiry mac ip hostname clientid
                    p = line.split()
                    if len(p) < 4:
                        continue
                    mac = norm_mac(p[1])
                    if not mac:
                        continue
                    if p[0].isdigit() and int(p[0]) and int(p[0]) < now:
                        continue                      # expired lease
                    by_ip[p[2]] = mac
                    if p[3] != "*":
                        names[mac] = p[3]
        except OSError:
            pass
        return names, by_ip

    # ---------------------------------------------------------------- lookups
    def learn(self, ip: str, mac: str | None):
        """Record an IP->MAC pair seen directly on a packet (NFQUEUE gives us this)."""
        mac = norm_mac(mac)
        if mac:
            with self._lock:
                self._arp[ip] = mac

    def mac_for(self, ip: str) -> str | None:
        with self._lock:
            mac = self._arp.get(ip)
        if mac is None:
            # Re-read on a miss, but remember misses per IP for a second so an
            # address that never has a MAC (localhost, the PC itself) can't
            # trigger a read storm.
            now = time.time()
            if now - self._misses.get(ip, 0) > 1.0:
                self._misses[ip] = now
                self.refresh(force=sys.platform.startswith("linux"))
                with self._lock:
                    mac = self._arp.get(ip)
                if mac:
                    self._misses.pop(ip, None)
        return mac

    def hostname_for(self, mac: str | None) -> str | None:
        if not mac:
            return None
        with self._lock:
            return self._names.get(mac)

    def has_leases(self) -> bool:
        return bool(self.leases_path and os.path.exists(self.leases_path))

    def lease_owner(self, ip: str) -> str | None:
        self.refresh()
        with self._lock:
            return self._lease_by_ip.get(ip)

    def lease_ip(self, mac: str) -> str | None:
        self.refresh()
        with self._lock:
            return self._lease_by_mac.get(mac)

    def device_id_for(self, ip: str) -> tuple[str, str | None]:
        mac = self.mac_for(ip)
        return (mac or ip), mac
