"""Wires every component together and runs the background loops."""
from __future__ import annotations

import sys
import threading
import time

from .alerts import AlertSink
from .config import resolve_path
from .db import DB
from .detector import Detector
from .dnscache import DnsCache
from .identity import Identity
from .inspector import FlowLabels, Inspector
from .lists import ListManager
from .policy import Policy
from .resolver import DnsTunnelDetector, GuardianResolver, QueryStats, start_dns
from .schedule import Scheduler

VERSION = "2.0"


class Guardian:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.mode = cfg["mode"]
        if self.mode == "gateway" and not sys.platform.startswith("linux"):
            raise SystemExit("gateway mode needs Linux (the Raspberry Pi). Use mode: monitor on this machine.")
        self.started_at = time.time()
        self.db = DB(resolve_path(cfg, cfg["database"]))
        self.alerts = AlertSink(self.db, echo=True)
        self.identity = Identity(cfg)
        self.lists = ListManager(cfg)
        self.lists.load()
        self.policy = Policy(cfg, self.db, self.lists, self.identity, self.alerts)
        self.scheduler = Scheduler(self.db, self.policy)
        self.dnscache = DnsCache(cfg["enforcement"]["consistency_grace"])
        self.stats = QueryStats()
        self.tunnel = DnsTunnelDetector(cfg["dns"]["tunnel_detection"], self.alerts)
        self.resolver = GuardianResolver(cfg, self.policy, self.lists, self.dnscache, self.db,
                                         self.alerts, self.scheduler, self.stats, self.tunnel)
        self.lists.resolve_fn = lambda name: self.resolver.lookup(name, "both")
        self.labels = FlowLabels()
        self.inspector = Inspector(cfg, self.policy, self.lists, self.dnscache, self.alerts, self.labels)

        self.gateway = self.nfq = None
        if self.mode == "gateway":
            from .gateway.nft import NftGateway
            self.gateway = NftGateway(cfg, self.lists, self.db, self.inspector)

        self.monitor = None
        backend = self._flow_backend()
        if backend is not None:
            from .flows.monitor import FlowMonitor
            self.monitor = FlowMonitor(cfg, self.db, self.policy, self.dnscache, self.labels, backend)
        self.detector = None
        if self.monitor is not None and cfg["detector"].get("enabled", True):
            self.detector = Detector(cfg, self.db, self.monitor, self.stats, self.lists,
                                     self.alerts, self.gateway)
        self.errors: dict[str, str] = {}

    def _flow_backend(self):
        if self.mode == "gateway":
            from .flows.conntrack import ConntrackBackend
            if ConntrackBackend.available():
                return ConntrackBackend(self.cfg)
            print("[flows] conntrack tool missing (apt install conntrack): no byte accounting")
            return None
        from .flows.sniffer import SnifferBackend
        if SnifferBackend.available():
            return SnifferBackend(self.cfg, self.labels)
        return None

    # ------------------------------------------------------------ lifecycle
    def start(self, download_lists: bool = True):
        d = self.cfg["dns"]
        self.dns_servers = start_dns(self.resolver, d["listen_host"], int(d["listen_port"]))
        print(f"[dns] listening on {d['listen_host']}:{d['listen_port']} -> {', '.join(d['upstreams'])}")
        if self.gateway is not None:
            from .gateway.nfq import NfqRunner
            self.gateway.setup()
            self.sync_gateway()
            self.nfq = NfqRunner(self.inspector, 0, self.cfg["enforcement"].get("fail_open", False))
            self.nfq.start()
            print(f"[gateway] firewall active ({self.gateway.backend} queue backend)")
        if download_lists:
            self.lists.start_background()
        if self.monitor is not None:
            self.monitor.start()
            print(f"[flows] monitoring via {self.monitor.backend.name}")
        else:
            print("[flows] traffic accounting disabled (no capture backend available)")
        if self.detector is not None:
            self.detector.start()
        threading.Thread(target=self._housekeeping, name="housekeeping", daemon=True).start()

    def stop(self):
        if self.gateway is not None:
            self.gateway.teardown()
        self.db.close()

    def _housekeeping(self):
        last_prune = 0.0
        while True:
            time.sleep(15)
            try:
                self.scheduler.reload()
                if self.gateway is not None:
                    self.sync_gateway()
                self.dnscache.prune()
                if time.time() - last_prune > 3600:
                    self.db.prune(self.cfg.get("retention_days", 30))
                    last_prune = time.time()
                self.errors.pop("housekeeping", None)
            except Exception as e:
                self.errors["housekeeping"] = str(e)
                print(f"[housekeeping] {e}")

    def sync_gateway(self):
        """Mirror device groups, pauses and lists into the firewall's sets."""
        if self.gateway is None:
            return
        trusted, paused, udp_ok, admin = set(), set(), set(), set()
        admin_groups = set(self.cfg["gateway"].get("admin_groups") or [])
        ip_of = {}
        for d in self.db.list_devices():
            mac = d.get("mac")
            if not mac:
                continue
            ip_of[mac] = d.get("ip")
            g = self.policy.group_name(d["device_id"])
            gc = self.cfg["groups"][g]
            if not gc["filtered"]:
                trusted.add(mac)
            elif gc.get("allow_udp"):
                udp_ok.add(mac)
            if g in admin_groups:
                admin.add(mac)
            if self.scheduler.is_paused(d["device_id"], g)[0]:
                paused.add(mac)
        changed = self.gateway.sync_device_sets(trusted, paused, udp_ok, admin)
        for mac in changed:
            if ip_of.get(mac):
                self.gateway.kill_device_flows(ip_of[mac])
        self.gateway.sync_ip_sets()

    def device_changed(self):
        self.policy.reload()
        self.scheduler.reload()
        if self.gateway is not None:
            self.sync_gateway()

    # ------------------------------------------------------------ status
    def status(self) -> dict:
        s = {
            "version": VERSION, "mode": self.mode, "uptime": time.time() - self.started_at,
            "dns": {"queries": self.resolver.counters["queries"], "blocked": self.resolver.counters["blocked"],
                    "https_stripped": self.resolver.counters["https_stripped"],
                    "remembered_answers": len(self.dnscache)},
            "lists": {"status": self.lists.status, "updating": self.lists.updating,
                      "last_update": self.lists.last_update},
            "inspector": dict(self.inspector.stats),
            "monitor": None, "detector": None, "gateway": None, "errors": self.errors,
        }
        if self.monitor is not None:
            s["monitor"] = {"backend": self.monitor.backend.name, "active_flows": len(self.monitor.active),
                            "last_tick": self.monitor.last_tick,
                            "error": self.monitor.error or getattr(self.monitor.backend, "error", None)}
        if self.detector is not None:
            s["detector"] = {"last_run": self.detector.last_run, "recent": self.detector.flagged[-10:]}
        if self.gateway is not None:
            s["gateway"] = dict(self.gateway.status)
            if self.nfq is not None:
                s["gateway"].update(nfq_running=self.nfq.running, nfq_handled=self.nfq.handled,
                                    nfq_errors=self.nfq.errors)
        return s
