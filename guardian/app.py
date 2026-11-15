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
        from .downloads import DownloadGuard
        kill = None
        if self.gateway is not None:
            from .gateway.system import kill_flow
            kill = kill_flow
        self.downloads = DownloadGuard(cfg, self.db, self.lists, self.alerts, kill_flow=kill)
        from .adult import AdultGuard
        self.adult = AdultGuard(cfg, self.lists, self.alerts)
        self.downloads.adult = self.adult
        self.inspector.adult = self.adult
        self.resolver.adult = self.adult
        from .reputation import Reputation
        self.reputation = Reputation(cfg, self.db, self.lists, guard=self.downloads)
        self.inspector.reputation = self.reputation
        self.downloads.reputation = self.reputation
        self.resolver.reputation = self.reputation
        self.inspector.downloads = self.downloads
        if self.monitor is not None:
            self.monitor.downloads = self.downloads
        self.detector = None
        if self.monitor is not None and cfg["detector"].get("enabled", True):
            self.detector = Detector(cfg, self.db, self.monitor, self.stats, self.lists,
                                     self.alerts, self.gateway, reputation=self.reputation)
        self.errors: dict[str, str] = {}
        self.lanwatch = None
        if self.mode == "gateway" and (cfg.get("tamper") or {}).get("enabled", True):
            from .lanwatch import LanWatch
            self.lanwatch = LanWatch(cfg, self.db, self.policy, self.identity, self.alerts,
                                     on_change=self.device_changed)
        self.alerts.listeners.append(self._auto_pause)
        self.alerts.listeners.append(self._escalate)
        self._attempts: dict[str, list] = {}
        self._escalated: dict[str, float] = {}
        self.refresh_allowlist()

    def _flow_backend(self):
        if self.mode == "gateway":
            from .flows.conntrack import ConntrackBackend
            if ConntrackBackend.available():
                return ConntrackBackend(self.cfg)
            print("[flows] conntrack tool missing (apt install conntrack): no byte accounting")
            return None
        from .flows.sniffer import SnifferBackend
        if SnifferBackend.available():
            return SnifferBackend(self.cfg, self.labels, observer=self.inspector.observe)
        return None

    # ------------------------------------------------------------ lifecycle
    def start(self, download_lists: bool = True):
        self._check_offline_gap()
        d = self.cfg["dns"]
        self.dns_servers = start_dns(self.resolver, d["listen_host"], int(d["listen_port"]))
        print(f"[dns] listening on {d['listen_host']}:{d['listen_port']} -> {', '.join(d['upstreams'])}")
        if self.mode == "gateway" and d.get("redirect_port"):
            self.dns_servers += start_dns(self.resolver, d["listen_host"], int(d["redirect_port"]))
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
        if self.lanwatch is not None:
            self.lanwatch.start()
            print(f"[lanwatch] watching {', '.join(self.lanwatch.ifaces)} for tampering")
        threading.Thread(target=self._housekeeping, name="housekeeping", daemon=True).start()

    # ------------------------------------------------------------ defences
    def refresh_allowlist(self):
        """Destinations a parent marked 'not a bypass' skip the inspector's checks."""
        rows = self.db.allowlist()
        self.inspector.allow_ips = {r["value"] for r in rows if r["kind"] == "ip"}
        self.alerts.scorer.reload()
        if self.detector is not None:
            self.detector.reload_allowlist()

    def _auto_pause(self, alert):
        """Pause a filtered device caught attacking the network itself."""
        tm = self.cfg.get("tamper") or {}
        minutes = float(tm.get("auto_pause_minutes", 0) or 0)
        did = alert.get("device_id")
        if not minutes or not did or alert["kind"] not in (tm.get("auto_pause_kinds") or []):
            return
        if (alert.get("confidence") or 0) < int(tm.get("auto_pause_confidence", 85)):
            return
        if not self.cfg["groups"][self.policy.configured_group(did)]["filtered"]:
            return                                   # never cut off an adult's device automatically
        if self.db.get_device(did) is None:
            self.db.update_device(did)
        self.scheduler.pause(did, minutes)
        self.db.execute("UPDATE alerts SET action=? WHERE id=(SELECT MAX(id) FROM alerts WHERE device_id=? "
                        "AND kind=?)", (f"device paused for {int(minutes)} min", did, alert["kind"]))
        self.device_changed()

    _ESCALATION_CATEGORIES = ("vpn", "dns", "disguise", "torrent")

    def _escalate(self, alert):
        """One blocked attempt is an app; technique after technique is a person
        working through a bypass tool. Name the tool and pause the device."""
        from .confidence import kind_category
        esc = self.cfg.get("escalation") or {}
        did = alert.get("device_id")
        if not did or alert["kind"] == "bypass_tool" or kind_category(alert["kind"]) not in self._ESCALATION_CATEGORIES:
            return
        if (alert.get("confidence") or 0) < int(esc.get("min_confidence", 70)):
            return
        now = time.time()
        window = float(esc.get("window", 600))
        hist = [(t, k) for t, k in self._attempts.get(did, []) if now - t < window] + [(now, alert["kind"])]
        self._attempts[did] = hist[-200:]
        kinds = sorted({k for _, k in hist})
        if len(kinds) < int(esc.get("min_techniques", 3)) or now - self._escalated.get(did, 0) < 1800:
            return
        self._escalated[did] = now
        if "tor" in kinds:
            tool = "Tor Browser (or another Tor-based app)"
        elif any(k in kinds for k in ("vpn_server", "blocked_udp", "vpn_fingerprint", "tunnel_behaviour",
                                      "protocol_violation", "no_sni", "sni_mismatch")):
            tool = "a VPN or proxy app"
        else:
            tool = "a bypass tool"
        minutes = float(esc.get("pause_minutes", 0) or 0)
        filtered = self.cfg["groups"][self.policy.configured_group(did)]["filtered"]
        action = "detected"
        if minutes and filtered:
            if self.db.get_device(did) is None:
                self.db.update_device(did)
            self.scheduler.pause(did, minutes)
            self.device_changed()
            action = f"device paused for {int(minutes)} min"
        self.alerts.emit("bypass_tool", device_id=did, client_ip=alert.get("client_ip"), action=action,
                         detail=f"{tool} appears to be running: {len(kinds)} different techniques tried within "
                                f"{int(window // 60)} minutes ({', '.join(kinds)}). Every attempt was blocked.")

    def _check_offline_gap(self):
        hb = self.db.get_meta("heartbeat")
        limit = float((self.cfg.get("tamper") or {}).get("offline_alert_minutes", 5)) * 60
        now = time.time()
        if hb and now - float(hb) > limit:
            start = float(hb)
            fmt = "%a %H:%M"
            self.alerts.emit("gateway_offline", detail=(
                f"The gateway was not running from {time.strftime(fmt, time.localtime(start))} to "
                f"{time.strftime(fmt, time.localtime(now))} ({(now - start) / 60:.0f} min). A power cut or "
                f"reboot does this - so does someone unplugging it."), action="noted")
        self.db.set_meta("heartbeat", str(now))

    def stop(self):
        if self.gateway is not None:
            self.gateway.teardown()
        self.db.close()

    def _housekeeping(self):
        last_prune = 0.0
        while True:
            time.sleep(15)
            try:
                self.db.set_meta("heartbeat", str(time.time()))
                self.scheduler.reload()
                if self.gateway is not None:
                    self.sync_gateway()
                if self.lanwatch is not None:
                    self.lanwatch.expire_pins()
                    self.lanwatch.check_static_ips()
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
            # Dashboard reachability follows the *configured* group: a parent whose
            # identity is in quarantine must still reach the dashboard to click
            # "It's me" (the password still protects it).
            if self.policy.configured_group(d["device_id"]) in admin_groups:
                admin.add(mac)
            if self.scheduler.is_paused(d["device_id"], g)[0]:
                paused.add(mac)
        changed = self.gateway.sync_device_sets(trusted, paused, udp_ok, admin)
        for mac in changed:
            if ip_of.get(mac):
                self.gateway.kill_device_flows(ip_of[mac])
        self.gateway.sync_ip_sets()

    def reconfigure(self):
        """Apply changed settings (setup wizard) to the running components.
        The config dict was updated in place; components that copied values out
        of it at start-up re-read them here."""
        from .adult import AdultGuard
        self.adult = AdultGuard(self.cfg, self.lists, self.alerts)
        self.resolver.adult = self.inspector.adult = self.downloads.adult = self.adult
        self.downloads.refresh_settings()
        self.reputation.refresh_settings()
        if self.monitor is not None:
            self.monitor.log_trusted = bool(self.cfg["flows"].get("log_trusted_devices", True))
        self.device_changed()

    def restart(self, delay: float = 1.0):
        """Restart the whole service so settings that need it (ports, dashboard
        access) take effect. Under systemd we simply exit and systemd starts us
        again; otherwise the process replaces itself with a fresh copy."""
        import os

        def go():
            time.sleep(delay)
            print("[restart] restarting to apply new settings")
            try:
                self.db.close()
            except Exception:
                pass
            if os.environ.get("INVOCATION_ID"):          # running under systemd
                os._exit(0)
            # Close everything first: some handles (the kernel packet queue, made by a
            # C library) would otherwise survive exec and block the new process.
            sys.stdout.flush()
            sys.stderr.flush()
            try:
                maxfd = os.sysconf("SC_OPEN_MAX")
            except (AttributeError, ValueError, OSError):
                maxfd = 4096
            os.closerange(3, maxfd)
            os.execv(sys.executable, [sys.executable] + sys.argv)

        threading.Thread(target=go, name="restart", daemon=True).start()

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
        if self.lanwatch is not None:
            s["lanwatch"] = {"running": self.lanwatch.running, "error": self.lanwatch.error,
                             "seen": dict(self.lanwatch.counters), "pinned": list(self.lanwatch.pins)}
        if self.gateway is not None:
            s["gateway"] = dict(self.gateway.status)
            if self.nfq is not None:
                s["gateway"].update(nfq_running=self.nfq.running, nfq_handled=self.nfq.handled,
                                    nfq_errors=self.nfq.errors)
        return s
