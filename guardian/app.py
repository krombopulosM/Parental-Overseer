"""Wires every component together and runs the background loops."""
from __future__ import annotations

import os
import sys
import threading
import time

from .alerts import AlertSink
from .config import resolve_data_path
from .db import DB
from .detector import Detector
from .dnscache import DnsCache
from .identity import Identity
from .inspector import FlowLabels, Inspector
from .lists import ListManager
from .policy import Policy
from .protections import on as prot
from .resolver import DnsTunnelDetector, GuardianResolver, QueryStats, start_dns
from .schedule import Scheduler

def _read_version() -> str:
    try:
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "VERSION")) as fh:
            return fh.read().strip()
    except OSError:
        return "0"


VERSION = _read_version()


class Guardian:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.mode = cfg["mode"]
        self.linux = sys.platform.startswith("linux")
        self.windows = sys.platform.startswith("win")
        if self.mode == "gateway" and not (self.linux or self.windows):
            raise SystemExit("gateway mode runs on Linux (the Raspberry Pi) or Windows. Use mode: monitor here.")
        self.started_at = time.time()
        self.db = DB(resolve_data_path(cfg, cfg["database"]))
        self.alerts = AlertSink(self.db, echo=True)
        self.identity = Identity(cfg)
        self.lists = ListManager(cfg)
        self.lists.load()
        self.policy = Policy(cfg, self.db, self.lists, self.identity, self.alerts)
        self.scheduler = Scheduler(self.db, self.policy)
        self.dnscache = DnsCache(cfg["enforcement"]["consistency_grace"], db=self.db)
        self.dnscache.load()
        self.stats = QueryStats()
        self.tunnel = DnsTunnelDetector(cfg["dns"]["tunnel_detection"], self.alerts)
        self.resolver = GuardianResolver(cfg, self.policy, self.lists, self.dnscache, self.db,
                                         self.alerts, self.scheduler, self.stats, self.tunnel)
        self.lists.resolve_fn = lambda name: self.resolver.lookup(name, "both")
        self.labels = FlowLabels()
        self.inspector = Inspector(cfg, self.policy, self.lists, self.dnscache, self.alerts, self.labels)
        if self.mode != "gateway":                      # watch-only: direct-address check for our DNS users only
            self.inspector.dns_users = lambda ip: self.stats.count(ip, 600) > 0

        self.gateway = self.nfq = None
        if self.mode == "gateway" and self.linux:
            from .gateway.nft import NftGateway
            self.gateway = NftGateway(cfg, self.lists, self.db, self.inspector)
        elif self.mode == "gateway" and self.windows:
            # Windows: WinDivert feeds the same inspector (this PC + its Mobile Hotspot)
            from .gateway.windivert import WindowsGateway
            self.gateway = WindowsGateway(cfg, self.lists, self.db, self.inspector, resolver=self.resolver,
                                          identity=self.identity, policy=self.policy)

        self.monitor = None
        backend = self._flow_backend()
        if backend is not None:
            from .flows.monitor import FlowMonitor
            self.monitor = FlowMonitor(cfg, self.db, self.policy, self.dnscache, self.labels, backend)
        from .downloads import DownloadGuard
        kill = None
        if self.gateway is not None and self.linux:
            from .gateway.system import kill_flow
            kill = kill_flow
        elif self.gateway is not None:
            kill = self.gateway.kill_flow
        self.downloads = DownloadGuard(cfg, self.db, self.lists, self.alerts, kill_flow=kill)
        self.downloads.categories_for = lambda dev, grp: self.policy.categories_for(dev, grp)
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
        if self.mode == "gateway" and self.linux and (cfg.get("tamper") or {}).get("enabled", True):
            from .lanwatch import LanWatch
            self.lanwatch = LanWatch(cfg, self.db, self.policy, self.identity, self.alerts,
                                     on_change=self.device_changed)
        from .updater import Updater
        self.updater = Updater(cfg, self.db, self.alerts)
        self.mdns = None
        if self.mode == "gateway" and self.linux:
            from .localname import MdnsPublisher
            self.mdns = MdnsPublisher(cfg)
        self.alerts.listeners.append(self._auto_pause)
        self.alerts.listeners.append(self._escalate)
        self._attempts: dict[str, list] = {}
        self._escalated: dict[str, float] = {}
        self.refresh_allowlist()

    def _flow_backend(self):
        if self.mode == "gateway" and sys.platform.startswith("linux"):
            from .flows.conntrack import ConntrackBackend
            if ConntrackBackend.available():
                return ConntrackBackend(self.cfg)
            print("[flows] conntrack tool missing (apt install conntrack): no byte accounting")
            return None
        from .flows.sniffer import SnifferBackend
        if SnifferBackend.available():
            return SnifferBackend(self.cfg, self.labels,
                                  observer=self.inspector.observe if self.mode != "gateway" else None)
        return None

    # ------------------------------------------------------------ lifecycle
    def start(self, download_lists: bool = True, queue_num: int = 0, takeover: bool = False):
        """Start serving. With takeover=True another version of this program is still
        running (an update): we share its ports, take over packet inspection in one
        atomic firewall switch, and take over the once-only jobs when it exits."""
        self.takeover = takeover
        self.queue_num = queue_num
        if takeover:
            self.inspector.handover_until = time.time() + 20
        d = self.cfg["dns"]
        self.dns_servers = start_dns(self.resolver, d["listen_host"], int(d["listen_port"]))
        print(f"[dns] listening on {d['listen_host']}:{d['listen_port']} -> {', '.join(d['upstreams'])}")
        if self.mode == "gateway" and d.get("redirect_port"):
            self.dns_servers += start_dns(self.resolver, d["listen_host"], int(d["redirect_port"]))
        if self.gateway is not None and self.windows:
            self.gateway.setup(devices=self._device_sets())
            st = self.gateway.status
            print(f"[gateway] Windows packet filter active (WinDivert: {', '.join(st.get('handles') or [])}; "
                  f"hotspot {'on' if st.get('hotspot') else 'off'})")
        elif self.gateway is not None:
            from .gateway.nfq import NfqRunner
            self.nfq = NfqRunner(self.inspector, queue_num, self.cfg["enforcement"].get("fail_open", False))
            if not self.nfq.bind():                    # bind first: nothing is sent to it yet
                raise RuntimeError(self.nfq.error or "packet queue unavailable")
            self.nfq.start()
            self.gateway.queue_num = queue_num
            self.gateway.setup(devices=self._device_sets())   # one atomic switch-over
            print(f"[gateway] firewall active ({self.gateway.backend} queue backend, queue {queue_num})")
        from .config import data_dir
        from .handover import Leader
        self.leader = Leader(os.path.join(data_dir(self.cfg), "leader.lock"))
        self._download_lists = download_lists
        self.leader.acquire_then(self._lead)
        if not self.leader.is_leader:
            print("[handover] serving alongside the previous version; taking over its jobs when it exits")

    def _lead(self):
        """The once-only jobs. Runs at start-up, or - during an update - the moment
        the previous version exits."""
        self.leading_since = time.time()
        if self.takeover:
            print("[handover] previous version has exited - taking over")
            self.policy.reload()
            self.scheduler.reload()
            self.refresh_allowlist()
            self.dnscache.load()
            if self.gateway is not None:
                self.sync_gateway(force=True)
        self._check_offline_gap()
        if self._download_lists:
            self.lists.start_background()
        if self.monitor is not None:
            n = self.monitor.resume_from_db()
            self.monitor.start()
            print(f"[flows] monitoring via {self.monitor.backend.name}" + (f" (resumed {n} connections)" if n else ""))
        else:
            print("[flows] traffic accounting disabled (no capture backend available)")
        if self.detector is not None:
            self.detector.start()
        if self.lanwatch is not None:
            self.lanwatch.start()
            print(f"[lanwatch] watching {', '.join(self.lanwatch.ifaces)} for tampering")
        if self.mdns is not None:
            self.mdns.sync()
            st = self.mdns.status()
            print(f"[mdns] {'announcing ' + st['name'] if st['running'] else 'not announcing: ' + str(st['error'])}")
        if getattr(self, "updater", None) is not None:
            self.updater.start()
        threading.Thread(target=self._housekeeping, name="housekeeping", daemon=True).start()

    def ready(self) -> bool:
        """Serving DNS, and (on the Pi) inspecting packets behind a loaded firewall."""
        ok = bool(getattr(self, "dns_servers", None))
        if self.gateway is not None:
            running = self.nfq.running if self.nfq is not None else getattr(self.gateway, "running", False)
            ok = ok and self.gateway.status.get("applied") and running
        return bool(ok)

    def shutdown(self, handover: bool):
        """handover=True: a newer process has taken over - stop answering, finish the
        packets already queued to us, leave the firewall alone. handover=False: the
        service is being stopped."""
        if handover:
            # New lookups and packets already go to the new process; keep answering
            # what's queued to us (DNS sockets, the packet queue) for a moment.
            time.sleep(2.0 if self.nfq is not None else 1.0)
        for s in getattr(self, "dns_servers", []):
            try:
                s.server.server_close()
            except Exception:
                pass
        if self.mdns is not None:
            self.mdns.stop()
        if not handover and self.gateway is not None:
            self.gateway.teardown()
        try:
            self.db.flush(timeout=3)
        except Exception:
            pass

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
        self.shutdown(handover=False)
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
                if self.mdns is not None:
                    self.mdns.sync()                 # restarts the announcement if Avahi restarted
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

    def _device_sets(self) -> dict:
        s = self._compute_sets()
        return {"trusted": s[0], "paused": s[1], "udp_ok": s[2], "admin": s[3], "open": s[4]}

    def sync_gateway(self, force: bool = False):
        """Mirror device groups, pauses and lists into the firewall's sets."""
        if self.gateway is None:
            return
        trusted, paused, udp_ok, admin, open_, ip_of = self._compute_sets(with_ips=True)
        changed = self.gateway.sync_device_sets(trusted, paused, udp_ok, admin, open_, force=force)
        for mac in changed:
            if ip_of.get(mac):
                self.gateway.kill_device_flows(ip_of[mac])
        self.gateway.sync_ip_sets(force=force)

    def _compute_sets(self, with_ips: bool = False):
        trusted, paused, udp_ok, admin, open_ = set(), set(), set(), set(), set()
        admin_groups = set(self.cfg["gateway"].get("admin_groups") or [])
        ip_of = {}
        for d in self.db.list_devices():
            mac = d.get("mac")
            if not mac:
                continue
            ip_of[mac] = d.get("ip")
            g = self.policy.group_name(d["device_id"])
            gc = self.cfg["groups"][g]
            non_web = prot(self.cfg, gc, "non_web")
            if not gc["filtered"]:
                trusted.add(mac)
            elif non_web == "games":
                udp_ok.add(mac)
            elif non_web == "allow":
                open_.add(mac)
            # Dashboard reachability follows the *configured* group: a parent whose
            # identity is in quarantine must still reach the dashboard to click
            # "It's me" (the password still protects it).
            if self.policy.configured_group(d["device_id"]) in admin_groups:
                admin.add(mac)
            if self.scheduler.is_paused(d["device_id"], g)[0]:
                paused.add(mac)
        if with_ips:
            return trusted, paused, udp_ok, admin, open_, ip_of
        return trusted, paused, udp_ok, admin, open_

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
        if self.mdns is not None:
            self.mdns.sync()
        self.device_changed()

    def restart(self, delay: float = 1.0):
        """Restart the whole service so settings that need it (ports, dashboard
        access) take effect. Under systemd we simply exit and systemd starts us
        again; otherwise the process replaces itself with a fresh copy."""
        import os

        from . import supervisor
        if supervisor.under_supervisor():
            # Seamless: a fresh copy of this version takes over, as for an update.
            supervisor.request_switch(self.cfg, os.environ.get("GUARDIAN_RELEASE_DIR"), "restart")
            return

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
        if self.mdns is not None:
            s["mdns"] = self.mdns.status()
        if self.lanwatch is not None:
            s["lanwatch"] = {"running": self.lanwatch.running, "error": self.lanwatch.error,
                             "seen": dict(self.lanwatch.counters), "pinned": list(self.lanwatch.pins)}
        if self.gateway is not None:
            s["gateway"] = dict(self.gateway.status)
            if self.nfq is not None:
                s["gateway"].update(nfq_running=self.nfq.running, nfq_handled=self.nfq.handled,
                                    nfq_errors=self.nfq.errors)
            elif hasattr(self.gateway, "stats"):          # Windows: same fields, from WinDivert
                st = self.gateway.stats
                s["gateway"].update(nfq_running=self.gateway.running, nfq_handled=st.get("packets", 0),
                                    nfq_errors=st.get("errors", 0), windivert=dict(st),
                                    hotspot_devices=sorted(self.gateway.seen_hotspot_clients))
        return s
