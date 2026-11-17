"""Turns raw per-connection counters into what a parent wants to know:
which device, which site/service, how long, how much data - and, from the
shape of the traffic, what the device is probably *doing* right now.

"How long" is measured as *active minutes*: a minute counts towards a service
if the device moved at least `active_minute_bytes` with it in that minute.
That avoids the trap of adding up overlapping connections (a YouTube tab holds
many) or counting an idle background socket as hours of use.

Every tick (2 s by default) each connection's byte/packet deltas are kept for
a minute, classified (activity.py), rolled up into a per-device headline and a
live per-activity throughput series for the dashboard graph.
"""
from __future__ import annotations

import collections
import threading
import time

from ..activity import CLASSES, classify_flow, features, summarize
from ..services import service_for

LIVE_SECONDS = 300


class FlowRec:
    __slots__ = ("tuple", "flow_key", "device_id", "client_ip", "proto", "dst_ip", "dst_port",
                 "domain", "domain_src", "service", "ja4", "verdict", "reason", "start", "last",
                 "bytes_up", "bytes_down", "pkts_up", "pkts_down", "ended", "window", "flagged",
                 "filtered", "group", "dirty", "ticks", "activity", "dl_state", "unk_state")

    def __init__(self, sample, ctx, now):
        proto, client, sport, dst, dport = sample.tuple
        self.tuple = sample.tuple
        self.flow_key = f"{sample.key}|{int(now)}"
        self.device_id, self.client_ip = ctx.device_id, client
        self.proto, self.dst_ip, self.dst_port = proto, dst, dport
        self.domain = self.domain_src = self.service = self.ja4 = None
        self.verdict = self.reason = None
        self.start = self.last = now
        self.bytes_up = self.bytes_down = self.pkts_up = self.pkts_down = 0
        self.ended = 0
        self.window: collections.deque = collections.deque()
        self.ticks: collections.deque = collections.deque()
        self.flagged = False
        self.filtered = ctx.filtered
        self.group = ctx.group
        self.dirty = True
        self.activity = None
        self.dl_state = None
        self.unk_state = None

    @property
    def total(self):
        return self.bytes_up + self.bytes_down

    @property
    def duration(self):
        return self.last - self.start

    def window_bytes(self, now, window):
        cutoff = now - window
        while self.window and self.window[0][0] < cutoff:
            self.window.popleft()
        return sum(b for _, b in self.window)

    def row(self):
        return {k: getattr(self, k) for k in (
            "flow_key", "device_id", "client_ip", "proto", "dst_ip", "dst_port", "domain",
            "domain_src", "service", "ja4", "verdict", "reason", "start", "last", "ended",
            "bytes_up", "bytes_down", "pkts_up", "pkts_down")}


class FlowMonitor:
    def __init__(self, cfg, db, policy, dnscache, labels, backend):
        f = cfg["flows"]
        self.cfg = cfg
        self.poll = float(f.get("poll_interval", 2))
        self.log_trusted = bool(f.get("log_trusted_devices", True))
        self.db, self.policy, self.dnscache, self.labels, self.backend = db, policy, dnscache, labels, backend
        self.downloads = None                 # DownloadGuard, wired by the app
        self.active: dict[str, FlowRec] = {}
        self._skip: set[str] = set()
        self._usage = collections.defaultdict(lambda: [0, 0])
        self.live: dict[str, collections.deque] = {}      # device -> deque[(ts, {class: bytes/s})]
        self.now: dict[str, dict] = {}                     # device -> activity summary
        self.lock = threading.Lock()
        self.last_tick = 0.0
        self.error = None
        self._resume: dict[str, dict] = {}

    def resume_from_db(self, max_age: float = 600) -> int:
        """Pick up the byte counters the previous process last saved for connections
        that are still open, so they aren't counted twice after a restart/update."""
        if self.db is None:
            return 0
        import time as _t
        rows = self.db.query("SELECT flow_key, start, bytes_up, bytes_down, pkts_up, pkts_down FROM flows "
                             "WHERE ended=0 AND last>=?", (_t.time() - max_age,))
        for r in rows:
            key = r["flow_key"].rsplit("|", 1)[0]
            self._resume[key] = dict(r)
        return len(rows)

    def start(self):
        self.backend.start()

        def loop():
            while True:
                try:
                    self.tick()
                    self.error = None
                except Exception as e:
                    self.error = str(e)
                    print(f"[flows] tick failed: {e}")
                time.sleep(self.poll)
        threading.Thread(target=loop, name="flows", daemon=True).start()

    def tick(self, now: float | None = None):
        self.ingest(self.backend.snapshot(), now or time.time())

    def _label(self, rec: FlowRec):
        lab = self.labels.get(rec.tuple)
        if lab:
            if lab.get("domain") and not rec.domain:
                rec.domain, rec.domain_src, rec.dirty = lab["domain"], lab.get("domain_src"), True
            if lab.get("ja4") and not rec.ja4:
                rec.ja4, rec.dirty = lab["ja4"], True
            if lab.get("verdict") and rec.verdict != lab["verdict"]:
                rec.verdict, rec.reason, rec.dirty = lab["verdict"], lab.get("reason"), True
        if not rec.domain:
            name = self.dnscache.best_name(rec.client_ip, rec.dst_ip)
            if name:
                rec.domain, rec.domain_src, rec.dirty = name, "dns", True
        svc = service_for(rec.domain) if rec.domain else f"ip:{rec.dst_ip}"
        if svc != rec.service:
            rec.service, rec.dirty = svc, True

    def ingest(self, samples, now: float):
        seen = set()
        minute = int(now // 60)
        dt = min(30.0, max(0.5, now - self.last_tick)) if self.last_tick else self.poll
        guard_calls = []
        with self.lock:
            for s in samples:
                seen.add(s.key)
                if s.key in self._skip:
                    continue
                rec = self.active.get(s.key)
                if rec is None:
                    ctx = self.policy.context(s.tuple[1])
                    if not ctx.filtered and not self.log_trusted:
                        self._skip.add(s.key)
                        continue
                    rec = self.active[s.key] = FlowRec(s, ctx, now)
                    prev = self._resume.pop(s.key, None)
                    if prev is not None:
                        rec.flow_key, rec.start = prev["flow_key"], prev["start"]
                        rec.bytes_up, rec.bytes_down = prev["bytes_up"], prev["bytes_down"]
                        rec.pkts_up, rec.pkts_down = prev["pkts_up"], prev["pkts_down"]
                d_up = s.bytes_up - rec.bytes_up if s.bytes_up >= rec.bytes_up else s.bytes_up
                d_dn = s.bytes_down - rec.bytes_down if s.bytes_down >= rec.bytes_down else s.bytes_down
                p_up = s.pkts_up - rec.pkts_up if s.pkts_up >= rec.pkts_up else s.pkts_up
                p_dn = s.pkts_down - rec.pkts_down if s.pkts_down >= rec.pkts_down else s.pkts_down
                rec.bytes_up, rec.bytes_down = s.bytes_up, s.bytes_down
                rec.pkts_up, rec.pkts_down = s.pkts_up, s.pkts_down
                self._label(rec)
                rec.ticks.append((now, dt, d_up, d_dn, p_up, p_dn))
                while rec.ticks and rec.ticks[0][0] < now - 60:
                    rec.ticks.popleft()
                if d_up or d_dn:
                    rec.last = now
                    rec.window.append((now, d_up + d_dn))
                    rec.dirty = True
                    u = self._usage[(rec.device_id, rec.service, minute)]
                    u[0] += d_up
                    u[1] += d_dn
                if rec.dirty and self.db is not None:
                    self.db.upsert_flow(rec.row())
                    rec.dirty = False
            for key in [k for k in self.active if k not in seen]:
                rec = self.active.pop(key)
                rec.ended = 1
                if self.db is not None:
                    self.db.upsert_flow(rec.row())
            self._skip &= seen
            usage, self._usage = self._usage, collections.defaultdict(lambda: [0, 0])

            # ---- activity: classify each connection, roll up per device
            per_device: dict[str, list] = {}
            rates: dict[str, dict] = {}
            for rec in self.active.values():
                f = features(rec.ticks, now)
                act = classify_flow(rec.proto, rec.service, f)
                rec.activity = act
                per_device.setdefault(rec.device_id, []).append((act, rec.service, f.total, rec.domain))
                last = rec.ticks[-1] if rec.ticks and rec.ticks[-1][0] == now else None
                if last and (last[2] or last[3]):
                    cls = act.cls if act else "other"
                    r = rates.setdefault(rec.device_id, {})
                    r[cls] = r.get(cls, 0) + (last[2] + last[3]) / dt
                if self.downloads is not None and rec.filtered:
                    guard_calls.append((rec, act, f))
            for dev in set(self.live) | set(per_device) | set(rates):
                dq = self.live.setdefault(dev, collections.deque())
                dq.append((now, rates.get(dev, {})))
                while dq and dq[0][0] < now - LIVE_SECONDS:
                    dq.popleft()
                if not any(v for _, r in dq for v in r.values()) and dev not in per_device:
                    del self.live[dev]
                    self.now.pop(dev, None)
            for dev, flows in per_device.items():
                summ = summarize(flows)
                summ["ts"] = now
                self.now[dev] = summ
                if summ["activity"] != "idle" and self.db is not None:
                    self.db.set_activity(dev, minute, summ["activity"], summ["headline"], summ["confidence"])

        for rec, act, f in guard_calls:
            try:
                gcfg = self.cfg["groups"].get(rec.group)
                if act is not None:
                    self.downloads.on_flow(rec, act, f, gcfg)
                self.downloads.on_unknown(rec, act, f, gcfg)
            except Exception as e:
                print(f"[downloads] {e}")
        if self.db is not None:
            for (dev, svc, m), (up, dn) in usage.items():
                self.db.add_usage(dev, svc, m, up, dn)
        self.last_tick = now

    def active_flows(self):
        with self.lock:
            return list(self.active.values())

    def live_view(self, device_id: str) -> dict:
        with self.lock:
            series = [{"ts": ts, **{c: round(v) for c, v in r.items()}} for ts, r in self.live.get(device_id, [])]
            now = dict(self.now.get(device_id) or {"headline": "Idle", "activity": "idle", "confidence": 0,
                                                    "why": [], "background": [], "classes": {}})
            flows = [r for r in self.active.values() if r.device_id == device_id]
        return {"series": series, "now": now, "classes": CLASSES, "flows": flows, "poll": self.poll}
