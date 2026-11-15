"""Turns raw per-connection counters into what a parent wants to know:
which device, which site/service, how long, how much data.

"How long" is measured as *active minutes*: a minute counts towards a service
if the device moved at least `active_minute_bytes` with it in that minute.
That avoids the trap of adding up overlapping connections (a YouTube tab holds
many) or counting an idle background socket as hours of use.
"""
from __future__ import annotations

import collections
import threading
import time

from ..services import service_for


class FlowRec:
    __slots__ = ("tuple", "flow_key", "device_id", "client_ip", "proto", "dst_ip", "dst_port",
                 "domain", "domain_src", "service", "ja4", "verdict", "reason", "start", "last",
                 "bytes_up", "bytes_down", "pkts_up", "pkts_down", "ended", "window", "flagged",
                 "filtered", "group", "dirty")

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
        self.flagged = False
        self.filtered = ctx.filtered
        self.group = ctx.group
        self.dirty = True

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
        self.poll = float(f.get("poll_interval", 5))
        self.log_trusted = bool(f.get("log_trusted_devices", True))
        self.db, self.policy, self.dnscache, self.labels, self.backend = db, policy, dnscache, labels, backend
        self.active: dict[str, FlowRec] = {}
        self._skip: set[str] = set()
        self._usage = collections.defaultdict(lambda: [0, 0])
        self.lock = threading.Lock()
        self.last_tick = 0.0
        self.error = None

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
                d_up = s.bytes_up - rec.bytes_up if s.bytes_up >= rec.bytes_up else s.bytes_up
                d_dn = s.bytes_down - rec.bytes_down if s.bytes_down >= rec.bytes_down else s.bytes_down
                rec.bytes_up, rec.bytes_down = s.bytes_up, s.bytes_down
                rec.pkts_up, rec.pkts_down = s.pkts_up, s.pkts_down
                self._label(rec)
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
        if self.db is not None:
            for (dev, svc, m), (up, dn) in usage.items():
                self.db.add_usage(dev, svc, m, up, dn)
        self.last_tick = now

    def active_flows(self):
        with self.lock:
            return list(self.active.values())
