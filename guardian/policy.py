"""Who is this device, which group is it in, and is this name allowed for it?

Decision order for a name:
  1. an 'allow' rule (global / group / device)  -> allow  (whitelist inside a blocked category)
  2. a 'block' rule                             -> block
  3. a category blocklist enabled for the group -> block
  4. otherwise                                  -> allow
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .services import normalize_name


@dataclass
class DeviceCtx:
    device_id: str
    ip: str
    mac: str | None
    group: str
    g: dict = field(repr=False)
    hostname: str | None = None

    @property
    def filtered(self) -> bool:
        return bool(self.g.get("filtered"))


@dataclass
class Decision:
    block: bool
    reason: str = ""
    category: str | None = None


class Policy:
    def __init__(self, cfg: dict, db, lists, identity, alerts=None):
        self.cfg = cfg
        self.db = db
        self.lists = lists
        self.identity = identity
        self.alerts = alerts
        self.forced_group: str | None = None   # replay tool / tests
        self._rules: list[dict] = []
        self._groups: dict[str, str | None] = {}
        self._touched: dict[str, float] = {}
        self._suspect: set[str] = set()
        self._lock = threading.Lock()
        self.reload()

    # ------------------------------------------------------------ state
    def reload(self):
        rules = self.db.list_rules() if self.db else []
        devices = self.db.list_devices() if self.db else []
        groups = {d["device_id"]: d.get("group_name") for d in devices}
        suspect = {d["device_id"] for d in devices if d.get("suspect")}
        with self._lock:
            self._rules = rules
            self._groups = groups
            self._suspect = suspect

    def group_name(self, device_id: str) -> str:
        if self.forced_group:
            return self.forced_group
        if device_id in self._suspect:            # identity under suspicion: strictest group
            return self.cfg["default_group"]
        g = self._groups.get(device_id)
        return g if g in self.cfg["groups"] else self.cfg["default_group"]

    def is_suspect(self, device_id: str) -> bool:
        return device_id in self._suspect

    def configured_group(self, device_id: str) -> str:
        g = self._groups.get(device_id)
        return g if g in self.cfg["groups"] else self.cfg["default_group"]

    def set_device_group(self, device_id: str, group: str | None):
        if group is not None and group not in self.cfg["groups"]:
            raise ValueError(f"unknown group {group}")
        self.db.update_device(device_id, group=group, set_group=True)
        self.reload()

    # ------------------------------------------------------------ identity
    def context(self, ip: str, mac: str | None = None) -> DeviceCtx:
        if mac:
            self.identity.learn(ip, mac)
            device_id, mac = mac.lower(), mac.lower()
        else:
            device_id, mac = self.identity.device_id_for(ip)
        group = self.group_name(device_id)
        ctx = DeviceCtx(device_id, ip, mac, group, self.cfg["groups"][group],
                        self.identity.hostname_for(mac))
        self._touch(ctx)
        return ctx

    def _touch(self, ctx: DeviceCtx):
        if self.db is None:
            return
        now = time.time()
        last = self._touched.get(ctx.device_id)
        if last is not None and now - last < 60:
            return
        self._touched[ctx.device_id] = now
        if ctx.mac and ctx.ip != ctx.device_id and ctx.ip in self._groups:
            if self.db.adopt_ip_device(ctx.ip, ctx.mac):
                self.reload()
        is_new = ctx.device_id not in self._groups
        self.db.upsert_device_seen(ctx.device_id, ctx.mac, ctx.ip, ctx.hostname)
        if is_new:
            with self._lock:
                self._groups.setdefault(ctx.device_id, None)
            if self.alerts:
                self.alerts.emit("new_device", device_id=ctx.device_id, client_ip=ctx.ip,
                                 action="placed in " + ctx.group,
                                 detail=f"{ctx.hostname or ctx.mac or ctx.ip} joined and was put in "
                                        f"the '{ctx.group}' group until you assign it")

    # ------------------------------------------------------------ decisions
    @staticmethod
    def _match(pattern: str, name: str) -> bool:
        return name == pattern or name.endswith("." + pattern)

    def decide(self, ctx: DeviceCtx, name: str) -> Decision:
        name = normalize_name(name) or ""
        rules = self._rules
        mine = [r for r in rules if r["scope"] == "global"
                or (r["scope"] == "group" and r["target"] == ctx.group)
                or (r["scope"] == "device" and r["target"] == ctx.device_id)]
        for r in mine:
            if r["action"] == "allow" and self._match(r["pattern"], name):
                return Decision(False, f"allow rule: {r['pattern']}")
        for r in mine:
            if r["action"] == "block" and self._match(r["pattern"], name):
                return Decision(True, f"block rule: {r['pattern']}", "rule")
        cat = self.lists.category_match(name, ctx.g.get("categories") or [])
        if cat:
            return Decision(True, f"category: {cat}", cat)
        return Decision(False, "")
