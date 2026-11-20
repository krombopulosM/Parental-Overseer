"""Who is this device, which group is it in, and is this name allowed for it?

Decision order for a name:
  1. an 'allow' rule (global / group / device)  -> allow  (whitelist inside a blocked category)
  2. a 'block' rule                             -> block
  3. a category blocklist enabled for the group -> block
  4. otherwise                                  -> allow
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field

from .protections import BYPASS_CATEGORIES, CATEGORY_FOR
from .protections import on as prot
from .services import normalize_name


@dataclass
class DeviceCtx:
    device_id: str
    ip: str
    mac: str | None
    group: str
    g: dict = field(repr=False)
    hostname: str | None = None
    categories: list | None = None          # the group's, adjusted by this device's own choices

    @property
    def filtered(self) -> bool:
        return bool(self.g.get("filtered"))

    def blocks(self, category: str) -> bool:
        cats = self.categories if self.categories is not None else (self.g.get("categories") or [])
        return category in cats


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
        self._overrides: dict[str, dict] = {}
        self._lock = threading.Lock()
        self.reload()

    # ------------------------------------------------------------ state
    def reload(self):
        rules = self.db.list_rules() if self.db else []
        devices = self.db.list_devices() if self.db else []
        groups = {d["device_id"]: d.get("group_name") for d in devices}
        suspect = {d["device_id"] for d in devices if d.get("suspect")}
        overrides = {}
        for d in devices:
            try:
                o = json.loads(d.get("category_overrides") or "{}")
            except ValueError:
                o = {}
            o = {k: v for k, v in o.items() if v in ("allow", "block")}
            if o:
                overrides[d["device_id"]] = o
        with self._lock:
            self._rules = rules
            self._groups = groups
            self._suspect = suspect
            self._overrides = overrides

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

    def category_overrides(self, device_id: str) -> dict:
        return dict(self._overrides.get(device_id) or {})

    def categories_for(self, device_id: str, group: str | None = None) -> list:
        """The categories blocked for this device: its group's, then its own choices
        (allow / block) on top. A device whose identity is in doubt gets the group's
        only - a copied address mustn't bring another child's allowances with it."""
        group = group or self.group_name(device_id)
        cats = list(self.cfg["groups"][group].get("categories") or [])
        if device_id in self._suspect:
            return cats
        for cat, how in (self._overrides.get(device_id) or {}).items():
            if how == "allow" and cat in cats:
                cats.remove(cat)
            elif how == "block" and cat not in cats:
                cats.append(cat)
        return cats

    def set_category_override(self, device_id: str, category: str, how: str | None):
        if how not in (None, "allow", "block"):
            raise ValueError("choose allow, block or the group's setting")
        o = self.category_overrides(device_id)
        if how is None:
            o.pop(category, None)
        else:
            o[category] = how
        self.db.update_device(device_id)
        self.db.set_category_overrides(device_id, o)
        self.reload()

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
                        self.identity.hostname_for(mac), self.categories_for(device_id, group))
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
        if ctx.filtered:
            v = self._bypass_decision(ctx, name)
            if v is not None:
                return v
        cats = [c for c in (ctx.categories if ctx.categories is not None else ctx.g.get("categories") or [])
                if c not in BYPASS_CATEGORIES]
        cat = self.lists.category_match(name, cats)
        if cat:
            return Decision(True, f"category: {cat}", cat)
        return Decision(False, "")

    _BYPASS_LABEL = {"tor": "Tor", "doh": "encrypted DNS", "vpn": "VPN", "proxy": "proxy",
                     "bypass": "VPN / proxy / bypass service"}

    def _bypass_decision(self, ctx, name) -> Decision | None:
        """VPN / Tor / proxy / encrypted-DNS sites follow their protection switch.
        A name on a specific list whose protection is off is let through even if
        the broader community list also has it."""
        for key, cat in CATEGORY_FOR.items():
            if self.lists.category_match(name, [cat]):
                if prot(self.cfg, ctx.g, key):
                    return Decision(True, f"{self._BYPASS_LABEL[cat]} site", cat)
                return None                     # switched off: skip the community list too
        if (prot(self.cfg, ctx.g, "vpn") or prot(self.cfg, ctx.g, "proxies")) and \
                self.lists.category_match(name, ["bypass"]):
            return Decision(True, "VPN / proxy / bypass service", "bypass")
        return None

    def prot(self, ctx, key):
        return prot(self.cfg, ctx.g, key)
