"""A diagnostics bundle: one zip with everything needed to look into a problem.

    System -> Help & diagnostics -> Download diagnostics       (from the dashboard)
    sudo parental-gateway-diagnostics                           (on the Pi, if the dashboard won't open)
    python run.py --diagnostics                                 (anywhere)

What's in it (see README.txt inside):
  summary, component status, the environment checklist, update state + history,
  supervisor state, settings, list status, protections, database health,
  devices (no browsing), recent alerts, the gateway's own log files, and on
  Linux the firewall rules, network setup, service status and journal.

Privacy:
  * never included: the dashboard password, sign-in sessions
  * anonymised by default: device names, MAC addresses, home-network IP
    addresses (replaced by stable labels like device-3, mac-2, lan-ip-5, so
    the same device can still be followed through the files)
  * left out unless asked for: sites visited and connections (recent activity)

Every section is collected on its own - if one part of the gateway is broken,
the rest of the bundle still gets made (that's when it's needed most).
"""
from __future__ import annotations

import io
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import zipfile

_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
_URL_CREDS = re.compile(r"(https?://)[^/\s:@]+(?::[^/\s@]*)?@")
SECRET_SETTINGS = {"admin_hash", "sessions"}


def _private(octets) -> bool:
    a, b = int(octets[0]), int(octets[1])
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or \
        (a == 100 and 64 <= b <= 127) or (a == 169 and b == 254)


class Redactor:
    """Replaces names, MACs and home-network addresses with stable labels."""

    def __init__(self, enabled: bool, devices: list[dict] | None = None, gateway_ip: str | None = None):
        self.enabled = enabled
        self.macs: dict[str, str] = {}
        self.ips: dict[str, str] = {}
        self.names: list[tuple[str, str]] = []
        if gateway_ip:
            self.ips[gateway_ip] = "gateway-ip"
        for i, d in enumerate(devices or [], 1):
            label = f"device-{i}"
            d["_label"] = label
            for key in ("name", "hostname"):
                v = (d.get(key) or "").strip()
                if len(v) >= 3 and not _IPV4.fullmatch(v) and not _MAC.fullmatch(v):
                    self.names.append((v, label))
        self.names.sort(key=lambda p: -len(p[0]))          # longest first: "Sam's iPad" before "Sam"

    def _mac(self, m):
        k = m.group(0).lower().replace("-", ":")
        if k not in self.macs:
            self.macs[k] = f"mac-{len(self.macs) + 1}"
        return self.macs[k]

    def _ip(self, m):
        ip = m.group(0)
        if not all(0 <= int(x) <= 255 for x in m.groups()) or not _private(m.groups()):
            return ip                                      # public addresses are kept: they're what got blocked
        if ip not in self.ips:
            self.ips[ip] = f"lan-ip-{len(self.ips) + 1}"
        return self.ips[ip]

    def text(self, s: str) -> str:
        s = _URL_CREDS.sub(r"\1<credentials removed>@", s)
        if not self.enabled:
            return s
        for name, label in self.names:
            s = s.replace(name, label)
        s = _MAC.sub(self._mac, s)
        return _IPV4.sub(self._ip, s)


# ------------------------------------------------------------------ the bundle
class Bundle:
    def __init__(self, redactor: Redactor):
        self.r = redactor
        self.files: dict[str, bytes] = {}
        self.errors: list[str] = []

    def add_text(self, name: str, text: str):
        self.files[name] = self.r.text(text).encode("utf-8", errors="replace")

    def add_json(self, name: str, obj):
        self.add_text(name, json.dumps(obj, indent=1, default=str, ensure_ascii=False))

    def section(self, name: str, fn):
        """Run one collector; record (rather than raise) if it fails."""
        t0 = time.time()
        try:
            fn()
        except Exception as e:
            import traceback
            self.errors.append(f"{name}: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        if time.time() - t0 > 10:
            self.errors.append(f"{name}: slow ({time.time() - t0:.0f} s)")

    def zip(self) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for name, data in sorted(self.files.items()):
                z.writestr(name, data)
            if self.errors:
                z.writestr("collector-errors.txt", self.r.text("\n\n".join(self.errors)))
        return buf.getvalue()


def _run(cmd: list[str], timeout: float = 8) -> str:
    if not shutil.which(cmd[0]):
        return f"({cmd[0]} not available)"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout + (("\n--- stderr ---\n" + p.stderr) if p.stderr.strip() else "")).strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"(timed out after {timeout:.0f} s)"
    except OSError as e:
        return f"({e})"


def _tail_file(path: str, max_bytes: int) -> bytes:
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - max_bytes))
        data = fh.read()
    return (b"... (start of file cut) ...\n" + data) if size > max_bytes else data


def _redacted_config(cfg: dict) -> dict:
    def clean(v):
        if isinstance(v, dict):
            return {k: clean(x) for k, x in v.items()}
        if isinstance(v, list):
            return [clean(x) for x in v]
        if isinstance(v, str):
            return _URL_CREDS.sub(r"\1<credentials removed>@", v)
        return v
    return clean(cfg)


def build(cfg: dict, g=None, include_alerts: bool = True, include_activity: bool = False,
          anonymise: bool = True, note: str = "") -> tuple[bytes, str]:
    """Make the zip. g: the running Guardian (None when run from the command line)."""
    from .config import data_dir, resolve_data_path
    data = data_dir(cfg)
    db, own_db = None, False
    if g is not None:
        db = g.db
    else:
        try:
            from .db import DB
            path = resolve_data_path(cfg, cfg["database"])
            if os.path.exists(path):
                db, own_db = DB(path), True
        except Exception:
            db = None
    devices = []
    if db is not None:
        try:
            devices = [dict(d) for d in db.list_devices()]
        except Exception:
            pass
    gw_ip = (cfg.get("gateway") or {}).get("lan_ip") if cfg.get("mode") == "gateway" else None
    red = Redactor(anonymise, devices, gw_ip)
    b = Bundle(red)
    now = time.time()

    b.add_text("README.txt", README.format(
        when=time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        anon="Device names, MAC addresses and home-network IP addresses are replaced by labels "
             "(device-N, mac-N, lan-ip-N)." if anonymise else "Device names and addresses are NOT anonymised.",
        activity="Recent sites and connections ARE included (activity/)." if include_activity
        else "Sites visited and connections are NOT included."))
    if note.strip():
        b.add_text("NOTE.txt", note.strip()[:20000] + "\n")

    def summary():
        from .updater import release_info
        from . import supervisor
        rel = os.environ.get("GUARDIAN_RELEASE_DIR") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        info = release_info(rel)
        sup = supervisor.state(cfg)
        sup_alive = False
        if sup.get("supervisor_pid"):
            try:
                os.kill(int(sup["supervisor_pid"]), 0)
                sup_alive = True
            except (OSError, ValueError):
                pass
        b.add_json("summary.json", {
            "created": time.strftime("%Y-%m-%d %H:%M:%S %z"), "created_ts": now,
            "made_by": "dashboard" if g is not None else "command line",
            "version": info.get("version"), "commit": info.get("commit"), "release": os.path.basename(rel),
            "mode": cfg.get("mode"), "platform": platform.platform(), "machine": platform.machine(),
            "python": sys.version, "hostname": socket.gethostname(),
            "timezone": time.strftime("%Z %z"), "uptime_s": (now - g.started_at) if g is not None else None,
            "supervised": supervisor.under_supervisor(), "supervisor_running": sup_alive,
            "data_dir": data, "anonymised": anonymise, "activity_included": include_activity,
        })
        b.add_json("supervisor/state.json", sup)
        for f in ("switch-result.json", "switch-request.json"):
            p = os.path.join(data, f)
            if os.path.exists(p):
                b.add_text(f"supervisor/{f}", open(p, encoding="utf-8", errors="replace").read())
    b.section("summary", summary)

    if g is not None:
        b.section("status", lambda: b.add_json("status.json", g.status()))
        b.section("updates", lambda: b.add_json("updates.json", g.updater.status()))
        b.section("inspector", lambda: b.add_json("inspector.json", {
            "stats": dict(g.inspector.stats), "flows_tracked": len(g.inspector.flows),
            "dyn_blocked": sorted(g.inspector.dyn_blocked), "handover_until": g.inspector.handover_until,
            "dns_cache_entries": len(g.dnscache), "leader": getattr(getattr(g, "leader", None), "is_leader", None)}))
    elif db is not None:
        b.section("updates", lambda: b.add_text("updates.json", db.get_setting("update_state") or "{}"))

    def env():
        from . import environment
        b.add_json("environment.json", environment.detect(cfg, g))
    b.section("environment", env)

    def settings():
        from . import protections
        b.add_json("config/effective.json", _redacted_config({k: v for k, v in cfg.items()}))
        local = os.path.join(data, "config.local.yaml")
        if os.path.exists(local):
            b.add_text("config/config.local.yaml", open(local, encoding="utf-8", errors="replace").read())
        b.add_json("config/protections.json", {n: protections.effective(cfg, gc) for n, gc in cfg["groups"].items()})
    b.section("settings", settings)

    if db is not None:
        def database():
            tables = [r["name"] for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")]
            counts = {t: db.query(f"SELECT COUNT(*) AS n FROM {t}")[0]["n"] for t in tables}
            path = resolve_data_path(cfg, cfg["database"])
            files = {os.path.basename(p): os.path.getsize(p) for p in (path, path + "-wal") if os.path.exists(p)}
            schema = {t: [r["name"] for r in db.query(f"PRAGMA table_info({t})")] for t in tables}
            check = db.query("PRAGMA quick_check(5)")
            settings = {r["key"]: (r["value"] if len(r["value"] or "") < 400 else f"({len(r['value'])} chars)")
                        for r in db.query("SELECT key, value FROM settings") if r["key"] not in SECRET_SETTINGS}
            meta = {r["key"]: r["value"] for r in db.query("SELECT key, value FROM meta")}
            b.add_json("database.json", {"files": files, "rows": counts, "quick_check": [list(r.values())[0] for r in check],
                                         "schema": schema, "settings": settings, "meta": meta})
        b.section("database", database)

        def devs():
            out = []
            for d in devices:
                gname = d.get("group_name")
                out.append({"label": d.get("_label"), "name": d.get("name"), "hostname": d.get("hostname"),
                            "mac": d.get("mac"), "ip": d.get("ip"), "group": gname or f"(default: {cfg['default_group']})",
                            "suspect": bool(d.get("suspect")), "paused_until": d.get("paused_until"),
                            "first_seen": d.get("first_seen"), "last_seen": d.get("last_seen")})
            b.add_json("devices.json", out)
            b.add_json("rules.json", {"rules": db.list_rules(), "schedules": db.list_schedules(),
                                      "allowlist": db.allowlist(), "dyn_blocks": db.dyn_blocks()})
        b.section("devices", devs)

        if include_alerts:
            b.section("alerts", lambda: b.add_json("alerts.json", db.alerts(since=now - 7 * 86400, limit=1000)))
        if include_activity:
            b.section("activity", lambda: (
                b.add_json("activity/dns-queries.json", db.recent_queries(500)),
                b.add_json("activity/connections.json", db.flows(since=now - 3600, limit=500))))

    if g is not None:
        b.section("lists", lambda: b.add_json("lists.json", g.lists.status))

    def logs():
        from .logs import log_dir
        d = log_dir(data)
        if not os.path.isdir(d):
            b.add_text("logs/README.txt", "No log files yet (they're written from this version on).\n")
            return
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                cap = 3_000_000 if name.endswith(".log") else 1_000_000
                b.add_text(f"logs/{name}", _tail_file(p, cap).decode("utf-8", errors="replace"))
    b.section("logs", logs)

    if sys.platform.startswith("linux"):
        def system():
            cmds = {
                "uname.txt": ["uname", "-a"], "uptime.txt": ["uptime"], "memory.txt": ["free", "-m"],
                "disk.txt": ["df", "-h", data], "ip-addr.txt": ["ip", "-4", "addr"], "ip-route.txt": ["ip", "route"],
                "ip-neigh.txt": ["ip", "neigh"], "nft-ruleset.txt": ["nft", "list", "ruleset"],
                "iptables.txt": ["iptables", "-S"], "conntrack-count.txt": ["conntrack", "-C"],
                "services.txt": ["systemctl", "--no-pager", "status", "parental-gateway", "dnsmasq", "avahi-daemon"],
                "journal-gateway.txt": ["journalctl", "-u", "parental-gateway", "-n", "3000", "--no-pager"],
                "journal-dnsmasq.txt": ["journalctl", "-u", "dnsmasq", "-n", "300", "--no-pager"],
                "kernel-messages.txt": ["dmesg", "--ctime", "-T"],
            }
            for name, cmd in cmds.items():
                out = _run(cmd)
                if name == "kernel-messages.txt":
                    out = "\n".join(out.splitlines()[-300:])
                b.add_text(f"system/{name}", out + "\n")
            sysctl = {}
            for k in ("net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding", "net/netfilter/nf_conntrack_acct",
                      "net/netfilter/nf_conntrack_count", "net/netfilter/nf_conntrack_max"):
                try:
                    sysctl[k] = open(f"/proc/sys/{k}").read().strip()
                except OSError as e:
                    sysctl[k] = str(e)
            model = ""
            try:
                model = open("/proc/device-tree/model").read().strip("\x00\n")
            except OSError:
                pass
            b.add_json("system/kernel-settings.json", {"sysctl": sysctl, "model": model})
        b.section("system", system)
    else:
        b.section("system", lambda: b.add_json("system/platform.json", {
            "platform": platform.platform(), "release": platform.release(), "version": platform.version()}))

    if own_db:
        try:
            db.close()
        except Exception:
            pass
    host = re.sub(r"[^A-Za-z0-9-]", "", socket.gethostname())[:20] or "gateway"
    name = f"parental-gateway-diagnostics-{host}-{time.strftime('%Y%m%d-%H%M%S')}.zip"
    return b.zip(), name


README = """Parental Gateway - diagnostics bundle
Made {when}.

Send this file to whoever is helping you. It contains:

  summary.json        version, platform, whether the service is running
  status.json         each component (DNS, firewall, inspector, monitor...) - from the dashboard only
  environment.json    the setup checklist (interfaces, permissions, lists)
  updates.json        update status and history
  supervisor/         the update/restart supervisor's state and last switch result
  config/             settings in effect (no passwords - none are kept there)
  database.json       database health, table sizes, schema, settings (password and sessions removed)
  devices.json        devices and their groups
  rules.json          site rules, schedules, allow-listed and blocked destinations
  alerts.json         alerts from the last 7 days (if included)
  activity/           sites looked up and connections in the last hour (only if you chose to include them)
  logs/               the gateway's own log files
  system/             (Linux) firewall rules, network setup, service status, system journal
  NOTE.txt            what you wrote about the problem
  collector-errors.txt  anything that couldn't be collected (useful too)

Privacy: the dashboard password and sign-in sessions are never included.
{anon}
{activity}
"""
