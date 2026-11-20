"""Dashboard web app + JSON API."""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import time

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse

import json

from . import localname, protections
from .alerts import KINDS
from .auth import Auth
from .activity import CLASSES
from .confidence import CATEGORIES, KIND_META
from .schedule import FOREVER
from .services import registrable_domain, service_label

COOKIE = "pg_session"
_DOMAIN_RE = re.compile(r"^[a-z0-9*_.-]+\.[a-z0-9-]+$")
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_STATIC = {"app.js": None, "devices.js": None, "wizard.js": None, "style.css": None, "docs.html": None,
           "manifest.webmanifest": "application/manifest+json", "icon-192.png": None, "icon-512.png": None,
           "icon-maskable-512.png": None, "apple-touch-icon.png": None, "favicon.png": None}
# Everything but the Guide loads before sign-in (the app shell, icons, the manifest).
_PUBLIC = {"/", "/api/session", "/api/login", "/api/setup", "/apple-touch-icon.png", "/favicon.ico"} | \
    {f"/static/{n}" for n in _STATIC if n != "docs.html"}


def _midnight() -> float:
    now = dt.datetime.now()
    return dt.datetime(now.year, now.month, now.day).timestamp()


def create_app(g) -> FastAPI:
    """g is the Guardian orchestrator."""
    app = FastAPI(title="Parental Gateway", docs_url=None, redoc_url=None, openapi_url=None)
    def on_login_fail(ip, n):
        if n >= 3:
            ctx = g.policy.context(ip)
            g.alerts.emit("dashboard_bruteforce", device_id=ctx.device_id, client_ip=ip,
                          detail=f"{n} wrong dashboard passwords in 5 minutes from {ip}. Logins from it "
                                 f"are locked for 5 minutes after the 5th.",
                          action="locked out" if n >= 5 else "detected")

    auth = Auth(g.db, on_fail=on_login_fail)
    static = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    active_bytes = int(g.cfg["flows"].get("active_minute_bytes", 10000))
    app.state.auth = auth

    def client_ip(req: Request) -> str:
        return req.client.host if req.client else ""

    @app.middleware("http")
    async def guard(req: Request, call_next):
        path = req.url.path
        if path not in _PUBLIC:
            if not auth.check(req.cookies.get(COOKIE)):
                return JSONResponse({"error": "login required"}, status_code=401)
        if req.method in ("POST", "PUT", "DELETE") and req.headers.get("x-guardian") != "1":
            return JSONResponse({"error": "missing X-Guardian header"}, status_code=403)
        resp = await call_next(req)
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    # ------------------------------------------------------------ static + auth
    @app.get("/")
    def index():
        return FileResponse(os.path.join(static, "index.html"), headers={"Cache-Control": "no-store"})

    @app.get("/static/{name}")
    def static_file(name: str):
        if name not in _STATIC:
            raise HTTPException(404)
        cache = "max-age=86400" if name.endswith(".png") else "no-store"
        return FileResponse(os.path.join(static, name), media_type=_STATIC[name],
                            headers={"Cache-Control": cache})

    @app.get("/apple-touch-icon.png")           # iOS asks for these at the site root
    def apple_icon():
        return static_file("apple-touch-icon.png")

    @app.get("/favicon.ico")
    def favicon():
        return FileResponse(os.path.join(static, "favicon.png"), media_type="image/png",
                            headers={"Cache-Control": "max-age=86400"})

    def setup_allowed(ip: str) -> tuple[bool, str]:
        if ip in ("127.0.0.1", "::1"):
            return True, ""
        from .appliance import setup_from_network
        return setup_from_network(g.cfg, ip)

    @app.get("/api/session")
    def session(req: Request):
        ip = client_ip(req)
        allowed, hint = setup_allowed(ip) if not auth.has_password() else (False, "")
        return {"authenticated": auth.check(req.cookies.get(COOKIE)),
                "needs_setup": not auth.has_password(), "setup_allowed": allowed, "setup_hint": hint,
                "setup_complete": g.db.get_setting("setup_complete") is not None,
                "mode": g.mode}

    @app.post("/api/setup")
    async def setup(req: Request, resp: Response):
        if auth.has_password():
            raise HTTPException(409, "already set up")
        allowed, hint = setup_allowed(client_ip(req))
        if not allowed:
            raise HTTPException(403, hint or "first-time setup must be done on the gateway itself "
                                             "(or run: python run.py --set-password)")
        body = await req.json()
        try:
            auth.set_password(body.get("password", ""))
        except ValueError as e:
            raise HTTPException(400, str(e))
        token = auth.login(body["password"], client_ip(req))
        resp.set_cookie(COOKIE, token, httponly=True, samesite="strict")
        return {"ok": True}

    @app.post("/api/login")
    async def login(req: Request, resp: Response):
        body = await req.json()
        ip = client_ip(req)
        if auth.locked_out(ip):
            raise HTTPException(429, "too many attempts - wait 5 minutes")
        token = auth.login(body.get("password", ""), ip)
        if not token:
            raise HTTPException(401, "wrong password")
        resp.set_cookie(COOKIE, token, httponly=True, samesite="strict")
        return {"ok": True}

    @app.post("/api/logout")
    def logout(req: Request, resp: Response):
        auth.logout(req.cookies.get(COOKIE))
        resp.delete_cookie(COOKIE)
        return {"ok": True}

    @app.post("/api/password")
    async def change_password(req: Request):
        body = await req.json()
        if not auth.verify(body.get("current", "")):
            raise HTTPException(401, "current password is wrong")
        try:
            auth.set_password(body.get("new", ""))
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"ok": True}

    # ------------------------------------------------------------ helpers
    def devices_view():
        midnight = _midnight()
        m0 = int(midnight // 60)
        qc = g.db.per_device_query_counts(midnight)
        online = g.db.online_minutes(m0, active_bytes)
        data = g.db.data_totals(m0)
        alerts = {}
        for a in g.db.alerts(since=midnight, limit=1000):
            if a["severity"] != "info":
                alerts[a["device_id"]] = alerts.get(a["device_id"], 0) + a["count"]
        out = []
        now = time.time()
        for d in g.db.list_devices():
            did = d["device_id"]
            grp = g.policy.group_name(did)
            paused, why = g.scheduler.is_paused(did, grp)
            out.append({
                "device_id": did, "mac": d["mac"], "ip": d["ip"], "name": d["name"],
                "hostname": d["hostname"], "label": d["name"] or d["hostname"] or d["ip"] or did,
                "group": grp, "group_set": d["group_name"] is not None,
                "filtered": g.cfg["groups"][grp]["filtered"],
                "online": (d["last_seen"] or 0) > now - 300, "last_seen": d["last_seen"],
                "paused": paused, "paused_reason": why, "suspect": bool(d.get("suspect")),
                "blocked_all": (d.get("paused_until") or 0) >= FOREVER,
                "first_seen": d.get("first_seen"),
                "minutes_today": (online.get(did) or {}).get("minutes", 0),
                "bytes_up": (data.get(did) or {}).get("bytes_up") or 0,
                "bytes_down": (data.get(did) or {}).get("bytes_down") or 0,
                "queries": (qc.get(did) or {}).get("queries", 0),
                "blocked": (qc.get(did) or {}).get("blocked") or 0,
                "alerts": alerts.get(did, 0),
            })
        out.sort(key=lambda x: (not x["online"], -(x["last_seen"] or 0)))
        return out

    def names_map():
        return {d["device_id"]: (d["name"] or d["hostname"] or d["ip"] or d["device_id"])
                for d in g.db.list_devices()}

    def flow_view(r, names, now):
        dur = (r["last"] if r.get("ended") else now) - r["start"]
        return {**{k: r.get(k) for k in ("device_id", "client_ip", "proto", "dst_ip", "dst_port",
                                         "domain", "domain_src", "ja4", "verdict", "reason",
                                         "bytes_up", "bytes_down", "start", "last", "ended")},
                "device": names.get(r.get("device_id"), r.get("client_ip")),
                "service": service_label(r.get("service")), "duration": max(0, dur)}

    def services_view(since_min, device_id=None, limit=25):
        rows = g.db.usage_by_service(since_min, active_bytes, device_id, limit)
        return [{"service": service_label(r["service"]), "key": r["service"], "minutes": r["minutes"],
                 "bytes_up": r["bytes_up"] or 0, "bytes_down": r["bytes_down"] or 0} for r in rows]

    def alert_view(a, names):
        meta = KIND_META.get(a["kind"], ("vpn", None, "none", ""))
        try:
            why = json.loads(a.get("confidence_why") or "[]")
        except ValueError:
            why = []
        return {**a, "title": KINDS.get(a["kind"], (a["kind"],))[0], "confidence_why": why,
                "category": a.get("category") or meta[0], "category_label": CATEGORIES.get(meta[0], ""),
                "fp_action": meta[2], "fp_note": meta[3],
                "device": names.get(a["device_id"], a["client_ip"] or "the gateway")}

    # ------------------------------------------------------------ dashboard data
    @app.get("/api/overview")
    def overview():
        midnight = _midnight()
        names = names_map()
        devs = devices_view()
        alerts = [a for a in g.db.alerts(since=midnight, limit=500) if a["severity"] != "info"]
        return {
            "mode": g.mode,
            "counts": g.db.query_counts(midnight),
            "devices_online": sum(1 for d in devs if d["online"]),
            "devices_total": len(devs),
            "bypass_attempts": sum(a["count"] for a in alerts),
            "data_down": sum(d["bytes_down"] for d in devs),
            "data_up": sum(d["bytes_up"] for d in devs),
            "top_services": services_view(int(midnight // 60), limit=10),
            "recent_alerts": [alert_view(a, names) for a in g.db.alerts(limit=8)],
            "devices": devs[:12],
        }

    @app.get("/api/groups")
    def groups():
        return {"groups": [{"name": n, **{k: v for k, v in gc.items() if k != "categories"},
                            "categories": gc.get("categories", [])}
                           for n, gc in g.cfg["groups"].items()],
                "default_group": g.cfg["default_group"]}

    @app.get("/api/devices")
    def devices(req: Request):
        rows = devices_view()
        ip = client_ip(req)
        try:
            you, mac = g.policy.identity.device_id_for(ip)
        except Exception:
            you, mac = None, None
        if not mac:                     # MAC not known here: the device last seen at this address
            you = next((d["device_id"] for d in rows if d["ip"] == ip), you)
        return {"devices": rows, "you": you}

    @app.get("/api/devices/{device_id}")
    def device(device_id: str):
        d = g.db.get_device(device_id)
        if not d:
            raise HTTPException(404)
        midnight = _midnight()
        names = names_map()
        now = time.time()
        view = next((x for x in devices_view() if x["device_id"] == device_id), None)
        live = []
        if g.monitor is not None:
            live = [flow_view(r.row(), names, now) for r in g.monitor.active_flows()
                    if r.device_id == device_id]
            live.sort(key=lambda f: -(f["bytes_down"] + f["bytes_up"]))
        timeline = []
        for row in g.db.activity_since(device_id, int(midnight // 60)):
            last = timeline[-1] if timeline else None
            if last and last["activity"] == row["activity"] and row["minute"] - last["end_minute"] <= 2:
                last["end_minute"] = row["minute"]
                last["headlines"][row["headline"]] = last["headlines"].get(row["headline"], 0) + 1
            else:
                timeline.append({"activity": row["activity"], "start_minute": row["minute"],
                                 "end_minute": row["minute"], "headlines": {row["headline"]: 1}})
        for t in timeline:
            t["start"], t["end"] = t["start_minute"] * 60, (t["end_minute"] + 1) * 60
            t["headline"] = max(t["headlines"], key=t["headlines"].get)
            t["label"] = CLASSES.get(t["activity"], t["activity"])
            del t["headlines"]
        return {
            "device": view,
            "timeline": timeline,
            "midnight": midnight,
            "services": services_view(int(midnight // 60), device_id, 50),
            "week": services_view(int((midnight - 6 * 86400) // 60), device_id, 25),
            "queries": g.db.recent_queries(150, device_id=device_id),
            "flows": live[:100],
            "alerts": [alert_view(a, names) for a in g.db.alerts(limit=50, device_id=device_id)],
        }

    @app.post("/api/devices/{device_id}")
    async def update_device(device_id: str, req: Request):
        body = await req.json()
        g.db.flush()      # make sure the device's own "seen" row (with its MAC) is written first
        if "name" in body:
            g.db.update_device(device_id, name=(body["name"] or "").strip()[:60])
        if "group" in body:
            grp = body["group"] or None
            if grp is not None and grp not in g.cfg["groups"]:
                raise HTTPException(400, "unknown group")
            g.policy.set_device_group(device_id, grp)
        g.device_changed()
        return {"ok": True}

    @app.delete("/api/devices/{device_id}")
    def forget_device(device_id: str):
        if not g.db.get_device(device_id):
            raise HTTPException(404)
        g.db.forget_device(device_id)
        g.device_changed()
        return {"ok": True}

    @app.post("/api/devices/{device_id}/pause")
    async def pause_device(device_id: str, req: Request):
        body = await req.json()
        minutes = float(body.get("minutes", 60))
        until = g.scheduler.pause(device_id, minutes)
        g.device_changed()
        return {"ok": True, "paused_until": until}

    @app.get("/api/flows")
    def flows(device: str | None = None, limit: int = 300):
        names = names_map()
        now = time.time()
        live = []
        if g.monitor is not None:
            live = [flow_view(r.row(), names, now) for r in g.monitor.active_flows()
                    if not device or r.device_id == device]
        live.sort(key=lambda f: -f["last"])
        recent = [flow_view(r, names, now) for r in
                  g.db.flows(since=now - 3600, device_id=device, limit=limit) if r["ended"]]
        return {"live": live[:limit], "recent": recent, "monitor": g.monitor is not None}

    @app.get("/api/queries")
    def queries(device: str | None = None, blocked: bool = False, limit: int = 200):
        names = names_map()
        rows = g.db.recent_queries(min(limit, 1000), device_id=device, blocked_only=blocked)
        for r in rows:
            r["device"] = names.get(r["device_id"], r["client_ip"])
        return {"queries": rows}

    @app.get("/api/alerts")
    def alerts(limit: int = 200, unacked: bool = False):
        names = names_map()
        return {"alerts": [alert_view(a, names) for a in g.db.alerts(limit=limit, unacked_only=unacked)]}

    @app.post("/api/alerts/{alert_id}/ack")
    def ack(alert_id: int):
        g.db.ack_alert(alert_id)
        return {"ok": True}

    @app.post("/api/alerts/{alert_id}/review")
    async def review_alert(alert_id: int, req: Request):
        """'Not a bypass' (fp) or 'Confirmed' (tp). Reviews calibrate future
        confidence scores; 'Not a bypass' also undoes the block where that makes sense."""
        body = await req.json()
        verdict = body.get("verdict")
        if verdict not in ("fp", "tp"):
            raise HTTPException(400, "verdict must be fp or tp")
        a = g.db.get_alert(alert_id)
        if not a:
            raise HTTPException(404)
        note = ""
        if verdict == "fp":
            action = KIND_META.get(a["kind"], (None, None, "none"))[2]
            if action == "allow_ip" and a["dst"]:
                g.db.add_allow("ip", a["dst"], f"not a bypass ({a['kind']}, alert {alert_id})")
                if g.gateway is not None:
                    g.gateway.unblock_ip(a["dst"])
                else:
                    g.db.remove_dyn_block(a["dst"])
                g.inspector.dyn_blocked.discard(a["dst"])
                if a["domain"] and a["kind"] == "tunnel_behaviour":
                    g.db.add_allow("domain", registrable_domain(a["domain"]), f"alert {alert_id}")
                note = f"{a['dst']} will no longer be blocked by this check"
            elif action == "fingerprint":
                g.reputation.forgive(a.get("ref"))
                note = "that software's fingerprint is trusted again"
            elif action == "identity" and a["device_id"]:
                g.db.set_suspect(a["device_id"], False)
                fp = g.db.get_fingerprint(a["device_id"])
                if fp:
                    g.db.save_fingerprint(a["device_id"], fp["fp"], fp["hostname"], prev_fp=fp["fp"])
                g.device_changed()
                note = "device trusted again; its current fingerprint is now the expected one"
            else:
                note = "confidence for similar alerts lowered"
        if verdict == "tp" and a.get("ref") and a["kind"] in ("tunnel_behaviour", "sni_mismatch", "no_sni",
                                                              "vpn_fingerprint", "tor", "unknown_site_held"):
            if g.reputation.learn_bad(a["ref"], f"a tunnel you confirmed ({a['kind']})", "parent"):
                note = "its software fingerprint will now be blocked on any server"
        if verdict == "tp" and a["kind"] == "unknown_site_held" and a["domain"]:
            row = g.db.query_one("SELECT ja4 FROM flows WHERE device_id=? AND dst_ip=? AND ja4 IS NOT NULL "
                                 "ORDER BY last DESC LIMIT 1", (a["device_id"], a["dst"]))
            if row and g.reputation.learn_bad(row["ja4"], f"the tunnel to {a['domain']}", "parent"):
                note = "its software fingerprint will now be blocked on any server"
        g.db.review_alert(alert_id, verdict)
        g.refresh_allowlist()
        return {"ok": True, "note": note}

    @app.post("/api/devices/{device_id}/trust")
    def trust_device(device_id: str):
        """"It's me": lift identity quarantine after a fingerprint change."""
        g.db.set_suspect(device_id, False)
        fp = g.db.get_fingerprint(device_id)
        if fp:
            g.db.save_fingerprint(device_id, fp["fp"], fp["hostname"], prev_fp=fp["fp"])
        for a in g.db.query("SELECT id FROM alerts WHERE device_id=? AND kind IN ('mac_spoof','mac_clone') "
                            "AND review IS NULL", (device_id,)):
            g.db.review_alert(a["id"], "fp")
        g.device_changed()
        g.refresh_allowlist()
        return {"ok": True}

    @app.post("/api/alerts/{alert_id}/allow")
    def allow_from_alert(alert_id: int):
        """'This is fine': exempt the destination from the behaviour detector,
        lift any automatic block, and allow its domain for this device's group."""
        a = g.db.get_alert(alert_id)
        if not a:
            raise HTTPException(404)
        if a["dst"]:
            g.db.add_allow("ip", a["dst"], f"from alert {alert_id}")
            if g.gateway is not None:
                g.gateway.unblock_ip(a["dst"])
            else:
                g.db.remove_dyn_block(a["dst"])
            g.inspector.dyn_blocked.discard(a["dst"])
        if a["domain"] and a["kind"] in ("tunnel_behaviour", "sni_mismatch", "no_sni", "dns_bypass_site"):
            g.db.add_allow("domain", registrable_domain(a["domain"]), f"from alert {alert_id}")
        g.db.ack_alert(alert_id)
        if g.detector is not None:
            g.detector.reload_allowlist()
        return {"ok": True}

    # ------------------------------------------------------------ rules & schedules
    @app.get("/api/rules")
    def rules():
        return {"rules": g.db.list_rules(), "allowlist": g.db.allowlist(),
                "dyn_blocks": g.db.dyn_blocks(), "fingerprints": g.reputation.learned()}

    @app.post("/api/rules")
    async def add_rule(req: Request):
        b = await req.json()
        pattern = (b.get("pattern") or "").strip().lower().rstrip(".")
        pattern = re.sub(r"^https?://", "", pattern).split("/")[0]
        if not _DOMAIN_RE.match(pattern):
            raise HTTPException(400, "enter a domain like tiktok.com")
        scope = b.get("scope", "global")
        if scope not in ("global", "group", "device") or b.get("action") not in ("block", "allow"):
            raise HTTPException(400, "bad scope/action")
        target = b.get("target") if scope != "global" else None
        if scope == "group" and target not in g.cfg["groups"]:
            raise HTTPException(400, "unknown group")
        g.db.add_rule(scope, target, pattern, b["action"])
        g.policy.reload()
        return {"ok": True}

    @app.delete("/api/rules/{rule_id}")
    def delete_rule(rule_id: int):
        g.db.delete_rule(rule_id)
        g.policy.reload()
        return {"ok": True}

    @app.delete("/api/allowlist/{aid}")
    def delete_allow(aid: int):
        g.db.delete_allow(aid)
        if g.detector is not None:
            g.detector.reload_allowlist()
        return {"ok": True}

    @app.delete("/api/dynblocks/{ip}")
    def delete_dyn(ip: str):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(400)
        if g.gateway is not None:
            g.gateway.unblock_ip(ip)
        else:
            g.db.remove_dyn_block(ip)
        g.inspector.dyn_blocked.discard(ip)
        return {"ok": True}

    @app.delete("/api/fingerprints/{ja4}")
    def forget_fingerprint(ja4: str):
        g.reputation.forgive(ja4)
        return {"ok": True}

    @app.get("/api/schedules")
    def schedules():
        return {"schedules": g.db.list_schedules()}

    @app.post("/api/schedules")
    async def add_schedule(req: Request):
        b = await req.json()
        if not (_TIME_RE.match(b.get("start", "")) and _TIME_RE.match(b.get("end", ""))):
            raise HTTPException(400, "times must be HH:MM")
        scope = b.get("scope", "group")
        if scope not in ("group", "device", "all"):
            raise HTTPException(400, "bad scope")
        days = ",".join(d for d in (b.get("days") or "").lower().replace(" ", "").split(",")
                        if d in ("mon", "tue", "wed", "thu", "fri", "sat", "sun")) or "mon,tue,wed,thu,fri,sat,sun"
        g.db.add_schedule(scope, b.get("target"), days, b["start"], b["end"])
        g.device_changed()
        return {"ok": True}

    @app.delete("/api/schedules/{sid}")
    def delete_schedule(sid: int):
        g.db.delete_schedule(sid)
        g.device_changed()
        return {"ok": True}

    # ------------------------------------------------------------ live
    def live_flow(r, names, now):
        v = flow_view(r.row(), names, now)
        a = r.activity
        v.update(activity=a.cls if a else "idle", activity_label=CLASSES.get(a.cls, "") if a else "Idle",
                 activity_confidence=a.confidence if a else None, activity_why=a.why if a else [],
                 download=r.dl_state)
        recent = [t for t in r.ticks if t[0] >= now - 10]
        secs = sum(t[1] for t in recent) or 1
        v["rate_down"] = sum(t[3] for t in recent) / secs
        v["rate_up"] = sum(t[2] for t in recent) / secs
        return v

    @app.get("/api/live")
    def live_all():
        if g.monitor is None:
            return {"devices": [], "monitor": False}
        names = names_map()
        devs = {d["device_id"]: d for d in g.db.list_devices()}
        out = []
        for did in list(g.monitor.live):
            lv = g.monitor.live_view(did)
            series = lv["series"]
            last = series[-5:]
            rate = sum(sum(v for k, v in p.items() if k != "ts") for p in last) / max(1, len(last))
            d = devs.get(did, {})
            out.append({"device_id": did, "label": names.get(did, did), "group": g.policy.group_name(did),
                        "headline": lv["now"]["headline"], "activity": lv["now"]["activity"],
                        "confidence": lv["now"]["confidence"], "rate": rate,
                        "spark": [round(sum(v for k, v in p.items() if k != "ts")) for p in series[-30:]],
                        "online": (d.get("last_seen") or 0) > time.time() - 300})
        out.sort(key=lambda x: -x["rate"])
        return {"devices": out, "monitor": True, "poll": g.monitor.poll}

    @app.get("/api/live/{device_id}")
    def live_device(device_id: str):
        if g.monitor is None:
            return {"series": [], "now": None, "classes": CLASSES, "flows": [], "monitor": False}
        names = names_map()
        now = time.time()
        lv = g.monitor.live_view(device_id)
        flows = [live_flow(r, names, now) for r in lv["flows"]]
        flows.sort(key=lambda f: -(f["rate_down"] + f["rate_up"]))
        return {"series": lv["series"], "now": lv["now"], "classes": CLASSES, "flows": flows[:60],
                "poll": lv["poll"], "monitor": True, "label": names.get(device_id, device_id)}

    # ------------------------------------------------------------ downloads
    def download_view(r, names):
        try:
            reasons = json.loads(r.get("reasons") or "[]")
        except ValueError:
            reasons = []
        return {**r, "reasons": reasons, "device": names.get(r["device_id"], r["client_ip"])}

    @app.get("/api/downloads")
    def downloads(status: str | None = None, limit: int = 200):
        names = names_map()
        rows = g.db.downloads(limit=min(limit, 1000), status=status)
        pending = g.db.downloads(limit=500, status="pending")
        return {"downloads": [download_view(r, names) for r in rows],
                "pending": [download_view(r, names) for r in pending],
                "policy": g.downloads.default_policy, "inline": g.downloads.inline}

    @app.post("/api/downloads/{rid}/approve")
    def approve_download(rid: int):
        r = g.downloads.approve(rid)
        if not r:
            raise HTTPException(404)
        for a in g.db.query("SELECT id FROM alerts WHERE kind IN ('download_held','video_held') AND device_id=? AND domain=? "
                            "AND review IS NULL", (r["device_id"], r["site"])):
            g.db.review_alert(a["id"], "fp")
        g.refresh_allowlist()
        return {"ok": True, "note": f"{r['site']} unblocked for this device - the download can be retried"}

    @app.post("/api/downloads/{rid}/deny")
    def deny_download(rid: int):
        r = g.downloads.deny(rid)
        if not r:
            raise HTTPException(404)
        if not r["site"].startswith("ip:"):
            g.db.add_rule("device", r["device_id"], r["site"], "block")
            g.policy.reload()
        for a in g.db.query("SELECT id FROM alerts WHERE kind IN ('download_held','video_held') AND device_id=? AND domain=? "
                            "AND review IS NULL", (r["device_id"], r["site"])):
            g.db.review_alert(a["id"], "tp")
        g.refresh_allowlist()
        return {"ok": True, "note": f"{r['site']} is now blocked for this device"}

    # ------------------------------------------------------------ health
    @app.get("/api/health")
    def health(days: int = 7):
        days = max(1, min(30, days))
        now = time.time()
        midnight = _midnight()
        since = midnight - (days - 1) * 86400
        devs = {d["device_id"]: d for d in devices_view()}
        rows = [r for r in g.db.alert_rows_since(since)
                if (r["category"] or KIND_META.get(r["kind"], ("info",))[0]) != "info"
                and r["review"] != "fp"]
        cats = [c for c in CATEGORIES if c != "info"]

        def day_index(ts):
            return int((ts - since) // 86400)

        per = {}
        hourly = {c: [0] * 24 for c in cats}
        daily = {c: [0] * days for c in cats}
        start24 = now - 86400
        for r in rows:
            cat = r["category"] or KIND_META.get(r["kind"], ("vpn",))[0]
            conf = r["confidence"] or 0
            daily[cat][min(days - 1, max(0, day_index(r["ts"])))] += r["count"]
            if r["ts"] >= start24:
                hourly[cat][min(23, int((r["ts"] - start24) // 3600))] += r["count"]
            did = r["device_id"]
            if not did:                     # gateway-level events (outages) live in the checks
                continue
            p = per.setdefault(did, {"attempts": 0, "today": 0, "kinds": set(), "strong_kinds": set(),
                                     "strong_attempts": 0, "max_conf": 0, "last": 0, "tamper": False,
                                     "by_cat": {c: 0 for c in cats}, "daily": [0] * days})
            p["attempts"] += r["count"]
            p["today"] += r["count"] if r["ts"] >= midnight else 0
            p["kinds"].add(r["kind"])
            p["by_cat"][cat] += r["count"]
            p["daily"][min(days - 1, max(0, day_index(r["ts"])))] += r["count"]
            p["max_conf"] = max(p["max_conf"], conf)
            p["last"] = max(p["last"], r["last_ts"])
            if conf >= 60:
                p["strong_kinds"].add(r["kind"])
                p["strong_attempts"] += r["count"]
            if cat == "tamper" and conf >= 70:
                p["tamper"] = True
        blocked = {}
        for b in g.db.blocked_by_device_day(since):
            blocked.setdefault(b["device_id"], [0] * days)
            i = min(days - 1, max(0, int(b["day_idx"])))
            blocked[b["device_id"]][i] += b["n"]

        def status(p):
            if p["tamper"]:
                return "tampering"
            if len(p["strong_kinds"]) >= 3 or p["strong_attempts"] >= 20:
                return "persistent"
            if p["max_conf"] >= 50:
                return "curious"
            return "clean"

        cards = []
        for did in set(per) | {d for d, v in devs.items() if v["filtered"]}:
            p = per.get(did)
            d = devs.get(did, {})
            bl = blocked.get(did, [0] * days)
            card = {"device_id": did, "label": d.get("label") or ("The gateway" if did == "gateway" else did),
                    "group": d.get("group"), "filtered": d.get("filtered", True), "online": d.get("online"),
                    "paused": d.get("paused"), "suspect": d.get("suspect"),
                    "blocked_today": bl[-1], "blocked_total": sum(bl), "blocked_daily": bl}
            if p:
                card.update(attempts=p["attempts"], attempts_today=p["today"], techniques=len(p["kinds"]),
                            max_confidence=p["max_conf"], last_attempt=p["last"], by_category=p["by_cat"],
                            daily=p["daily"], status=status(p))
            else:
                card.update(attempts=0, attempts_today=0, techniques=0, max_confidence=0, last_attempt=None,
                            by_category={c: 0 for c in cats}, daily=[0] * days, status="clean")
            if did != "gateway" and (card["attempts"] or card["blocked_total"]):
                card["top_blocked"] = g.db.top_blocked_domains(since, did, 5)
            cards.append(card)
        order = {"tampering": 0, "persistent": 1, "curious": 2, "clean": 3}
        cards.sort(key=lambda c: (order[c["status"]], -c["attempts"], -c["blocked_total"]))

        # ---- network checks
        st = g.status()
        checks = []

        def check(name, level, detail):
            checks.append({"name": name, "level": level, "detail": detail})
        check("Site filtering", "ok", f"{st['dns']['queries']:,} lookups answered since start")
        if g.mode == "gateway":
            gw = st.get("gateway") or {}
            ok = gw.get("applied") and gw.get("nfq_running")
            check("Firewall & inspector", "ok" if ok else "bad",
                  f"active ({gw.get('backend')}), {gw.get('nfq_handled', 0):,} packets inspected" if ok
                  else "NOT running - filtered devices have no web access (fail closed)")
            lw = st.get("lanwatch") or {}
            check("Tamper watch", "ok" if lw.get("running") else "bad",
                  "listening for ARP/DHCP/router spoofing" if lw.get("running")
                  else f"not running: {lw.get('error') or 'unknown'}")
        else:
            check("Enforcement", "warn", "Monitor mode: lookups are filtered, but nothing stops a device "
                                         "that skips this DNS. Use gateway mode on the Pi.")
        lu = st["lists"]["last_update"]
        failing = [src["source"] for v in st["lists"]["status"].values() for src in v["sources"]
                   if not src.get("ok") and src["source"].startswith("http")]
        if lu and now - lu < 48 * 3600 and not failing:
            check("Blocklists", "ok", f"updated {int((now - lu) // 3600)} h ago")
        else:
            check("Blocklists", "warn", ("some sources failed to download: " + ", ".join(
                f.split("/")[2] for f in failing[:4])) if failing else "not refreshed in the last 48 h")
        adults = [d for d in devs.values() if not d["filtered"]]
        check("Adult devices assigned", "ok" if adults else "warn",
              f"{len(adults)} device(s) unfiltered" if adults
              else "No device is in an unfiltered group yet - the dashboard is reachable from every device")
        tamper24 = [r for r in rows if (r["category"] == "tamper") and (r["confidence"] or 0) >= 70
                    and r["last_ts"] >= start24 and r["kind"] != "gateway_offline"]
        check("Tampering (24 h)", "bad" if tamper24 else "ok",
              f"{len(tamper24)} high-confidence tampering event(s)" if tamper24 else "none detected")
        offline = [r for r in rows if r["kind"] == "gateway_offline"]
        check("Gateway uptime", "warn" if offline else "ok",
              f"offline {len(offline)} time(s) in the last {days} days" if offline else
              f"no gaps in the last {days} days")
        pop = len(getattr(g.lists, "popular", ()) or ())
        check("Unknown-destination protection", "ok" if pop else "warn",
              f"{pop:,} popular sites known; heavy traffic elsewhere is held for review" if pop else
              "popularity list not downloaded yet - unknown destinations are only reported, not held")
        check("Behaviour detector", "ok" if st.get("detector") else "warn",
              "running" if st.get("detector") else "off (needs traffic accounting)")
        bad = sum(c["level"] == "bad" for c in checks)
        warn = sum(c["level"] == "warn" for c in checks)
        score = max(0, 100 - 25 * bad - 8 * warn)

        rev = g.db.review_stats()
        return {
            "days": days, "since": since, "score": score,
            "overall": "At risk" if bad else ("Needs attention" if warn else "Healthy"),
            "checks": checks, "devices": cards, "categories": {c: CATEGORIES[c] for c in cats},
            "hourly": hourly, "hourly_start": start24, "daily": daily,
            "totals": {c: sum(daily[c]) for c in cats},
            "reviews": {"reviewed": sum(r["reviewed"] for r in rev), "fp": sum(r["fp"] or 0 for r in rev),
                        "by_kind": [{"kind": r["kind"], "title": KINDS.get(r["kind"], (r["kind"],))[0],
                                     "reviewed": r["reviewed"], "fp": r["fp"] or 0} for r in rev]},
        }

    # ------------------------------------------------------------ guide
    @app.get("/api/setup-summary")
    def setup_summary():
        """The settings that matter, in words, for the Guide's 'Your setup' panel."""
        c = g.cfg
        a, d, tm = c.get("adult") or {}, c.get("downloads") or {}, c.get("tamper") or {}
        st = g.status()
        return {
            "mode": g.mode,
            "groups": [{"name": n, "filtered": gc["filtered"], "categories": gc.get("categories", []),
                        "protections": protections.effective(c, gc),
                        "adult": gc.get("adult_protection") or (a.get("mode") if gc["filtered"] else "off"),
                        "downloads": gc.get("downloads") or (d.get("policy") if gc["filtered"] else "off"),
                        "is_default": n == c["default_group"]}
                       for n, gc in c["groups"].items()],
            "adult": {"mode": a.get("mode"), "safesearch": a.get("safesearch"),
                      "youtube": a.get("youtube_restricted"), "family_dns": a.get("family_dns"),
                      "unknown_video": a.get("unknown_video")},
            "downloads": {"policy": d.get("policy"), "threshold": d.get("suspicious_score")},
            "tamper": {"auto_pause_minutes": tm.get("auto_pause_minutes"),
                       "auto_quarantine": tm.get("auto_quarantine_confidence")},
            "lists": {k.split(":", 1)[1]: v["entries"] for k, v in st["lists"]["status"].items()},
            "fail_open": c["enforcement"].get("fail_open"),
            "poll": c["flows"].get("poll_interval"),
        }

    def protections_defs():
        return [{"key": k, **v} for k, v in protections.PROTECTIONS.items()]

    # ------------------------------------------------------------ setup wizard
    def wizard_bedtime():
        try:
            return json.loads(g.db.get_setting("wizard_bedtime") or "null")
        except ValueError:
            return None

    @app.get("/api/wizard")
    def wizard(req: Request):
        from . import environment, settings
        g.db.flush()
        here_id = g.identity.device_id_for(client_ip(req))[0] if client_ip(req) else None   # look, don't register
        devs = [{"device_id": d["device_id"], "label": d["label"], "name": d["name"], "hostname": d["hostname"],
                 "ip": d["ip"], "mac": d["mac"], "group": d["group"], "group_set": d["group_set"],
                 "online": d["online"], "last_seen": d["last_seen"]} for d in devices_view()]
        return {
            "complete": g.db.get_setting("setup_complete") is not None,
            "mode": g.mode,
            "presets": settings.PRESETS,
            "protections": protections_defs(),
            "categories": [{"key": k, "label": v[0], "description": v[1], "default": v[2]}
                           for k, v in settings.CATEGORY_INFO.items() if k in (g.cfg.get("categories") or {})],
            "groups": [{"name": n, "filtered": gc["filtered"], "description": gc.get("description", "")}
                       for n, gc in g.cfg["groups"].items()],
            "values": settings.current(g.cfg),
            "bedtime": wizard_bedtime() or {"enabled": False, "start": "21:00", "end": "07:00",
                                            "days": "sun,mon,tue,wed,thu", "groups": ["kids"]},
            "environment": environment.detect(g.cfg, g),
            "address": localname.addresses(g.cfg, client_ip(req)),
            "devices": devs,
            "this_device": here_id,
            "this_ip": client_ip(req),
        }

    @app.post("/api/wizard/apply")
    async def wizard_apply(req: Request):
        from . import settings
        body = await req.json()
        try:
            result = settings.apply(g.cfg, body.get("values") or {})
        except (ValueError, TypeError) as e:
            raise HTTPException(400, str(e))
        g.db.flush()
        for d in body.get("devices") or []:
            did = d.get("device_id")
            if not did:
                continue
            if "name" in d:
                g.db.update_device(did, name=(d.get("name") or "").strip()[:60])
            if "group" in d:
                grp = d.get("group") or None
                if grp is not None and grp not in g.cfg["groups"]:
                    raise HTTPException(400, f"unknown group {grp}")
                g.policy.set_device_group(did, grp)
        bt = body.get("bedtime")
        if bt is not None:
            old = wizard_bedtime() or {}
            for sid in old.get("schedule_ids") or []:
                g.db.delete_schedule(sid)
            ids = []
            if bt.get("enabled"):
                if not (_TIME_RE.match(bt.get("start", "")) and _TIME_RE.match(bt.get("end", ""))):
                    raise HTTPException(400, "bedtime times must be HH:MM")
                days = ",".join(x for x in (bt.get("days") or "").split(",")
                                if x in ("mon", "tue", "wed", "thu", "fri", "sat", "sun")) or \
                    "mon,tue,wed,thu,fri,sat,sun"
                for grp in bt.get("groups") or ["kids"]:
                    if grp in g.cfg["groups"] and g.cfg["groups"][grp]["filtered"]:
                        g.db.add_schedule("group", grp, days, bt["start"], bt["end"])
                        ids.append(g.db.query_one("SELECT MAX(id) AS id FROM schedules")["id"])
                bt = {**bt, "days": days}
            g.db.set_setting("wizard_bedtime", json.dumps({**bt, "schedule_ids": ids}))
        g.reconfigure()
        if body.get("finish", True):
            g.db.set_setting("setup_complete", str(time.time()))
        return {"ok": True, **result}

    @app.get("/api/address")
    def address(req: Request):
        a = localname.addresses(g.cfg, client_ip(req))
        a["qr_svg"] = localname.qr_svg(a["qr_url"])
        a["mdns"] = g.mdns.status() if g.mdns is not None else None
        a["mode"] = g.mode
        return a

    # ------------------------------------------------------------ diagnostics
    @app.post("/api/diagnostics")
    async def diagnostics(req: Request):
        from starlette.concurrency import run_in_threadpool
        from .diagnostics import build
        b = await req.json()
        blob, name = await run_in_threadpool(
            build, g.cfg, g, include_alerts=bool(b.get("alerts", True)), include_activity=bool(b.get("activity", False)),
            anonymise=bool(b.get("anonymise", True)), note=str(b.get("note") or "")[:20000])
        print(f"[diagnostics] bundle downloaded ({len(blob) // 1024} KB, anonymised={bool(b.get('anonymise', True))})")
        return Response(blob, media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})

    # ------------------------------------------------------------ updates
    @app.get("/api/updates")
    def updates():
        return g.updater.status()

    @app.post("/api/updates/check")
    def updates_check():
        return g.updater.check(manual=True)

    @app.post("/api/updates/install")
    def updates_install():
        from .updater import UpdateError
        try:
            return g.updater.install(manual=True)
        except UpdateError as e:
            raise HTTPException(409, str(e))

    @app.post("/api/updates/rollback")
    def updates_rollback():
        from .updater import UpdateError
        try:
            return g.updater.rollback()
        except UpdateError as e:
            raise HTTPException(409, str(e))

    @app.post("/api/updates/settings")
    async def updates_settings(req: Request):
        from . import settings
        b = await req.json()
        keys = {"enabled": "updates_enabled", "auto_install": "updates_auto", "source": "updates_source",
                "branch": "updates_branch", "subdir": "updates_subdir"}
        try:
            settings.apply(g.cfg, {keys[k]: v for k, v in b.items() if k in keys})
        except (ValueError, TypeError) as e:
            raise HTTPException(400, str(e))
        return g.updater.status()

    @app.get("/api/protections")
    def get_protections():
        c = g.cfg
        return {"definitions": protections_defs(), "global": dict(c["protections"]),
                "groups": [{"name": n, "filtered": gc["filtered"],
                            "overrides": {k: v for k, v in (gc.get("protections") or {}).items() if v is not None},
                            "effective": protections.effective(c, gc)}
                           for n, gc in c["groups"].items()]}

    @app.post("/api/protections")
    async def set_protection(req: Request):
        from . import settings
        b = await req.json()
        key, scope, value = b.get("key"), b.get("group", "all"), b.get("value")
        try:
            if scope == "all":
                if value is None:
                    raise ValueError("choose a value for the house-wide setting")
                settings.apply(g.cfg, {"protections": {**g.cfg["protections"], key: value}})
            else:
                settings.set_group_protection(g.cfg, scope, key, value)
        except (ValueError, TypeError) as e:
            raise HTTPException(400, str(e))
        g.reconfigure()
        return {"ok": True, **get_protections()}

    @app.post("/api/wizard/skip")
    def wizard_skip():
        g.db.set_setting("setup_complete", str(time.time()))
        return {"ok": True}

    @app.post("/api/system/restart")
    def restart():
        g.restart()
        return {"ok": True, "message": "restarting - the dashboard will be back in a few seconds"}

    # ------------------------------------------------------------ system
    @app.get("/api/system")
    def system():
        return g.status()

    @app.post("/api/system/update-lists")
    def update_lists():
        if not g.lists.updating:
            import threading

            def run():
                g.lists.update()
                if g.gateway is not None:
                    g.gateway.sync_ip_sets()
            threading.Thread(target=run, daemon=True).start()
        return {"ok": True}

    return app
