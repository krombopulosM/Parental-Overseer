"""Dashboard web app + JSON API."""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import time

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse

from .alerts import KINDS
from .auth import Auth
from .services import registrable_domain, service_label

COOKIE = "pg_session"
_DOMAIN_RE = re.compile(r"^[a-z0-9*_.-]+\.[a-z0-9-]+$")
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_PUBLIC = {"/", "/static/app.js", "/static/style.css", "/api/session", "/api/login", "/api/setup"}


def _midnight() -> float:
    now = dt.datetime.now()
    return dt.datetime(now.year, now.month, now.day).timestamp()


def create_app(g) -> FastAPI:
    """g is the Guardian orchestrator."""
    app = FastAPI(title="Parental Gateway", docs_url=None, redoc_url=None, openapi_url=None)
    auth = Auth(g.db)
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
        if name not in ("app.js", "style.css"):
            raise HTTPException(404)
        return FileResponse(os.path.join(static, name), headers={"Cache-Control": "no-store"})

    @app.get("/api/session")
    def session(req: Request):
        ip = client_ip(req)
        local = ip in ("127.0.0.1", "::1")
        return {"authenticated": auth.check(req.cookies.get(COOKIE)),
                "needs_setup": not auth.has_password(), "setup_allowed": local,
                "mode": g.mode}

    @app.post("/api/setup")
    async def setup(req: Request, resp: Response):
        if auth.has_password():
            raise HTTPException(409, "already set up")
        if client_ip(req) not in ("127.0.0.1", "::1"):
            raise HTTPException(403, "first-time setup must be done on the gateway itself "
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
                "paused": paused, "paused_reason": why,
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
        return {**a, "title": KINDS.get(a["kind"], (a["kind"],))[0],
                "device": names.get(a["device_id"], a["client_ip"])}

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
    def devices():
        return {"devices": devices_view()}

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
        return {
            "device": view,
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
                "dyn_blocks": g.db.dyn_blocks()}

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
