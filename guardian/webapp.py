"""FastAPI dashboard + JSON API. Reads/writes the same SQLite DB the resolver uses."""
import os
import time

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse


def create_app(db, policy, cfg):
    app = FastAPI(title="Parental Gateway")
    static_dir = os.path.join(cfg["__base__"], "guardian", "static")

    @app.get("/", response_class=HTMLResponse)
    def index():
        with open(os.path.join(static_dir, "index.html"), "r", encoding="utf-8") as fh:
            return fh.read()

    @app.get("/api/overview")
    def overview(window: int = 86400):
        since = time.time() - window
        return {
            "counts": db.counts(since),
            "devices": _devices(db, since),
            "top_domains": db.top_domains(since, 25),
            "recent": db.recent_queries(60),
            "server_time": time.time(),
        }

    @app.get("/api/device/{ip}")
    def device(ip: str):
        return {"ip": ip, "recent": db.recent_queries(200, client_ip=ip)}

    @app.post("/api/device")
    async def update_device(req: Request):
        body = await req.json()
        db.set_device(body["ip"], body.get("name"), body.get("group"))
        return {"ok": True}

    @app.get("/api/rules")
    def rules():
        return {"rules": db.list_rules()}

    @app.post("/api/rules")
    async def add_rule(req: Request):
        body = await req.json()
        db.add_rule(body.get("scope", "global"), body.get("target"),
                    body["pattern"], body.get("action", "block"))
        return {"ok": True}

    @app.delete("/api/rules/{rule_id}")
    def delete_rule(rule_id: int):
        db.delete_rule(rule_id)
        return {"ok": True}

    return app


def _devices(db, since):
    meta = {d["ip"]: d for d in db.list_devices()}
    out, seen = [], set()
    for act in db.device_activity(since):
        ip = act["client_ip"]
        m = meta.get(ip, {})
        out.append({"ip": ip, "name": m.get("name"),
                    "group": m.get("group_name", "default"),
                    "queries": act["queries"], "blocked": act["blocked"] or 0,
                    "last": act["last"]})
        seen.add(ip)
    for ip, m in meta.items():                    # known but quiet in this window
        if ip not in seen:
            out.append({"ip": ip, "name": m.get("name"),
                        "group": m.get("group_name", "default"),
                        "queries": 0, "blocked": 0, "last": m.get("last_seen")})
    return out
