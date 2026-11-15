"""Download guard: notice downloads, judge how suspicious they are, and hold
the suspicious ones for a parent to approve or deny.

How a download is noticed
  * HTTPS: a connection turns into a sustained, one-way, high-bandwidth
    transfer (see activity.py). The file itself is encrypted, so the decision
    rests on *where* it comes from and *who* is downloading it.
  * Plain HTTP: the request is readable, so the file name and extension are
    known before a single byte arrives, and a risky file is stopped up front.

What "hold" means
  The connection is cut, and that site is blocked for that device until you
  decide. Approve: the device can download from that site again (browsers can
  usually resume). Deny: the site stays blocked for that device.
"""
from __future__ import annotations

import json
import os
import posixpath
import threading
import time
import urllib.parse

from .services import is_ip_literal, registrable_domain, service_for, service_label

POLICIES = ("off", "review_suspicious", "review_all", "block_suspicious")


class DownloadGuard:
    def __init__(self, cfg, db, lists, alerts, kill_flow=None):
        d = cfg.get("downloads") or {}
        self.cfg, self.db, self.lists, self.alerts = cfg, db, lists, alerts
        self.default_policy = d.get("policy", "review_suspicious")
        self.min_bytes = int(d.get("min_bytes", 5_000_000))
        self.min_rate = float(d.get("min_rate", 200_000))
        self.threshold = int(d.get("suspicious_score", 50))
        self.risky = {e.lower().lstrip(".") for e in d.get("risky_extensions") or []}
        self.trusted = set(d.get("trusted_services") or [])
        self.inline = cfg.get("mode") == "gateway"
        self.kill_flow = kill_flow
        self.held: dict[tuple, int] = {}
        self.approved: set[tuple] = set()
        self._lock = threading.Lock()
        self.reload()

    # ------------------------------------------------------------ state
    def reload(self):
        if self.db is None:
            return
        held, approved = {}, set()
        for r in self.db.query("SELECT id, device_id, site, status FROM downloads "
                               "WHERE status IN ('pending', 'approved')"):
            key = (r["device_id"], r["site"])
            if r["status"] == "pending" and self.inline:
                held[key] = r["id"]
            elif r["status"] == "approved":
                approved.add(key)
        with self._lock:
            self.held, self.approved = held, approved

    def policy_for(self, group_cfg) -> str:
        p = (group_cfg or {}).get("downloads") or self.default_policy
        return p if p in POLICIES else "review_suspicious"

    @staticmethod
    def site_key(name: str | None, ip: str | None = None) -> str:
        if name:
            return registrable_domain(name) or name
        return f"ip:{ip}"

    def held_for(self, device_id: str, name: str | None) -> int | None:
        if not name:
            return None
        return self.held.get((device_id, self.site_key(name)))

    # ------------------------------------------------------------ scoring
    def score(self, device_id, name, *, http=False, filename=None, ip=None):
        reasons, score = [], 0
        site = self.site_key(name, ip)
        svc = service_for(name) if name else None
        trusted = svc in self.trusted
        cat = self.lists.category_match(name, ["torrent", "piracy", "filehost"]) if name else None
        if cat == "torrent":
            score += 60
            reasons.append("+60: a torrent site")
        elif cat:
            score += 55
            reasons.append("+55: a file-sharing, APK or cracked-software site")
        if not name or is_ip_literal(name or ""):
            score += 30
            reasons.append("+30: no site name, just an IP address")
        if http:
            score += 15
            reasons.append("+15: unencrypted (plain HTTP) download")
        ext = os.path.splitext(filename or "")[1].lower().lstrip(".")
        if ext and ext in self.risky:
            score += 40
            reasons.append(f"+40: a .{ext} file (programs, installers and archives can carry malware)")
        if name and not cat and not trusted and svc == registrable_domain(name):
            score += 10
            reasons.append(f"+10: {site} isn't a service the gateway recognises")
        if self.db is not None and name:
            first = self.db.domain_first_seen(registrable_domain(name))
            installed = float(self.db.get_meta("installed_at") or 0)
            learning = time.time() - installed < (self.cfg.get("detector") or {}).get("learning_days", 3) * 86400
            if not learning and (first is None or time.time() - first < 86400):
                score += 20
                reasons.append(f"+20: {site} was first seen on this network today")
            recent = [k for k in self.db.distinct_kinds_since(device_id, time.time() - 86400)
                      if k not in ("new_device", "download_held", "gateway_offline")]
            if recent:
                score += 10
                reasons.append("+10: this device tried to get around the filter in the last 24 h")
        if trusted:
            score -= 60
            reasons.append(f"-60: from {service_label(svc)}, a known app store / game / system service")
        return max(0, min(99, score)), reasons, trusted

    def _decide(self, policy, score, trusted) -> bool:
        if policy == "off":
            return False
        if policy == "review_all":
            return not trusted
        return score >= self.threshold

    # ------------------------------------------------------------ HTTPS downloads (from the flow monitor)
    def on_flow(self, rec, act, feat, group_cfg):
        if getattr(rec, "dl_state", None) is not None or act is None or act.cls != "download":
            return None
        if rec.bytes_down < self.min_bytes or feat.rate_down < self.min_rate:
            return None
        policy = self.policy_for(group_cfg)
        site = self.site_key(rec.domain, rec.dst_ip)
        if (rec.device_id, site) in self.approved:
            rec.dl_state = "approved"
            rec.flagged = True                 # behaviour detector: parent already OK'd this
            self._record(rec, site, None, 0, [], "approved earlier", "allowed")
            return "allowed"
        score, reasons, trusted = self.score(rec.device_id, rec.domain, http=rec.dst_port == 80,
                                             ip=rec.dst_ip)
        if not self._decide(policy, score, trusted):
            rec.dl_state = "allowed"
            self._record(rec, site, None, score, reasons, f"policy: {policy}", "allowed")
            return "allowed"
        rec.dl_state = "held"
        rec.flagged = True
        rid = self._hold(rec.device_id, rec.client_ip, site, rec.domain, rec.dst_ip, rec.dst_port,
                         None, rec.bytes_down, feat.rate_down, score, reasons, policy)
        if self.inline and self.kill_flow:
            self.kill_flow(rec.proto, rec.client_ip, rec.tuple[2], rec.dst_ip, rec.dst_port)
        return rid

    # ------------------------------------------------------------ plain-HTTP downloads (inline)
    def check_http(self, ctx, pkt, req):
        """Return a hold reason if this HTTP request fetches a risky file."""
        path = urllib.parse.urlsplit(req.target).path if req.target.startswith("/") else \
            urllib.parse.urlsplit(req.target).path
        filename = posixpath.basename(urllib.parse.unquote(path)) or None
        ext = os.path.splitext(filename or "")[1].lower().lstrip(".")
        if not ext or ext not in self.risky:
            return None
        policy = self.policy_for(ctx.g)
        site = self.site_key(req.host, pkt.dst)
        if (ctx.device_id, site) in self.approved:
            return None
        score, reasons, trusted = self.score(ctx.device_id, req.host, http=True, filename=filename, ip=pkt.dst)
        if not self._decide(policy, score, trusted):
            return None
        self._hold(ctx.device_id, ctx.ip, site, req.host, pkt.dst, pkt.dport, filename, 0, 0, score,
                   reasons, policy)
        return f"download of {filename} from {site} held for review"

    # ------------------------------------------------------------ records
    def _record(self, rec, site, filename, score, reasons, note, status):
        if self.db is None:
            return None
        return self.db.add_download({
            "device_id": rec.device_id, "client_ip": rec.client_ip, "site": site, "domain": rec.domain,
            "dst_ip": rec.dst_ip, "dst_port": rec.dst_port, "filename": filename,
            "bytes_seen": rec.bytes_down, "rate": 0, "score": score, "reasons": json.dumps(reasons),
            "status": status, "note": note})

    def _hold(self, device_id, client_ip, site, domain, dst_ip, dst_port, filename, nbytes, rate, score,
              reasons, policy):
        auto_deny = policy == "block_suspicious"
        status = "denied" if auto_deny else "pending"
        rid = None
        if self.db is not None:
            rid = self.db.add_download({
                "device_id": device_id, "client_ip": client_ip, "site": site, "domain": domain,
                "dst_ip": dst_ip, "dst_port": dst_port, "filename": filename, "bytes_seen": nbytes,
                "rate": rate, "score": score, "reasons": json.dumps(reasons), "status": status,
                "note": "monitor mode: not stopped" if not self.inline else policy})
        if self.inline:
            with self._lock:
                self.held[(device_id, site)] = rid or -1
        what = filename or f"a {nbytes / 1e6:.0f} MB file" if (filename or nbytes) else "a file"
        if not self.inline:
            action = "would hold (monitor mode)"
        elif auto_deny:
            action = "blocked (policy: block suspicious)"
        else:
            action = "held for your review"
        self.alerts.emit("download_held", device_id=device_id, client_ip=client_ip, dst=dst_ip,
                         domain=site, base=score, action=action,
                         detail=f"Downloading {what} from {site}. Suspicion {score}/100: " + "; ".join(reasons))
        return rid

    def _settle_others(self, r, status):
        """One decision covers every pending hold for that device + site."""
        for o in self.db.query("SELECT id FROM downloads WHERE device_id=? AND site=? AND status='pending' "
                               "AND id!=?", (r["device_id"], r["site"], r["id"])):
            self.db.update_download(o["id"], status=status)

    def approve(self, rid):
        r = self.db.get_download(rid)
        if not r:
            return None
        self.db.update_download(rid, status="approved")
        self._settle_others(r, "approved")
        with self._lock:
            self.held.pop((r["device_id"], r["site"]), None)
            self.approved.add((r["device_id"], r["site"]))
        return r

    def deny(self, rid):
        r = self.db.get_download(rid)
        if not r:
            return None
        self.db.update_download(rid, status="denied")
        self._settle_others(r, "denied")
        with self._lock:
            self.held.pop((r["device_id"], r["site"]), None)
        return r
