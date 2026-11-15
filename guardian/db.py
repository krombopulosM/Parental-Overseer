"""SQLite storage.

High-volume writes (DNS log, flow updates, usage buckets) go through a queue
that a background thread commits in batches, so a busy network never stalls a
DNS answer waiting on the SD card. Reads use their own connection (WAL mode
lets readers and the writer work at the same time).
"""
from __future__ import annotations

import queue
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS devices (
    device_id    TEXT PRIMARY KEY,      -- MAC address when known, otherwise IP
    mac          TEXT,
    ip           TEXT,
    name         TEXT,
    hostname     TEXT,
    group_name   TEXT,                  -- NULL = config default_group
    first_seen   REAL,
    last_seen    REAL,
    paused_until REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, device_id TEXT, client_ip TEXT NOT NULL,
    qname TEXT NOT NULL, qtype TEXT, action TEXT NOT NULL, reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_queries_dev ON queries(device_id, ts);
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_key TEXT UNIQUE, device_id TEXT, client_ip TEXT, proto TEXT,
    dst_ip TEXT, dst_port INTEGER, domain TEXT, domain_src TEXT, service TEXT, ja4 TEXT,
    verdict TEXT, reason TEXT,
    start REAL, last REAL, ended INTEGER DEFAULT 0,
    bytes_up INTEGER DEFAULT 0, bytes_down INTEGER DEFAULT 0,
    pkts_up INTEGER DEFAULT 0, pkts_down INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_flows_start ON flows(start);
CREATE INDEX IF NOT EXISTS idx_flows_dev ON flows(device_id, start);
CREATE TABLE IF NOT EXISTS usage (
    device_id TEXT, service TEXT, minute INTEGER,
    bytes_up INTEGER DEFAULT 0, bytes_down INTEGER DEFAULT 0,
    PRIMARY KEY (device_id, service, minute)
);
CREATE INDEX IF NOT EXISTS idx_usage_minute ON usage(minute);
CREATE TABLE IF NOT EXISTS domains_seen (domain TEXT PRIMARY KEY, first_seen REAL);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, last_ts REAL, count INTEGER DEFAULT 1,
    device_id TEXT, client_ip TEXT, kind TEXT, severity TEXT,
    detail TEXT, dst TEXT, domain TEXT, action TEXT, acknowledged INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(last_ts);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL, target TEXT, pattern TEXT NOT NULL, action TEXT NOT NULL, created REAL
);
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL, target TEXT, days TEXT NOT NULL,
    start TEXT NOT NULL, "end" TEXT NOT NULL, enabled INTEGER DEFAULT 1, created REAL
);
CREATE TABLE IF NOT EXISTS dyn_blocks (
    ip TEXT PRIMARY KEY, reason TEXT, device_id TEXT, created REAL, expires REAL
);
CREATE TABLE IF NOT EXISTS allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, value TEXT, note TEXT, created REAL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
"""

_FLOW_UPSERT = """
INSERT INTO flows (flow_key, device_id, client_ip, proto, dst_ip, dst_port, domain, domain_src,
                   service, ja4, verdict, reason, start, last, ended,
                   bytes_up, bytes_down, pkts_up, pkts_down)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(flow_key) DO UPDATE SET
    domain=COALESCE(excluded.domain, flows.domain),
    domain_src=COALESCE(excluded.domain_src, flows.domain_src),
    service=COALESCE(excluded.service, flows.service),
    ja4=COALESCE(excluded.ja4, flows.ja4),
    verdict=COALESCE(excluded.verdict, flows.verdict),
    reason=COALESCE(excluded.reason, flows.reason),
    last=excluded.last, ended=excluded.ended,
    bytes_up=excluded.bytes_up, bytes_down=excluded.bytes_down,
    pkts_up=excluded.pkts_up, pkts_down=excluded.pkts_down
"""

_USAGE_UPSERT = """
INSERT INTO usage (device_id, service, minute, bytes_up, bytes_down) VALUES (?,?,?,?,?)
ON CONFLICT(device_id, service, minute) DO UPDATE SET
    bytes_up = usage.bytes_up + excluded.bytes_up,
    bytes_down = usage.bytes_down + excluded.bytes_down
"""


class DB:
    def __init__(self, path: str):
        self.path = path
        self._wlock = threading.RLock()
        self._rlock = threading.Lock()
        self._w = sqlite3.connect(path, check_same_thread=False)
        self._w.row_factory = sqlite3.Row
        self._w.execute("PRAGMA journal_mode=WAL")
        self._w.execute("PRAGMA synchronous=NORMAL")
        self._migrate()
        self._w.executescript(SCHEMA)
        self._w.commit()
        self._r = sqlite3.connect(path, check_same_thread=False)
        self._r.row_factory = sqlite3.Row
        self._q: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._writer = threading.Thread(target=self._writer_loop, name="db-writer", daemon=True)
        self._writer.start()
        if self.get_meta("installed_at") is None:
            self.set_meta("installed_at", str(time.time()))

    # ------------------------------------------------------------- plumbing
    def _migrate(self):
        qcols = {r[1] for r in self._w.execute("PRAGMA table_info(queries)")}
        if qcols and "device_id" not in qcols:       # must exist before SCHEMA indexes it
            self._w.execute("ALTER TABLE queries ADD COLUMN device_id TEXT")
        cols = {r[1] for r in self._w.execute("PRAGMA table_info(devices)")}
        if cols and "device_id" not in cols:          # Phase 1 schema (keyed by IP)
            self._w.execute("ALTER TABLE devices RENAME TO devices_v1")
            self._w.executescript(SCHEMA)
            self._w.execute(
                "INSERT INTO devices (device_id, ip, name, group_name, first_seen, last_seen) "
                "SELECT ip, ip, name, CASE WHEN group_name='default' THEN NULL ELSE group_name END, "
                "first_seen, last_seen FROM devices_v1")
            self._w.execute("DROP TABLE devices_v1")
        self._w.commit()

    def _writer_loop(self):
        while not self._stop.is_set():
            try:
                first = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            batch = [first]
            while len(batch) < 2000:
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break
            with self._wlock:
                try:
                    for sql, params in batch:
                        self._w.execute(sql, params)
                    self._w.commit()
                except Exception as e:  # never let one bad row kill logging
                    print(f"[db] write batch failed: {e}")
                    self._w.rollback()
            for _ in batch:
                self._q.task_done()

    def enqueue(self, sql: str, params: tuple):
        self._q.put((sql, params))

    def flush(self, timeout: float = 5.0):
        """Wait until queued writes are committed (used by tests and shutdown)."""
        end = time.time() + timeout
        while self._q.unfinished_tasks and time.time() < end:   # queued *or* being written
            time.sleep(0.02)

    def execute(self, sql: str, params: tuple = ()):
        with self._wlock:
            cur = self._w.execute(sql, params)
            self._w.commit()
            return cur

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._rlock:
            return [dict(r) for r in self._r.execute(sql, params).fetchall()]

    def query_one(self, sql: str, params: tuple = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def close(self):
        self.flush()
        self._stop.set()

    # ------------------------------------------------------------- meta/settings
    def get_meta(self, key):
        r = self.query_one("SELECT value FROM meta WHERE key=?", (key,))
        return r["value"] if r else None

    def set_meta(self, key, value):
        self.execute("INSERT INTO meta (key, value) VALUES (?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def get_setting(self, key, default=None):
        r = self.query_one("SELECT value FROM settings WHERE key=?", (key,))
        return r["value"] if r else default

    def set_setting(self, key, value):
        self.execute("INSERT INTO settings (key, value) VALUES (?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # ------------------------------------------------------------- devices
    def upsert_device_seen(self, device_id, mac, ip, hostname=None):
        now = time.time()
        self.enqueue(
            "INSERT INTO devices (device_id, mac, ip, hostname, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET "
            "ip=excluded.ip, mac=COALESCE(excluded.mac, devices.mac), "
            "hostname=COALESCE(excluded.hostname, devices.hostname), last_seen=excluded.last_seen",
            (device_id, mac, ip, hostname, now, now))

    def get_device(self, device_id):
        return self.query_one("SELECT * FROM devices WHERE device_id=?", (device_id,))

    def list_devices(self):
        return self.query("SELECT * FROM devices ORDER BY last_seen DESC")

    def update_device(self, device_id, name=None, group=None, set_group=False):
        now = time.time()
        self.execute("INSERT INTO devices (device_id, first_seen, last_seen) VALUES (?,?,?) "
                     "ON CONFLICT(device_id) DO NOTHING", (device_id, now, now))
        if name is not None:
            self.execute("UPDATE devices SET name=? WHERE device_id=?", (name or None, device_id))
        if set_group:
            self.execute("UPDATE devices SET group_name=? WHERE device_id=?", (group, device_id))

    def adopt_ip_device(self, ip: str, mac: str) -> bool:
        """A device first seen before its MAC was known was stored under its IP.
        Fold that record (name, group, history) into the MAC-keyed device."""
        self.flush()
        with self._wlock:
            old = self._w.execute("SELECT * FROM devices WHERE device_id=? AND mac IS NULL", (ip,)).fetchone()
            if not old:
                return False
            if self._w.execute("SELECT 1 FROM devices WHERE device_id=?", (mac,)).fetchone():
                self._w.execute("UPDATE devices SET name=COALESCE(name, ?), group_name=COALESCE(group_name, ?), "
                                "first_seen=MIN(first_seen, ?) WHERE device_id=?",
                                (old["name"], old["group_name"], old["first_seen"], mac))
                self._w.execute("DELETE FROM devices WHERE device_id=?", (ip,))
            else:
                self._w.execute("UPDATE devices SET device_id=?, mac=? WHERE device_id=?", (mac, mac, ip))
            for table in ("queries", "flows", "alerts"):
                self._w.execute(f"UPDATE {table} SET device_id=? WHERE device_id=?", (mac, ip))
            self._w.execute("UPDATE OR IGNORE usage SET device_id=? WHERE device_id=?", (mac, ip))
            self._w.execute("DELETE FROM usage WHERE device_id=?", (ip,))
            self._w.commit()
            return True

    def set_paused_until(self, device_id, until):
        self.execute("UPDATE devices SET paused_until=? WHERE device_id=?", (until, device_id))

    # ------------------------------------------------------------- DNS log
    def log_query(self, device_id, client_ip, qname, qtype, action, reason):
        self.enqueue("INSERT INTO queries (ts, device_id, client_ip, qname, qtype, action, reason) "
                     "VALUES (?,?,?,?,?,?,?)",
                     (time.time(), device_id, client_ip, qname, qtype, action, reason))

    def note_domain_seen(self, domain):
        self.enqueue("INSERT OR IGNORE INTO domains_seen (domain, first_seen) VALUES (?,?)",
                     (domain, time.time()))

    def domain_first_seen(self, domain):
        r = self.query_one("SELECT first_seen FROM domains_seen WHERE domain=?", (domain,))
        return r["first_seen"] if r else None

    def recent_queries(self, limit=100, device_id=None, blocked_only=False):
        where, params = [], []
        if device_id:
            where.append("device_id=?")
            params.append(device_id)
        if blocked_only:
            where.append("action='blocked'")
        sql = "SELECT * FROM queries"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return self.query(sql, tuple(params))

    def query_counts(self, since, device_id=None):
        sql = ("SELECT COUNT(*) AS total, SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) "
               "AS blocked FROM queries WHERE ts>=?")
        params = [since]
        if device_id:
            sql += " AND device_id=?"
            params.append(device_id)
        r = self.query_one(sql, tuple(params))
        return {"total": r["total"] or 0, "blocked": r["blocked"] or 0}

    def per_device_query_counts(self, since):
        return {r["device_id"]: r for r in self.query(
            "SELECT device_id, COUNT(*) AS queries, "
            "SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked "
            "FROM queries WHERE ts>=? GROUP BY device_id", (since,))}

    # ------------------------------------------------------------- flows/usage
    def upsert_flow(self, f: dict):
        self.enqueue(_FLOW_UPSERT, (
            f["flow_key"], f["device_id"], f["client_ip"], f["proto"], f["dst_ip"], f["dst_port"],
            f.get("domain"), f.get("domain_src"), f.get("service"), f.get("ja4"),
            f.get("verdict"), f.get("reason"), f["start"], f["last"], int(f.get("ended", 0)),
            f["bytes_up"], f["bytes_down"], f["pkts_up"], f["pkts_down"]))

    def add_usage(self, device_id, service, minute, up, down):
        self.enqueue(_USAGE_UPSERT, (device_id, service, minute, up, down))

    def flows(self, since=0, device_id=None, active_only=False, limit=200):
        where, params = ["last>=?"], [since]
        if device_id:
            where.append("device_id=?")
            params.append(device_id)
        if active_only:
            where.append("ended=0")
        params.append(limit)
        return self.query(f"SELECT * FROM flows WHERE {' AND '.join(where)} "
                          "ORDER BY last DESC LIMIT ?", tuple(params))

    def usage_by_service(self, since_minute, active_bytes, device_id=None, limit=50):
        sql = ("SELECT service, SUM(CASE WHEN bytes_up+bytes_down>=? THEN 1 ELSE 0 END) AS minutes, "
               "SUM(bytes_up) AS bytes_up, SUM(bytes_down) AS bytes_down FROM usage WHERE minute>=?")
        params = [active_bytes, since_minute]
        if device_id:
            sql += " AND device_id=?"
            params.append(device_id)
        sql += " GROUP BY service ORDER BY minutes DESC, bytes_down DESC LIMIT ?"
        params.append(limit)
        return self.query(sql, tuple(params))

    def online_minutes(self, since_minute, active_bytes):
        return {r["device_id"]: r for r in self.query(
            "SELECT device_id, COUNT(*) AS minutes, SUM(up) AS bytes_up, SUM(down) AS bytes_down FROM "
            "(SELECT device_id, minute, SUM(bytes_up) AS up, SUM(bytes_down) AS down FROM usage "
            " WHERE minute>=? GROUP BY device_id, minute) "
            "WHERE up+down>=? GROUP BY device_id", (since_minute, active_bytes))}

    def data_totals(self, since_minute):
        return {r["device_id"]: r for r in self.query(
            "SELECT device_id, SUM(bytes_up) AS bytes_up, SUM(bytes_down) AS bytes_down "
            "FROM usage WHERE minute>=? GROUP BY device_id", (since_minute,))}

    # ------------------------------------------------------------- alerts
    def upsert_alert(self, a: dict, dedupe_window: float):
        now = time.time()
        with self._wlock:
            row = self._w.execute(
                "SELECT id FROM alerts WHERE device_id IS ? AND kind=? AND dst IS ? AND domain IS ? "
                "AND last_ts>=? ORDER BY id DESC LIMIT 1",
                (a.get("device_id"), a["kind"], a.get("dst"), a.get("domain"),
                 now - dedupe_window)).fetchone()
            if row:
                self._w.execute("UPDATE alerts SET last_ts=?, count=count+1, detail=?, action=? "
                                "WHERE id=?", (now, a.get("detail"), a.get("action"), row["id"]))
                self._w.commit()
                return row["id"], False
            cur = self._w.execute(
                "INSERT INTO alerts (ts, last_ts, count, device_id, client_ip, kind, severity, detail, "
                "dst, domain, action) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (now, now, 1, a.get("device_id"), a.get("client_ip"), a["kind"], a.get("severity"),
                 a.get("detail"), a.get("dst"), a.get("domain"), a.get("action")))
            self._w.commit()
            return cur.lastrowid, True

    def alerts(self, since=0, limit=100, unacked_only=False, device_id=None):
        where, params = ["last_ts>=?"], [since]
        if unacked_only:
            where.append("acknowledged=0")
        if device_id:
            where.append("device_id=?")
            params.append(device_id)
        params.append(limit)
        return self.query(f"SELECT * FROM alerts WHERE {' AND '.join(where)} "
                          "ORDER BY last_ts DESC LIMIT ?", tuple(params))

    def get_alert(self, alert_id):
        return self.query_one("SELECT * FROM alerts WHERE id=?", (alert_id,))

    def ack_alert(self, alert_id):
        self.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))

    # ------------------------------------------------------------- rules
    def add_rule(self, scope, target, pattern, action):
        self.execute("INSERT INTO rules (scope, target, pattern, action, created) VALUES (?,?,?,?,?)",
                     (scope, target, pattern.lower().strip().rstrip("."), action, time.time()))

    def delete_rule(self, rule_id):
        self.execute("DELETE FROM rules WHERE id=?", (rule_id,))

    def list_rules(self):
        return self.query("SELECT * FROM rules ORDER BY id DESC")

    # ------------------------------------------------------------- schedules
    def add_schedule(self, scope, target, days, start, end):
        self.execute('INSERT INTO schedules (scope, target, days, start, "end", created) '
                     "VALUES (?,?,?,?,?,?)", (scope, target, days, start, end, time.time()))

    def delete_schedule(self, sid):
        self.execute("DELETE FROM schedules WHERE id=?", (sid,))

    def list_schedules(self):
        return self.query("SELECT * FROM schedules ORDER BY id")

    # ------------------------------------------------------------- dynamic blocks / allowlist
    def add_dyn_block(self, ip, reason, device_id, expires):
        self.execute("INSERT INTO dyn_blocks (ip, reason, device_id, created, expires) VALUES (?,?,?,?,?) "
                     "ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, expires=excluded.expires",
                     (ip, reason, device_id, time.time(), expires))

    def remove_dyn_block(self, ip):
        self.execute("DELETE FROM dyn_blocks WHERE ip=?", (ip,))

    def dyn_blocks(self):
        return self.query("SELECT * FROM dyn_blocks WHERE expires>? ORDER BY created DESC",
                          (time.time(),))

    def add_allow(self, kind, value, note=""):
        if not self.query_one("SELECT id FROM allowlist WHERE kind=? AND value=?", (kind, value)):
            self.execute("INSERT INTO allowlist (kind, value, note, created) VALUES (?,?,?,?)",
                         (kind, value, note, time.time()))

    def allowlist(self):
        return self.query("SELECT * FROM allowlist ORDER BY id DESC")

    def delete_allow(self, aid):
        self.execute("DELETE FROM allowlist WHERE id=?", (aid,))

    # ------------------------------------------------------------- housekeeping
    def prune(self, retention_days):
        cutoff = time.time() - retention_days * 86400
        self.enqueue("DELETE FROM queries WHERE ts<?", (cutoff,))
        self.enqueue("DELETE FROM flows WHERE last<?", (cutoff,))
        self.enqueue("DELETE FROM usage WHERE minute<?", (int(cutoff // 60) - 60 * 24 * 60,))
        self.enqueue("DELETE FROM alerts WHERE last_ts<?", (cutoff,))
        self.enqueue("DELETE FROM dyn_blocks WHERE expires<?", (time.time(),))
