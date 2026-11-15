"""SQLite storage: devices, DNS query log, and filtering rules.

One connection shared across the DNS server threads and the web app, guarded
by a lock. SQLite is plenty for a home network's query volume.
"""
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    ip          TEXT PRIMARY KEY,
    name        TEXT,
    group_name  TEXT NOT NULL DEFAULT 'default',
    first_seen  REAL,
    last_seen   REAL
);
CREATE TABLE IF NOT EXISTS queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    client_ip   TEXT NOT NULL,
    qname       TEXT NOT NULL,
    qtype       TEXT,
    action      TEXT NOT NULL,          -- allowed | blocked
    reason      TEXT
);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_queries_client ON queries(client_ip);
CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL,          -- global | group | device
    target      TEXT,                   -- group name or device ip; NULL for global
    pattern     TEXT NOT NULL,
    action      TEXT NOT NULL,          -- block | allow
    created     REAL
);
"""


class DB:
    def __init__(self, path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # ----- devices -----
    def touch_device(self, ip):
        now = time.time()
        with self._lock:
            cur = self._conn.execute("SELECT ip FROM devices WHERE ip=?", (ip,))
            if cur.fetchone():
                self._conn.execute("UPDATE devices SET last_seen=? WHERE ip=?", (now, ip))
            else:
                self._conn.execute(
                    "INSERT INTO devices (ip, name, group_name, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?)", (ip, None, "default", now, now))
            self._conn.commit()

    def get_group(self, ip):
        with self._lock:
            row = self._conn.execute(
                "SELECT group_name FROM devices WHERE ip=?", (ip,)).fetchone()
            return row["group_name"] if row else "default"

    def set_device(self, ip, name=None, group=None):
        now = time.time()
        with self._lock:
            exists = self._conn.execute(
                "SELECT ip FROM devices WHERE ip=?", (ip,)).fetchone()
            if not exists:
                self._conn.execute(
                    "INSERT INTO devices (ip, name, group_name, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?)", (ip, name, group or "default", now, now))
            else:
                if name is not None:
                    self._conn.execute("UPDATE devices SET name=? WHERE ip=?", (name, ip))
                if group is not None:
                    self._conn.execute("UPDATE devices SET group_name=? WHERE ip=?", (group, ip))
            self._conn.commit()

    def list_devices(self):
        with self._lock:
            cur = self._conn.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            return [dict(r) for r in cur.fetchall()]

    # ----- query log -----
    def log_query(self, client_ip, qname, qtype, action, reason):
        with self._lock:
            self._conn.execute(
                "INSERT INTO queries (ts, client_ip, qname, qtype, action, reason) "
                "VALUES (?,?,?,?,?,?)",
                (time.time(), client_ip, qname, qtype, action, reason))
            self._conn.commit()

    def recent_queries(self, limit=100, client_ip=None):
        with self._lock:
            if client_ip:
                cur = self._conn.execute(
                    "SELECT * FROM queries WHERE client_ip=? ORDER BY id DESC LIMIT ?",
                    (client_ip, limit))
            else:
                cur = self._conn.execute(
                    "SELECT * FROM queries ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]

    def top_domains(self, since, limit=20):
        with self._lock:
            cur = self._conn.execute(
                "SELECT qname, COUNT(*) AS hits, "
                "SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked "
                "FROM queries WHERE ts>=? GROUP BY qname ORDER BY hits DESC LIMIT ?",
                (since, limit))
            return [dict(r) for r in cur.fetchall()]

    def device_activity(self, since):
        with self._lock:
            cur = self._conn.execute(
                "SELECT client_ip, COUNT(*) AS queries, "
                "SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked, MAX(ts) AS last "
                "FROM queries WHERE ts>=? GROUP BY client_ip ORDER BY queries DESC",
                (since,))
            return [dict(r) for r in cur.fetchall()]

    def counts(self, since):
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) AS blocked "
                "FROM queries WHERE ts>=?", (since,)).fetchone()
            return {"total": row["total"] or 0, "blocked": row["blocked"] or 0}

    # ----- rules -----
    def add_rule(self, scope, target, pattern, action):
        with self._lock:
            self._conn.execute(
                "INSERT INTO rules (scope, target, pattern, action, created) VALUES (?,?,?,?,?)",
                (scope, target, pattern.lower().strip().rstrip("."), action, time.time()))
            self._conn.commit()

    def delete_rule(self, rule_id):
        with self._lock:
            self._conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))
            self._conn.commit()

    def list_rules(self):
        with self._lock:
            cur = self._conn.execute("SELECT * FROM rules ORDER BY id DESC")
            return [dict(r) for r in cur.fetchall()]

    def rules_for(self, ip, group):
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM rules WHERE scope='global' "
                "OR (scope='group' AND target=?) OR (scope='device' AND target=?)",
                (group, ip))
            return [dict(r) for r in cur.fetchall()]
