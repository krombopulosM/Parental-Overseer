"""Dashboard login. On the Pi the dashboard is reachable from the LAN, so
without this a child could simply open it and unblock themselves."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time

ITERATIONS = 310_000
SESSION_HOURS = 12


class Auth:
    def __init__(self, db, on_fail=None):
        self.db = db
        self.on_fail = on_fail          # callable(ip, recent_failures)
        self._sessions: dict[str, float] = {}
        self._fails: dict[str, list] = {}
        self._lock = threading.Lock()
        self._load_sessions()

    # Sessions survive a restart (the setup wizard restarts the service). Only a
    # hash of each token is stored, so reading the database doesn't sign anyone in.
    @staticmethod
    def _h(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _load_sessions(self):
        try:
            saved = json.loads(self.db.get_setting("sessions") or "{}")
        except ValueError:
            saved = {}
        now = time.time()
        self._sessions = {k: float(v) for k, v in saved.items() if float(v) > now}

    def _save_sessions(self):
        now = time.time()
        live = {k: v for k, v in self._sessions.items() if v > now}
        self.db.set_setting("sessions", json.dumps(live))

    def has_password(self) -> bool:
        return bool(self.db.get_setting("admin_hash"))

    def set_password(self, password: str):
        if len(password or "") < 8:
            raise ValueError("password must be at least 8 characters")
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
        self.db.set_setting("admin_hash", f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}")
        with self._lock:
            self._sessions.clear()          # changing the password logs everyone out
            self._save_sessions()

    def verify(self, password: str) -> bool:
        stored = self.db.get_setting("admin_hash")
        if not stored:
            return False
        try:
            _, iters, salt, digest = stored.split("$")
            calc = hashlib.pbkdf2_hmac("sha256", (password or "").encode(), bytes.fromhex(salt), int(iters))
            return hmac.compare_digest(calc.hex(), digest)
        except ValueError:
            return False

    def locked_out(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            recent = [t for t in self._fails.get(ip, []) if now - t < 300]
            self._fails[ip] = recent
            return len(recent) >= 5

    def login(self, password: str, ip: str) -> str | None:
        if self.locked_out(ip):
            return None
        if not self.verify(password):
            with self._lock:
                self._fails.setdefault(ip, []).append(time.time())
                n = len([t for t in self._fails[ip] if time.time() - t < 300])
            if self.on_fail:
                self.on_fail(ip, n)
            return None
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[self._h(token)] = time.time() + SESSION_HOURS * 3600
            self._fails.pop(ip, None)
            self._save_sessions()
        return token

    def check(self, token: str | None) -> bool:
        if not token:
            return False
        with self._lock:
            key = self._h(token)
            exp = self._sessions.get(key)
            if exp is None or exp < time.time():
                self._sessions.pop(key, None)
                return False
            return True

    def logout(self, token: str | None):
        with self._lock:
            if self._sessions.pop(self._h(token or ""), None) is not None:
                self._save_sessions()
