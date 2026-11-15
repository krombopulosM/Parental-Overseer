"""Internet-off times: manual pauses ("pause for 1 hour") and recurring
schedules ("kids group: 21:00-07:00 on school nights")."""
from __future__ import annotations

import datetime as dt
import threading
import time

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _hm(s: str) -> int:
    h, m = s.strip().split(":")
    return int(h) * 60 + int(m)


def window_active(days: str, start: str, end: str, when: dt.datetime) -> bool:
    day_list = [d.strip().lower()[:3] for d in days.split(",") if d.strip()]
    if not day_list or "all" in day_list or "dai" in day_list:
        day_list = DAYS
    s, e = _hm(start), _hm(end)
    now = when.hour * 60 + when.minute
    today = DAYS[when.weekday()]
    yesterday = DAYS[(when.weekday() - 1) % 7]
    if s == e:
        return today in day_list
    if s < e:
        return today in day_list and s <= now < e
    # overnight window, e.g. 21:00-07:00
    return (today in day_list and now >= s) or (yesterday in day_list and now < e)


class Scheduler:
    def __init__(self, db, policy):
        self.db = db
        self.policy = policy
        self._schedules: list[dict] = []
        self._paused: dict[str, float] = {}
        self._lock = threading.Lock()
        self.reload()

    def reload(self):
        scheds = self.db.list_schedules()
        paused = {d["device_id"]: d["paused_until"] or 0 for d in self.db.list_devices()
                  if (d.get("paused_until") or 0) > time.time()}
        with self._lock:
            self._schedules = scheds
            self._paused = paused

    def pause(self, device_id: str, minutes: float):
        until = time.time() + minutes * 60 if minutes > 0 else 0
        self.db.set_paused_until(device_id, until)
        self.reload()
        return until

    def is_paused(self, device_id: str, group: str, now: float | None = None):
        now = now or time.time()
        with self._lock:
            until = self._paused.get(device_id, 0)
            scheds = list(self._schedules)
        if until > now:
            return True, "paused until " + time.strftime("%H:%M", time.localtime(until))
        when = dt.datetime.fromtimestamp(now)
        for s in scheds:
            if not s.get("enabled", 1):
                continue
            applies = (s["scope"] == "group" and s["target"] == group) or \
                      (s["scope"] == "device" and s["target"] == device_id) or s["scope"] == "all"
            if applies and window_active(s["days"], s["start"], s["end"], when):
                return True, f"scheduled off {s['start']}-{s['end']}"
        return False, ""
