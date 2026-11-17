"""The supervisor: the long-lived process the system service runs.

It starts the gateway (a "worker"), and when an update, a rollback or a settings
restart is wanted, it switches workers without a gap:

  1. start the new worker alongside the old one, on the other packet queue;
  2. the new worker shares the DNS and dashboard ports, binds its queue, swaps
     the firewall over to itself in one atomic step, and says "ready";
  3. only then is the old worker asked to finish up (it drains what's already
     queued to it and exits) - the new one takes over its once-only jobs.

If the new worker never becomes ready, the old one takes the firewall back and
the new one is stopped: the update is abandoned and nothing changed. If a newly
installed version keeps crashing, the supervisor goes back to the previous one.

After switching to a new version the supervisor re-launches itself from that
version's code (the running worker stays its child), so the supervisor is
updated too.

Only the standard library is used here, so it runs before anything else is
installed and survives a broken update.
"""
from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import time

# Signals held across a re-launch. SIGUSR1 only exists on Linux/macOS - the
# supervisor itself only runs there, but this module is imported everywhere.
_HELD = {s for s in (getattr(signal, n, None) for n in ("SIGTERM", "SIGINT", "SIGUSR1")) if s is not None}
SUPPORTED = hasattr(signal, "SIGUSR1") and hasattr(os, "WNOHANG")
READY_TIMEOUT = 120          # a Raspberry Pi loading big lists can take a while
STOP_TIMEOUT = 25
CRASH_WINDOW = 600           # a new version crashing twice within this is rolled back


# ------------------------------------------------------------------ helpers (also used by the worker)
def under_supervisor() -> bool:
    return bool(os.environ.get("GUARDIAN_SUPERVISOR_PID"))


def data_dir_of(cfg: dict | None = None) -> str:
    if cfg is not None:
        return cfg.get("__data__") or cfg["__base__"]
    return os.environ["GUARDIAN_DATA_DIR"]


def _write_json(path: str, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1)
    os.replace(tmp, path)


def _read_json(path: str, default=None):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def request_switch(cfg: dict, release_dir: str | None, reason: str) -> bool:
    """Ask the supervisor to switch to release_dir (None: the running one)."""
    pid = int(os.environ.get("GUARDIAN_SUPERVISOR_PID") or 0)
    if not pid:
        return False
    d = data_dir_of(cfg)
    _write_json(os.path.join(d, "switch-request.json"),
                {"release": release_dir or os.environ.get("GUARDIAN_RELEASE_DIR"), "reason": reason,
                 "requested_at": time.time()})
    try:
        os.kill(pid, signal.SIGUSR1)
        return True
    except OSError:
        return False


def last_result(cfg: dict) -> dict | None:
    return _read_json(os.path.join(data_dir_of(cfg), "switch-result.json"))


def state(cfg: dict) -> dict:
    return _read_json(os.path.join(data_dir_of(cfg), "supervisor.json"), {}) or {}


def managed_root(release_dir: str) -> str | None:
    """<root>/releases/<id> -> <root>, for installs made by setup-pi.sh."""
    parent = os.path.dirname(os.path.abspath(release_dir))
    return os.path.dirname(parent) if os.path.basename(parent) == "releases" else None


def python_for(release_dir: str) -> str:
    for cand in (os.path.join(release_dir, ".venv", "bin", "python"),
                 os.path.join(release_dir, ".venv", "Scripts", "python.exe")):
        if os.path.exists(cand):
            return cand
    return sys.executable


# ------------------------------------------------------------------ worker handles
class Worker:
    def __init__(self, pid: int, release: str, slot: int, popen=None):
        self.pid, self.release, self.slot, self.popen = pid, release, slot, popen
        self.exit_code = None
        self.started = time.time()

    def alive(self) -> bool:
        if self.exit_code is not None:
            return False
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.exit_code = -1
            return False
        if pid == 0:
            return True
        self.exit_code = os.waitstatus_to_exitcode(status)
        return False

    def send(self, sig):
        try:
            os.kill(self.pid, sig)
        except OSError:
            pass

    def stop(self, sig=signal.SIGTERM, timeout: float = STOP_TIMEOUT):
        self.send(sig)
        deadline = time.time() + timeout
        while self.alive() and time.time() < deadline:
            time.sleep(0.1)
        if self.alive():
            self.send(signal.SIGKILL)
            while self.alive():
                time.sleep(0.05)


# ------------------------------------------------------------------ the supervisor
class Supervisor:
    def __init__(self, release_dir: str, data_dir: str, worker_args: list[str]):
        self.release = os.path.realpath(release_dir)
        self.data_dir = data_dir
        self.worker_args = worker_args
        self.root = managed_root(self.release)
        self.state_path = os.path.join(data_dir, "supervisor.json")
        st = _read_json(self.state_path, {}) or {}
        self.previous = st.get("previous") if st.get("release") == self.release else st.get("release")
        if self.previous == self.release:
            self.previous = None
        self.worker: Worker | None = None
        self.slot = 0
        self.crashes: list[float] = []
        self.switched_at = float(st.get("switched_at") or 0)
        self._switch = self._stop = False

    # ---------------------------------------------------- bookkeeping
    def log(self, msg):
        print(f"[supervisor] {msg}", flush=True)

    def save(self):
        _write_json(self.state_path, {"release": self.release, "previous": self.previous, "slot": self.slot,
                                      "supervisor_pid": os.getpid(),
                                      "worker_pid": self.worker.pid if self.worker else None,
                                      "switched_at": self.switched_at, "saved_at": time.time()})

    def result(self, ok: bool, reason: str, target: str, error: str | None = None):
        _write_json(os.path.join(self.data_dir, "switch-result.json"),
                    {"ok": ok, "reason": reason, "release": target, "running": self.release,
                     "error": error, "at": time.time()})

    def point_current(self, release: str):
        """Move the <root>/current link atomically (managed installs only)."""
        if not self.root:
            return
        link = os.path.join(self.root, "current")
        tmp = link + ".new"
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        os.symlink(os.path.relpath(release, self.root), tmp)
        os.replace(tmp, link)

    # ---------------------------------------------------- workers
    def start_worker(self, release: str, slot: int, takeover: bool):
        r, w = os.pipe()
        env = dict(os.environ, GUARDIAN_DATA_DIR=self.data_dir, GUARDIAN_SUPERVISOR_PID=str(os.getpid()),
                   GUARDIAN_RELEASE_DIR=release)
        args = [python_for(release), os.path.join(release, "run.py"), "--worker", "--slot", str(slot),
                "--ready-fd", str(w)] + (["--takeover"] if takeover else []) + self.worker_args
        p = subprocess.Popen(args, cwd=release, env=env, pass_fds=(w,))
        os.close(w)
        worker = Worker(p.pid, release, slot, p)
        ok, why = self._wait_ready(worker, r)
        os.close(r)
        return worker, ok, why

    def _wait_ready(self, worker: Worker, fd: int):
        deadline = time.time() + READY_TIMEOUT
        buf = b""
        while time.time() < deadline:
            if not worker.alive():
                return False, f"the new version exited during start-up (code {worker.exit_code})"
            ready, _, _ = select.select([fd], [], [], 0.5)
            if ready:
                chunk = os.read(fd, 256)
                if not chunk:
                    continue
                buf += chunk
                if b"ready" in buf:
                    return True, None
        return False, f"the new version didn't become ready within {READY_TIMEOUT} s"

    # ---------------------------------------------------- main loop
    def run(self, adopt_pid: int | None = None, slot: int = 0):
        signal.signal(signal.SIGUSR1, lambda *_: setattr(self, "_switch", True))
        signal.signal(signal.SIGTERM, lambda *_: setattr(self, "_stop", True))
        signal.signal(signal.SIGINT, lambda *_: setattr(self, "_stop", True))
        if hasattr(signal, "pthread_sigmask"):             # deliver anything held during a re-launch
            signal.pthread_sigmask(signal.SIG_UNBLOCK, _HELD)
        self.slot = slot
        if adopt_pid:
            self.worker = Worker(adopt_pid, self.release, slot)
            self.log(f"running {os.path.basename(self.release)} (re-launched; worker {adopt_pid} carries on)")
        else:
            self.cold_start(self.release)
        self.save()
        while not self._stop:
            time.sleep(0.25)
            if self._switch:
                self._switch = False
                self.handle_switch()
            elif self.worker is not None and not self.worker.alive():
                self.handle_crash()
        self.log("stopping")
        if self.worker is not None:
            self.worker.stop(signal.SIGINT)     # SIGINT = the service is stopping (not a hand-over)
        return 0

    def cold_start(self, release: str):
        delay = 1
        while not self._stop:
            worker, ok, why = self.start_worker(release, self.slot, takeover=False)
            if ok:
                self.worker = worker
                self.log(f"worker {worker.pid} ready ({os.path.basename(release)})")
                return True
            self.log(f"start failed: {why}; retrying in {delay} s")
            worker.stop(signal.SIGKILL, 2)
            time.sleep(delay)
            delay = min(delay * 2, 30)
        return False

    def handle_switch(self):
        req = _read_json(os.path.join(self.data_dir, "switch-request.json"), {}) or {}
        target = os.path.realpath(req.get("release") or self.release)
        reason = req.get("reason") or "switch"
        if not os.path.exists(os.path.join(target, "run.py")):
            self.result(False, reason, target, "that version isn't installed")
            return
        self.log(f"{reason}: switching to {os.path.basename(target)}")
        old = self.worker
        new_slot = 1 - self.slot
        new, ok, why = self.start_worker(target, new_slot, takeover=True)
        if not ok:
            self.log(f"{reason} abandoned: {why}")
            if old is not None and old.alive():
                old.send(signal.SIGUSR2)        # take the firewall back before the new one goes
                time.sleep(1.5)
            new.stop(signal.SIGKILL, 2)
            self.result(False, reason, target, why)
            return
        self.worker, self.slot = new, new_slot
        if target != self.release:
            self.previous, self.release = self.release, target
            self.switched_at = time.time()
            self.crashes = []
            self.point_current(target)
        self.save()
        self.result(True, reason, target)        # before the old one goes: the new one reads it then
        if old is not None:
            old.stop(signal.SIGTERM)             # SIGTERM = hand-over: drain and exit
        self.log(f"{reason} complete: worker {new.pid} serving {os.path.basename(target)}")
        if os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) != target:
            self.reexec()

    def handle_crash(self):
        code = self.worker.exit_code
        now = time.time()
        self.crashes = [t for t in self.crashes if now - t < CRASH_WINDOW] + [now]
        self.log(f"worker {self.worker.pid} exited unexpectedly (code {code})")
        recent_update = now - self.switched_at < CRASH_WINDOW
        if recent_update and len(self.crashes) >= 2 and self.previous and os.path.exists(self.previous):
            bad = self.release
            self.log(f"{os.path.basename(bad)} keeps crashing since it was installed - going back to "
                     f"{os.path.basename(self.previous)}")
            self.release, self.previous = self.previous, bad
            self.point_current(self.release)
            self.crashes = []
            self.switched_at = 0
            ok = self.cold_start(self.release)
            self.save()
            self.result(False, "crash", bad, f"kept crashing after the update (exit code {code}); rolled back")
            if ok and os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) != self.release:
                self.reexec()
            return
        time.sleep(min(30, 2 ** (len(self.crashes) - 1)))
        self.cold_start(self.release)
        self.save()

    def reexec(self):
        """Become the new version's supervisor; the worker keeps running as our child.
        Stop/switch signals are held (not lost) across the exec and delivered to the
        new image once its handlers are in place."""
        if hasattr(signal, "pthread_sigmask"):
            signal.pthread_sigmask(signal.SIG_BLOCK, _HELD)
            if self._stop:
                signal.pthread_sigmask(signal.SIG_UNBLOCK, _HELD)
                return
        self.save()
        py = python_for(self.release)
        args = [py, os.path.join(self.release, "run.py"), "--supervise", "--adopt", str(self.worker.pid),
                "--slot", str(self.slot)] + self.worker_args
        self.log(f"re-launching the supervisor from {os.path.basename(self.release)}")
        sys.stdout.flush()
        sys.stderr.flush()
        os.execv(py, args)
