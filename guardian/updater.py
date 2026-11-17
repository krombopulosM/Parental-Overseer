"""Automatic updates.

Every hour (and when you press "Check for updates") the gateway asks its update
source - a git repository - whether there's a newer version. Installing one:

  1. download   the new version is unpacked into its own folder
                (<root>/releases/<version>-<commit>); the running one isn't touched
  2. prepare    Python packages: reused if requirements didn't change, otherwise a
                fresh environment is built (and compiled) in the background;
                the code is pre-compiled so it starts quickly
  3. test       `run.py --selftest` must pass against this machine's settings
  4. switch     the supervisor starts the new version alongside the old one and
                hands over with no gap (see supervisor.py / handover.py)

Anything failing before step 4 leaves the running version exactly as it was. If
the new version fails to start or keeps crashing, the supervisor goes back to the
previous one. Wi-Fi, DHCP and the firewall are never stopped.

The installed layout (made by tools/install.py, run by setup-pi.sh):

  <root>/current -> releases/<id>     what the service runs
  <root>/releases/<id>/               one folder per version (+ .venv -> ../../venvs/<hash>)
  <root>/venvs/<hash>/                Python environments, shared while requirements match
  <root>/data/                        database, config.local.yaml, list cache, repo cache

The staging helpers use only the standard library (the installer runs them
before any packages exist).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time

_BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
_SUBDIR = re.compile(r"^[A-Za-z0-9._/-]{0,200}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_COPY_IGNORE = shutil.ignore_patterns(".git", ".venv", "__pycache__", "*.pyc", "guardian.db*", "config.local.yaml",
                                      "cache", ".pytest_cache", "*.tmp")


class UpdateError(Exception):
    pass


# ------------------------------------------------------------------ layout
class Layout:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.releases = os.path.join(self.root, "releases")
        self.venvs = os.path.join(self.root, "venvs")
        self.data = os.path.join(self.root, "data")
        self.repo = os.path.join(self.data, "repo.git")
        self.current_link = os.path.join(self.root, "current")

    @classmethod
    def of_release(cls, release_dir: str):
        parent = os.path.dirname(os.path.realpath(release_dir))
        return cls(os.path.dirname(parent)) if os.path.basename(parent) == "releases" else None

    def current(self) -> str | None:
        return os.path.realpath(self.current_link) if os.path.exists(self.current_link) else None

    def ensure(self):
        for d in (self.releases, self.venvs, self.data):
            os.makedirs(d, exist_ok=True)

    def point_current(self, release: str):
        tmp = self.current_link + ".new"
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        os.symlink(os.path.relpath(release, self.root), tmp)
        os.replace(tmp, self.current_link)


_INFO_CACHE: dict[str, tuple] = {}


def release_info(release_dir: str) -> dict:
    """Version and commit of an installed release (release.json), or of a
    development checkout (VERSION + git HEAD)."""
    if not release_dir:
        return {}
    key = os.path.realpath(release_dir)
    stamp = tuple(os.path.getmtime(p) if os.path.exists(p) else 0
                  for p in (os.path.join(key, "release.json"), os.path.join(key, "VERSION")))
    hit = _INFO_CACHE.get(key)
    if hit and hit[0] == stamp and time.time() - hit[2] < 60:
        return dict(hit[1])
    info = {}
    try:
        with open(os.path.join(key, "release.json"), encoding="utf-8") as fh:
            info = json.load(fh)
    except (OSError, ValueError):
        pass
    if not info.get("version"):
        info["version"] = read_version(key)
    if not info.get("commit") and _git_toplevel(key):
        try:
            info["commit"] = git("rev-parse", "HEAD", cwd=key, timeout=10).strip()
            info["dev_checkout"] = True
        except UpdateError:
            pass
    _INFO_CACHE[key] = (stamp, dict(info), time.time())
    return info


def read_version(release_dir: str) -> str:
    try:
        with open(os.path.join(release_dir, "VERSION"), encoding="utf-8") as fh:
            return fh.read().strip() or "0"
    except OSError:
        return "0"


# ------------------------------------------------------------------ git
def git(*args, cwd=None, timeout=180) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/bin/true")
    try:
        p = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise UpdateError("git isn't installed (sudo apt install git)")
    except subprocess.TimeoutExpired:
        raise UpdateError(f"git {args[0]} took too long - is the internet connection up?")
    if p.returncode != 0:
        msg = (p.stderr or p.stdout).strip().splitlines()
        raise UpdateError(msg[-1] if msg else f"git {args[0]} failed")
    return p.stdout


def _git_toplevel(path: str) -> str | None:
    try:
        return git("rev-parse", "--show-toplevel", cwd=path, timeout=10).strip()
    except (UpdateError, OSError):
        return None


def validate_source(source: str, branch: str, subdir: str):
    if not source:
        raise UpdateError("no update source is set")
    if not (source.startswith("https://") or source.startswith("file://") or os.path.isabs(source)):
        raise UpdateError("the update source must be an https:// git URL or a folder on this machine")
    if "::" in source or source.startswith("-"):
        raise UpdateError("that update source isn't allowed")
    if not _BRANCH.match(branch or "") or branch.startswith("-") or ".." in branch:
        raise UpdateError("invalid branch name")
    if not _SUBDIR.match(subdir or "") or ".." in (subdir or "").split("/"):
        raise UpdateError("invalid folder name")


def remote_head(source: str, branch: str) -> str:
    out = git("ls-remote", "--", source, f"refs/heads/{branch}", timeout=60)
    sha = out.split()[0] if out.split() else ""
    if not _SHA.match(sha):
        raise UpdateError(f"branch '{branch}' wasn't found in the update source")
    return sha


def fetch(layout: Layout, source: str, branch: str, sha: str):
    if not os.path.isdir(layout.repo):
        git("init", "--bare", "-q", layout.repo)
    git("--git-dir", layout.repo, "fetch", "-q", "--depth", "50", "--", source,
        f"+refs/heads/{branch}:refs/remotes/updates/{branch}", timeout=600)
    try:
        git("--git-dir", layout.repo, "cat-file", "-e", f"{sha}^{{commit}}")
    except UpdateError:
        raise UpdateError("the newest version wasn't in what was downloaded - try again in a minute")


def describe(layout: Layout, sha: str, subdir: str, since: str | None) -> dict:
    path = f"{subdir.strip('/')}/VERSION" if subdir.strip("/") else "VERSION"
    try:
        version = git("--git-dir", layout.repo, "show", f"{sha}:{path}").strip()
    except UpdateError:
        version = sha[:7]
    rng = f"{since}..{sha}" if since and _SHA.match(since) else sha
    try:
        args = ["--git-dir", layout.repo, "log", "--format=%s", "-n", "20", rng]
        if subdir.strip("/"):
            args += ["--", subdir.strip("/")]
        changes = [c for c in git(*args).splitlines() if c.strip()]
    except UpdateError:
        changes = []
    return {"commit": sha, "version": version, "changes": changes}


# ------------------------------------------------------------------ staging (stdlib only)
def _release_name(version: str, commit: str | None) -> str:
    v = re.sub(r"[^A-Za-z0-9._-]", "_", version or "0")
    return f"{v}-{commit[:7]}" if commit else f"{v}-local-{time.strftime('%Y%m%d-%H%M%S')}"


def stage_from_git(layout: Layout, sha: str, subdir: str, meta: dict) -> str:
    name = _release_name(meta.get("version"), sha)
    final = os.path.join(layout.releases, name)
    if os.path.exists(os.path.join(final, "run.py")):
        return final                                  # already staged earlier
    tmp = os.path.join(layout.releases, f".staging-{name}")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    tree = f"{sha}:{subdir.strip('/')}" if subdir.strip("/") else sha
    tar_path = tmp + ".tar"
    with open(tar_path, "wb") as fh:
        p = subprocess.run(["git", "--git-dir", layout.repo, "archive", "--format=tar", tree],
                           stdout=fh, stderr=subprocess.PIPE, timeout=300)
    if p.returncode != 0:
        raise UpdateError("couldn't unpack the new version: " + p.stderr.decode(errors="replace").strip()[-200:])
    with tarfile.open(tar_path) as tf:
        try:
            tf.extractall(tmp, filter="data")        # refuses absolute paths, '..', devices
        except TypeError:                             # Python < 3.12
            tf.extractall(tmp)
    os.unlink(tar_path)
    if not os.path.exists(os.path.join(tmp, "run.py")):
        shutil.rmtree(tmp, ignore_errors=True)
        raise UpdateError("the downloaded version doesn't look like this program (no run.py) - check the folder setting")
    _write_info(tmp, {**meta, "commit": sha, "staged_at": time.time()})
    os.replace(tmp, final)
    return final


def stage_from_dir(layout: Layout, src: str, meta: dict) -> str:
    name = _release_name(meta.get("version") or read_version(src), meta.get("commit"))
    final = os.path.join(layout.releases, name)
    tmp = os.path.join(layout.releases, f".staging-{name}")
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(src, tmp, ignore=_COPY_IGNORE, symlinks=False)
    _write_info(tmp, {**meta, "version": meta.get("version") or read_version(src), "staged_at": time.time()})
    if os.path.exists(final):                        # never replace a folder that may be running
        final = f"{final}-{int(time.time())}"
    os.replace(tmp, final)
    return final


def _write_info(release: str, info: dict):
    with open(os.path.join(release, "release.json"), "w", encoding="utf-8") as fh:
        json.dump(info, fh, indent=1)


def requirements_hash(release: str, gateway: bool) -> str:
    h = hashlib.sha256(f"{sys.version_info[:2]}|{sys.platform}".encode())
    for name in ("requirements.txt", "requirements-gateway.txt" if gateway else None):
        if name and os.path.exists(os.path.join(release, name)):
            with open(os.path.join(release, name), "rb") as fh:
                h.update(name.encode() + b"\0" + fh.read())
    return h.hexdigest()[:16]


def ensure_venv(layout: Layout, release: str, gateway: bool, log=print, base_python: str | None = None) -> str:
    """Link the release to a Python environment with its requirements installed.
    Reused when the requirements are unchanged (the usual case: seconds); built
    from scratch otherwise (pip compiles netfilterqueue's C extension, which on a
    Pi takes a few minutes - all while the running version carries on)."""
    key = requirements_hash(release, gateway)
    venv = os.path.join(layout.venvs, key)
    py = os.path.join(venv, "bin", "python")
    if not os.path.exists(py):
        log("building a new Python environment (requirements changed)")
        building = venv + ".building"
        shutil.rmtree(building, ignore_errors=True)
        base = base_python or getattr(sys, "_base_executable", None) or sys.executable
        _run([base, "-m", "venv", building], "creating the Python environment", timeout=600)
        reqs = ["-r", os.path.join(release, "requirements.txt")]
        if gateway and os.path.exists(os.path.join(release, "requirements-gateway.txt")):
            reqs += ["-r", os.path.join(release, "requirements-gateway.txt")]
        pip = os.path.join(building, "bin", "pip")
        nice = ["nice", "-n", "10"] if shutil.which("nice") else []
        _run(nice + [pip, "install", "-q", "--disable-pip-version-check", *reqs],
             "installing Python packages", timeout=3600)
        os.replace(building, venv)
    link = os.path.join(release, ".venv")
    if os.path.lexists(link):
        os.unlink(link)
    os.symlink(os.path.relpath(venv, release), link)
    return os.path.join(release, ".venv", "bin", "python")


def _run(args, what, timeout=600, env=None, cwd=None) -> str:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd)
    except subprocess.TimeoutExpired:
        raise UpdateError(f"{what} took too long")
    if p.returncode != 0:
        tail = (p.stdout + p.stderr).strip().splitlines()[-8:]
        raise UpdateError(f"{what} failed: " + " | ".join(tail)[-400:])
    return p.stdout


def compile_release(python: str, release: str):
    _run([python, "-m", "compileall", "-q", "-j", "0", os.path.join(release, "guardian"),
          os.path.join(release, "run.py")], "pre-compiling", timeout=600)


def selftest(python: str, release: str, data_dir: str) -> str:
    env = dict(os.environ, GUARDIAN_DATA_DIR=data_dir)
    env.pop("GUARDIAN_SUPERVISOR_PID", None)
    return _run([python, os.path.join(release, "run.py"), "--selftest"], "the self-test",
                timeout=300, env=env, cwd=release)


def prune(layout: Layout, keep: set[str], max_releases: int = 3):
    """Keep the running, previous and newest releases; remove the rest and any
    Python environments nothing uses."""
    rels = sorted((os.path.join(layout.releases, d) for d in os.listdir(layout.releases)
                   if not d.startswith(".")), key=os.path.getmtime, reverse=True)
    keep = {os.path.realpath(k) for k in keep if k}
    room = max_releases - sum(1 for r in rels if os.path.realpath(r) in keep)
    for r in rels:
        if os.path.realpath(r) in keep:
            continue
        if room > 0:
            room -= 1
            continue
        shutil.rmtree(r, ignore_errors=True)
    used = set()
    for d in os.listdir(layout.releases):
        link = os.path.join(layout.releases, d, ".venv")
        if os.path.islink(link):
            used.add(os.path.basename(os.path.realpath(link)))
    for v in os.listdir(layout.venvs):
        if v not in used and not v.endswith(".building"):
            shutil.rmtree(os.path.join(layout.venvs, v), ignore_errors=True)
    for d in os.listdir(layout.releases):
        if d.startswith(".staging-"):
            shutil.rmtree(os.path.join(layout.releases, d), ignore_errors=True)


# ------------------------------------------------------------------ the running updater
STEPS = [("downloading", "Downloading"), ("preparing", "Preparing"), ("testing", "Testing"),
         ("switching", "Switching over")]


class Updater:
    def __init__(self, cfg: dict, db, alerts=None, release_dir: str | None = None):
        self.cfg, self.db, self.alerts = cfg, db, alerts
        self.release_dir = os.path.realpath(release_dir or os.environ.get("GUARDIAN_RELEASE_DIR") or
                                            os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.layout = Layout.of_release(self.release_dir)
        self._lock = threading.Lock()
        self._busy = False
        self._started = False

    # ---------------------------------------------------- settings / state
    @property
    def settings(self) -> dict:
        return self.cfg.get("updates") or {}

    def _state(self) -> dict:
        try:
            return json.loads(self.db.get_setting("update_state") or "{}")
        except ValueError:
            return {}

    def _save(self, **changes):
        st = self._state()
        st.update(changes)
        self.db.set_setting("update_state", json.dumps(st))
        return st

    def status(self) -> dict:
        try:
            self.reconcile()
        except Exception:
            pass
        st = self._state()
        info = release_info(self.release_dir)
        from . import supervisor
        sup = supervisor.state(self.cfg) if supervisor.under_supervisor() else {}
        prev = sup.get("previous")
        s = self.settings
        out = {
            "current": {"version": info.get("version"), "commit": info.get("commit"),
                        "installed_at": info.get("staged_at"), "release": os.path.basename(self.release_dir)},
            "managed": self.layout is not None and supervisor.under_supervisor(),
            "settings": {"enabled": bool(s.get("enabled", True)), "auto_install": bool(s.get("auto_install", True)),
                         "source": s.get("source") or "", "branch": s.get("branch") or "main",
                         "subdir": s.get("subdir") or "", "interval_minutes": int(s.get("interval_minutes", 60))},
            "status": st.get("status") or "idle", "message": st.get("message"), "error": st.get("error"),
            "step": st.get("step"), "steps": STEPS,
            "latest": st.get("latest"), "last_check": st.get("last_check"),
            "next_check": st.get("next_check"), "history": (st.get("history") or [])[:10],
            "previous": {"release": os.path.basename(prev), **{k: release_info(prev).get(k) for k in ("version", "commit")}}
            if prev and os.path.exists(prev) else None,
            "busy": self._busy,
        }
        if not out["settings"]["source"]:
            out["status"], out["message"] = "not_configured", "No update source is set."
        return out

    # ---------------------------------------------------- background loop
    def start(self):
        if self._started:
            return
        self._started = True
        self.reconcile()
        threading.Thread(target=self._loop, name="updater", daemon=True).start()

    def _loop(self):
        time.sleep(90)                                 # let a fresh start settle first
        while True:
            s = self.settings
            interval = max(10, int(s.get("interval_minutes", 60))) * 60
            if s.get("enabled", True) and s.get("source"):
                try:
                    st = self.check()
                    if st.get("status") == "available" and s.get("auto_install", True) and self.can_install():
                        self.install()
                except Exception as e:                 # never let the loop die
                    print(f"[updates] {e}")
            self._save(next_check=time.time() + interval)
            time.sleep(interval)

    def can_install(self) -> bool:
        from . import supervisor
        return self.layout is not None and supervisor.under_supervisor()

    # ---------------------------------------------------- check
    def check(self, manual: bool = False) -> dict:
        s = self.settings
        source, branch, subdir = s.get("source") or "", s.get("branch") or "main", s.get("subdir") or ""
        if not source:
            return self.status()
        if self._busy:
            return self.status()
        self._save(status="checking", error=None, message="Checking for updates…")
        try:
            validate_source(source, branch, subdir)
            head = remote_head(source, branch)
            cur = release_info(self.release_dir).get("commit")
            now = time.time()
            if head == cur:
                self._save(status="up_to_date", message="You have the newest version.", latest=None,
                           last_check=now)
            else:
                if self.layout is None:
                    latest = {"commit": head, "version": head[:7], "changes": []}
                else:
                    fetch(self.layout, source, branch, head)
                    latest = describe(self.layout, head, subdir, cur)
                msg = f"Version {latest['version']} is available."
                if not self.can_install():
                    msg += (" This copy is a development folder, so it isn't updated automatically - "
                            "use git pull." if self.layout is None else
                            " It will install when the service runs under its supervisor.")
                self._save(status="available", message=msg, latest=latest, last_check=now)
        except UpdateError as e:
            self._save(status="failed", error=str(e), message="Couldn't check for updates.", last_check=time.time())
        return self.status()

    # ---------------------------------------------------- install
    def install(self, manual: bool = False) -> dict:
        if not self.can_install():
            raise UpdateError("updates can only be installed on a gateway set up with setup-pi.sh "
                              "(running under its supervisor)")
        with self._lock:
            if self._busy:
                return self.status()
            self._busy = True
        self._save(status="installing", step="downloading", error=None, message="Starting the update…")
        threading.Thread(target=self._install, args=(manual,), name="update-install", daemon=True).start()
        return self.status()

    def _install(self, manual: bool):
        from . import supervisor
        s = self.settings
        source, branch, subdir = s.get("source") or "", s.get("branch") or "main", s.get("subdir") or ""
        cur = release_info(self.release_dir)
        target = None
        lock = None
        try:
            lock = _file_lock(os.path.join(self.layout.data, "update.lock"))
            validate_source(source, branch, subdir)
            self._save(status="installing", step="downloading", error=None, message="Downloading the new version…")
            head = remote_head(source, branch)
            if head == cur.get("commit"):
                self._save(status="up_to_date", step=None, message="You have the newest version.")
                return
            fetch(self.layout, source, branch, head)
            meta = describe(self.layout, head, subdir, cur.get("commit"))
            target = stage_from_git(self.layout, head, subdir, {"version": meta["version"], "source": source,
                                                                 "branch": branch, "subdir": subdir})
            self._save(step="preparing", message=f"Preparing version {meta['version']}…", latest=meta)
            py = ensure_venv(self.layout, target, self.cfg.get("mode") == "gateway",
                             log=lambda m: self._save(message=m[0].upper() + m[1:] + "…"))
            compile_release(py, target)
            self._save(step="testing", message="Testing the new version…")
            selftest(py, target, self.layout.data)
            self._save(step="switching", status="switching",
                       message=f"Switching to version {meta['version']} - filtering carries on throughout…",
                       switch_requested_at=time.time(), switch_target=target, switch_from=self.release_dir,
                       switch_manual=manual)
            if not supervisor.request_switch(self.cfg, target, "update"):
                raise UpdateError("the supervisor didn't answer")
            # If the switch works, this process is retired and the new one records
            # the result. If it doesn't, we're still here: record the failure.
            deadline = time.time() + supervisor.READY_TIMEOUT + 60
            while time.time() < deadline:
                time.sleep(1)
                res = supervisor.last_result(self.cfg) or {}
                if res.get("at", 0) >= self._state().get("switch_requested_at", 0) and \
                        os.path.realpath(res.get("release") or "") == os.path.realpath(target):
                    if not res.get("ok"):
                        raise UpdateError(f"the new version didn't take over: {res.get('error')}")
                    return
            raise UpdateError("switching over took too long")
        except (UpdateError, OSError) as e:
            self._record(ok=False, frm=cur, to=release_info(target) if target else self._state().get("latest"),
                         error=str(e), manual=manual)
            self._save(status="failed", step=None, error=str(e),
                       message="The update wasn't installed - nothing changed, protection carried on as before.")
            if self.alerts:
                self.alerts.emit("update_failed", detail=f"An update couldn't be installed: {e}. "
                                                         f"The running version carried on unchanged.",
                                 action="kept the current version")
        finally:
            if lock is not None:
                lock.close()
            with self._lock:
                self._busy = False

    def rollback(self) -> dict:
        from . import supervisor
        prev = (supervisor.state(self.cfg) or {}).get("previous")
        if not self.can_install() or not prev or not os.path.exists(os.path.join(prev, "run.py")):
            raise UpdateError("there's no previous version to go back to")
        self._save(status="switching", step="switching", message="Going back to the previous version…",
                   switch_requested_at=time.time(), switch_target=prev, switch_from=self.release_dir,
                   switch_manual=True, error=None)
        supervisor.request_switch(self.cfg, prev, "rollback")
        return self.status()

    # ---------------------------------------------------- after a switch
    def reconcile(self):
        """Run by the process that just took over: record how the last switch went."""
        from . import supervisor
        st = self._state()
        res = supervisor.last_result(self.cfg) if supervisor.under_supervisor() else None
        if not res or res.get("at", 0) <= st.get("result_recorded_at", 0):
            return
        if res.get("reason") not in ("update", "rollback", "crash"):
            self._save(result_recorded_at=res["at"])
            return
        frm = release_info(st.get("switch_from")) if st.get("switch_from") else {}
        to = release_info(res.get("release") or "")
        if res.get("ok"):
            self._record(ok=True, frm=frm, to=to, manual=st.get("switch_manual"), reason=res["reason"])
            word = "Went back to" if res["reason"] == "rollback" else "Updated to"
            self._save(status="installed", step=None, error=None, result_recorded_at=res["at"], latest=None,
                       message=f"{word} version {to.get('version')} with no interruption.")
            if self.layout is not None:
                try:                                   # keep this version, the previous one, and one more
                    prune(self.layout, keep={self.release_dir, (supervisor.state(self.cfg) or {}).get("previous")})
                except OSError:
                    pass
            if self.alerts:
                self.alerts.emit("update_installed", action="installed",
                                 detail=f"{word} version {to.get('version')} ({(to.get('commit') or '')[:7]}). "
                                        f"Filtering and Wi-Fi carried on throughout.")
        else:
            self._record(ok=False, frm=frm, to=to, error=res.get("error"), manual=st.get("switch_manual"),
                         reason=res["reason"])
            self._save(status="failed", step=None, error=res.get("error"), result_recorded_at=res["at"],
                       message="The update was undone - the previous version is running.")
            if self.alerts:
                self.alerts.emit("update_failed", action="rolled back",
                                 detail=f"Version {to.get('version')} was rolled back: {res.get('error')}")

    def _record(self, ok, frm, to, error=None, manual=False, reason="update"):
        st = self._state()
        hist = st.get("history") or []
        hist.insert(0, {"at": time.time(), "ok": ok, "reason": reason, "manual": bool(manual),
                        "from": {k: (frm or {}).get(k) for k in ("version", "commit")},
                        "to": {k: (to or {}).get(k) for k in ("version", "commit")}, "error": error})
        self._save(history=hist[:20])


class _file_lock:
    def __init__(self, path):
        self.fh = open(path, "a+")
        if os.name != "nt":
            import fcntl
            try:
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                self.fh.close()
                raise UpdateError("another update is already in progress")

    def close(self):
        self.fh.close()
