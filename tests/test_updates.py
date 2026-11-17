"""Updates: staging from git, environments, the updater's state, and the
supervisor's switching / rollback logic (with stand-in worker programs)."""
import json
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import time

import pytest

from conftest import ROOT
from guardian import updater
from guardian.updater import Layout, UpdateError

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def sh(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


def make_upstream(tmp_path, version="1.0.0"):
    """A git repo where the app lives in a subfolder (the `subdir` setting)."""
    repo = tmp_path / "upstream"
    app = repo / "app"
    app.mkdir(parents=True)
    (app / "run.py").write_text("print('hi')\n")
    (app / "VERSION").write_text(version + "\n")
    (app / "requirements.txt").write_text("pyyaml\n")
    (repo / "README").write_text("outer\n")
    sh("git", "init", "-q", "-b", "main", cwd=repo)
    sh("git", "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A", cwd=repo)
    sh("git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "first", cwd=repo)
    return repo


def commit(repo, msg, **files):
    for name, text in files.items():
        p = repo / "app" / name
        p.write_text(text)
    sh("git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", msg, cwd=repo)
    return sh("git", "rev-parse", "HEAD", cwd=repo).strip()


def fake_venv(layout, release, gateway=False):
    """Pretend the environment for these requirements already exists (no pip in tests)."""
    key = updater.requirements_hash(release, gateway)
    b = os.path.join(layout.venvs, key, "bin")
    os.makedirs(b, exist_ok=True)
    if not os.path.exists(os.path.join(b, "python")):
        os.symlink(sys.executable, os.path.join(b, "python"))


# ------------------------------------------------------------------ git staging
def test_validate_source():
    updater.validate_source("https://github.com/x/y.git", "main", "")
    updater.validate_source("/srv/repo", "release/2", "parental-gateway")
    for src, br, sub in [("ext::sh -c id", "main", ""), ("relative/path", "main", ""), ("-uhoh", "main", ""),
                         ("https://x/y", "--upload-pack=x", ""), ("https://x/y", "a..b", ""),
                         ("https://x/y", "main", "../etc"), ("", "main", "")]:
        with pytest.raises(UpdateError):
            updater.validate_source(src, br, sub)


def test_check_fetch_describe_and_stage(tmp_path):
    repo = make_upstream(tmp_path)
    first = sh("git", "rev-parse", "HEAD", cwd=repo).strip()
    second = commit(repo, "Faster inspector", VERSION="1.1.0\n")
    layout = Layout(tmp_path / "inst")
    layout.ensure()
    assert updater.remote_head(str(repo), "main") == second
    updater.fetch(layout, str(repo), "main", second)
    meta = updater.describe(layout, second, "app", first)
    assert meta["version"] == "1.1.0" and meta["changes"] == ["Faster inspector"]
    rel = updater.stage_from_git(layout, second, "app", {"version": meta["version"]})
    assert os.path.basename(rel) == f"1.1.0-{second[:7]}"
    assert open(os.path.join(rel, "VERSION")).read().strip() == "1.1.0"
    assert not os.path.exists(os.path.join(rel, "README"))            # only the app folder
    assert updater.release_info(rel)["commit"] == second
    assert updater.stage_from_git(layout, second, "app", meta) == rel  # idempotent
    with pytest.raises(UpdateError):
        updater.remote_head(str(repo), "nope")


def test_venv_reused_when_requirements_unchanged(tmp_path):
    layout = Layout(tmp_path / "inst")
    layout.ensure()
    a = layout.releases + "/a"
    b = layout.releases + "/b"
    for d in (a, b):
        os.makedirs(d)
        open(d + "/requirements.txt", "w").write("pyyaml\n")
    fake_venv(layout, a)
    built = []
    py_a = updater.ensure_venv(layout, a, False, log=built.append)
    py_b = updater.ensure_venv(layout, b, False, log=built.append)
    assert built == [] and os.path.realpath(py_a) == os.path.realpath(py_b)
    open(b + "/requirements.txt", "w").write("pyyaml\nqrcode\n")
    assert updater.requirements_hash(a, False) != updater.requirements_hash(b, False)


def test_install_from_dir_migrates_flat_layout(tmp_path):
    root = tmp_path / "opt"
    root.mkdir()
    (root / "run.py").write_text("old\n")                                 # the old flat install
    (root / "guardian.db").write_text("DB")
    (root / "config.local.yaml").write_text("mode: gateway\n")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import install
    layout = Layout(root)
    layout.ensure()
    assert install.migrate_flat(layout)
    assert (root / "data" / "guardian.db").read_text() == "DB"
    assert (root / "data" / "config.local.yaml").exists()
    assert not (root / "run.py").exists() and (root / ".pre-releases-layout" / "run.py").exists()
    rel = updater.stage_from_dir(layout, ROOT, {"commit": "abc1234def"})
    assert os.path.exists(os.path.join(rel, "run.py")) and not os.path.exists(os.path.join(rel, ".venv"))
    assert not any(n.startswith("guardian.db") for n in os.listdir(rel))
    layout.point_current(rel)
    assert layout.current() == os.path.realpath(rel)


def test_prune_keeps_running_and_previous(tmp_path):
    layout = Layout(tmp_path / "inst")
    layout.ensure()
    rels = []
    for i in range(6):
        d = os.path.join(layout.releases, f"r{i}")
        os.makedirs(d)
        os.utime(d, (time.time() - 100 + i, time.time() - 100 + i))
        rels.append(d)
    updater.prune(layout, keep={rels[0], rels[5]}, max_releases=3)
    left = sorted(os.listdir(layout.releases))
    assert "r0" in left and "r5" in left and len(left) == 3


def test_updater_check_states(tmp_path, monkeypatch):
    from guardian.db import DB
    repo = make_upstream(tmp_path)
    head = sh("git", "rev-parse", "HEAD", cwd=repo).strip()
    layout = Layout(tmp_path / "inst")
    layout.ensure()
    updater.fetch(layout, str(repo), "main", head)
    rel = updater.stage_from_git(layout, head, "app", {"version": "1.0.0"})
    db = DB(str(tmp_path / "g.db"))
    cfg = {"__base__": str(tmp_path), "__data__": layout.data, "mode": "monitor",
           "updates": {"enabled": True, "auto_install": True, "source": str(repo), "branch": "main", "subdir": "app"}}
    u = updater.Updater(cfg, db, release_dir=rel)
    assert u.check()["status"] == "up_to_date"
    commit(repo, "New dashboard", VERSION="1.2.0\n")
    st = u.check()
    assert st["status"] == "available" and st["latest"]["version"] == "1.2.0"
    assert st["latest"]["changes"] == ["New dashboard"]
    assert u.can_install() is False                                    # not under a supervisor here
    with pytest.raises(UpdateError):
        u.install()
    cfg["updates"]["source"] = "ext::sh -c id"
    assert u.check()["status"] == "failed"
    cfg["updates"]["source"] = ""
    assert u.status()["status"] == "not_configured"
    db.close()


# ------------------------------------------------------------------ the supervisor, with stand-in workers
FAKE = textwrap.dedent('''
    import json, os, signal, sys, time
    REPO, ME = {repo!r}, os.path.dirname(os.path.abspath(__file__))
    args = sys.argv[1:]
    if "--supervise" in args:
        sys.path.insert(0, REPO)
        from guardian.supervisor import Supervisor
        adopt = int(args[args.index("--adopt") + 1]) if "--adopt" in args else None
        slot = int(args[args.index("--slot") + 1]) if "--slot" in args else 0
        sys.exit(Supervisor(ME, os.environ["GUARDIAN_DATA_DIR"], []).run(adopt_pid=adopt, slot=slot))
    data = os.environ["GUARDIAN_DATA_DIR"]
    def log(ev):
        with open(os.path.join(data, "events.log"), "a") as fh:
            fh.write(json.dumps({{"pid": os.getpid(), "rel": os.path.basename(ME), "ev": ev,
                                 "slot": args[args.index("--slot") + 1], "takeover": "--takeover" in args}}) + "\\n")
    mode = open(os.path.join(ME, "mode")).read().strip()
    log("start")
    signal.signal(signal.SIGTERM, lambda *_: (log("handover-exit"), os._exit(0)))
    signal.signal(signal.SIGINT, lambda *_: (log("final-exit"), os._exit(0)))
    signal.signal(signal.SIGUSR2, lambda *_: log("reclaim"))
    if mode == "fail":
        time.sleep(0.3); log("fail"); os._exit(3)
    fd = int(args[args.index("--ready-fd") + 1])
    if mode == "crash" and not os.path.exists(os.path.join(ME, "crashed-once")) is False:
        pass
    os.write(fd, b"ready\\n"); os.close(fd)
    if mode == "crash":
        time.sleep(0.5); log("crash"); os._exit(9)
    while True:
        time.sleep(0.1)
''')


@pytest.fixture
def sup_env(tmp_path):
    root = tmp_path / "inst"
    layout = Layout(root)
    layout.ensure()

    def release(name, mode="ok"):
        d = os.path.join(layout.releases, name)
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "run.py"), "w").write(FAKE.format(repo=ROOT))
        open(os.path.join(d, "mode"), "w").write(mode)
        return d

    procs = []

    def start(rel):
        layout.point_current(rel)
        env = dict(os.environ, GUARDIAN_DATA_DIR=layout.data)
        p = subprocess.Popen([sys.executable, os.path.join(layout.current_link, "run.py"), "--supervise"],
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        procs.append(p)
        wait_for(lambda: "start" in [e["ev"] for e in events()])
        wait_for(lambda: (state() or {}).get("worker_pid"))
        return p

    def events():
        try:
            return [json.loads(line) for line in open(os.path.join(layout.data, "events.log"))]
        except OSError:
            return []

    def state():
        try:
            return json.load(open(os.path.join(layout.data, "supervisor.json")))
        except (OSError, ValueError):
            return None

    def switch(rel, reason="update"):
        t = time.time()
        json.dump({"release": rel, "reason": reason}, open(os.path.join(layout.data, "switch-request.json"), "w"))
        os.kill(state()["supervisor_pid"], signal.SIGUSR1)
        wait_for(lambda: (json.load(open(os.path.join(layout.data, "switch-result.json")))
                          if os.path.exists(os.path.join(layout.data, "switch-result.json")) else {}).get("at", 0) >= t)
        return json.load(open(os.path.join(layout.data, "switch-result.json")))

    class E:
        pass
    e = E()
    e.layout, e.release, e.start, e.events, e.state, e.switch = layout, release, start, events, state, switch
    yield e
    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()


def wait_for(cond, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            v = cond()
            if v:
                return v
        except (OSError, ValueError, KeyError, TypeError):
            pass
        time.sleep(0.05)
    raise AssertionError("timed out")


def test_supervisor_switches_with_overlap_and_relaunches_itself(sup_env):
    e = sup_env
    v1, v2 = e.release("v1"), e.release("v2")
    p = e.start(v1)
    first = e.state()
    res = e.switch(v2)
    assert res["ok"] and res["release"] == os.path.realpath(v2)
    wait_for(lambda: "handover-exit" in [x["ev"] for x in e.events()])
    ev = e.events()
    starts = [x for x in ev if x["ev"] == "start"]
    assert [(x["rel"], x["slot"], x["takeover"]) for x in starts] == [("v1", "0", False), ("v2", "1", True)]
    # the old worker was asked to hand over only after the new one was ready
    assert [x["ev"] for x in ev].index("handover-exit") > [x["ev"] for x in ev].index("start", 1)
    assert e.layout.current() == os.path.realpath(v2)
    st = wait_for(lambda: e.state() if e.state()["release"] == os.path.realpath(v2) else None)
    assert st["previous"] == os.path.realpath(v1) and st["slot"] == 1
    # the supervisor re-launched itself from v2's code - same process, same worker
    wait_for(lambda: e.state()["supervisor_pid"] == first["supervisor_pid"] and p.poll() is None)
    assert e.state()["worker_pid"] == starts[1]["pid"]
    # stopping the service = final stop for the worker
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=15)
    assert "final-exit" in [x["ev"] for x in e.events()]


def test_failed_switch_keeps_old_and_takes_firewall_back(sup_env):
    e = sup_env
    v1, bad = e.release("v1"), e.release("bad", mode="fail")
    e.start(v1)
    res = e.switch(bad)
    assert not res["ok"] and "exited during start-up" in res["error"]
    evs = [x["ev"] for x in e.events() if x["rel"] == "v1"]
    assert "reclaim" in evs and "handover-exit" not in evs
    assert e.layout.current() == os.path.realpath(v1)
    assert e.state()["slot"] == 0


def test_crashing_update_is_rolled_back(sup_env):
    e = sup_env
    v1, v2 = e.release("v1"), e.release("v2", mode="crash")
    e.start(v1)
    assert e.switch(v2)["ok"]
    res = wait_for(lambda: (lambda r: r if r.get("reason") == "crash" else None)(
        json.load(open(os.path.join(e.layout.data, "switch-result.json")))), timeout=40)
    assert not res["ok"] and "rolled back" in res["error"]
    wait_for(lambda: e.layout.current() == os.path.realpath(v1))
    wait_for(lambda: e.state()["release"] == os.path.realpath(v1))
    assert [x["rel"] for x in e.events() if x["ev"] == "start"][-1] == "v1"


def test_worker_crash_is_restarted(sup_env):
    e = sup_env
    v1 = e.release("v1")
    e.start(v1)
    pid = e.state()["worker_pid"]
    os.kill(pid, signal.SIGKILL)
    wait_for(lambda: e.state()["worker_pid"] != pid, timeout=20)
    assert len([x for x in e.events() if x["ev"] == "start"]) == 2
