"""Install (or update) the gateway into its versioned layout. Run by setup-pi.sh.

    sudo python3 tools/install.py --root /opt/parental-gateway --gateway [--switch]

  * copies this folder into <root>/releases/<version>-<commit>
  * links a Python environment (built only if the requirements changed)
  * pre-compiles it and runs its self-test against this machine's settings
  * --switch: if the service is running, hands over to the new copy with no gap;
    otherwise just points <root>/current at it (the service starts it)

An older installation (everything directly in <root>) is migrated: its database,
settings and list cache move into <root>/data.

Only the standard library is used - this runs before anything is installed.
"""
import argparse
import json
import os
import shutil
import signal
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from guardian import updater  # noqa: E402

DATA_FILES = ("guardian.db", "guardian.db-wal", "guardian.db-shm", "config.local.yaml")


def migrate_flat(layout: updater.Layout):
    """<root>/run.py etc. from the old installer -> data moves to <root>/data."""
    if not os.path.exists(os.path.join(layout.root, "run.py")) or os.path.islink(layout.current_link):
        return False
    print(f"==> Moving the existing installation's data into {layout.data}")
    for f in DATA_FILES:
        src = os.path.join(layout.root, f)
        if os.path.exists(src) and not os.path.exists(os.path.join(layout.data, f)):
            shutil.move(src, os.path.join(layout.data, f))
    cache = os.path.join(layout.root, "blocklists", "cache")
    if os.path.isdir(cache) and not os.path.exists(os.path.join(layout.data, "blocklists", "cache")):
        os.makedirs(os.path.join(layout.data, "blocklists"), exist_ok=True)
        shutil.move(cache, os.path.join(layout.data, "blocklists", "cache"))
    old = os.path.join(layout.root, ".pre-releases-layout")
    shutil.rmtree(old, ignore_errors=True)
    os.makedirs(old)
    for name in os.listdir(layout.root):
        if name not in ("releases", "venvs", "data", "current", ".pre-releases-layout"):
            shutil.move(os.path.join(layout.root, name), os.path.join(old, name))
    return True


def git_origin(src: str) -> dict:
    """If installing from a git checkout, where future updates can come from."""
    try:
        top = updater.git("rev-parse", "--show-toplevel", cwd=src, timeout=10).strip()
        commit = updater.git("rev-parse", "HEAD", cwd=src, timeout=10).strip()
        branch = updater.git("rev-parse", "--abbrev-ref", "HEAD", cwd=src, timeout=10).strip()
        try:
            url = updater.git("remote", "get-url", "origin", cwd=src, timeout=10).strip()
        except updater.UpdateError:
            url = ""
        sub = os.path.relpath(os.path.realpath(src), os.path.realpath(top))
        dirty = bool(updater.git("status", "--porcelain", "--", ".", cwd=src, timeout=20).strip())
        return {"commit": None if dirty else commit, "branch": branch, "source": url,
                "subdir": "" if sub == "." else sub, "dirty": dirty}
    except updater.UpdateError:
        return {}


def supervisor_pid(layout) -> int | None:
    try:
        with open(os.path.join(layout.data, "supervisor.json")) as fh:
            pid = int(json.load(fh).get("supervisor_pid") or 0)
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError, TypeError):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="/opt/parental-gateway")
    ap.add_argument("--source-dir", default=HERE)
    ap.add_argument("--gateway", action="store_true", help="also install the gateway-only packages")
    ap.add_argument("--python", default=sys.executable, help="interpreter for new Python environments")
    ap.add_argument("--switch", action="store_true", help="hand over to the new copy if the service is running")
    ap.add_argument("--skip-selftest", action="store_true")
    args = ap.parse_args()

    layout = updater.Layout(args.root)
    layout.ensure()
    migrate_flat(layout)
    origin = git_origin(args.source_dir)
    meta = {"version": updater.read_version(args.source_dir), "commit": origin.get("commit"),
            "source": origin.get("source"), "branch": origin.get("branch"), "subdir": origin.get("subdir"),
            "installed_by": "install.py"}
    print(f"==> Installing version {meta['version']} into {layout.releases}")
    release = updater.stage_from_dir(layout, args.source_dir, meta)
    py = updater.ensure_venv(layout, release, args.gateway, base_python=args.python)
    updater.compile_release(py, release)
    if not args.skip_selftest:
        print(updater.selftest(py, release, layout.data).strip().splitlines()[-1])
    pid = supervisor_pid(layout) if args.switch else None
    if pid:
        print("==> Handing over to the new copy (filtering carries on)")
        req = {"release": release, "reason": "update", "requested_at": time.time()}
        with open(os.path.join(layout.data, "switch-request.json"), "w") as fh:
            json.dump(req, fh)
        os.kill(pid, signal.SIGUSR1)
        deadline = time.time() + 240
        while time.time() < deadline:
            time.sleep(1)
            try:
                with open(os.path.join(layout.data, "switch-result.json")) as fh:
                    res = json.load(fh)
            except (OSError, ValueError):
                continue
            if res.get("at", 0) >= req["requested_at"]:
                print("==> " + ("Done" if res.get("ok") else f"Hand-over failed, still on the old version: {res.get('error')}"))
                break
    else:
        layout.point_current(release)
    keep = {release, layout.current()}
    try:
        with open(os.path.join(layout.data, "supervisor.json")) as fh:
            keep.add(json.load(fh).get("previous"))
    except (OSError, ValueError):
        pass
    updater.prune(layout, keep)
    print(json.dumps({"release": release, "origin": origin}))


if __name__ == "__main__":
    main()
