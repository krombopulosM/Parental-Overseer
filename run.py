"""Parental Gateway entry point.

    python run.py                    # start (mode comes from config.yaml / config.local.yaml)
    python run.py --set-password     # set or reset the dashboard password
    python run.py --update-lists     # download blocklists now and exit
    python run.py --config other.yaml
"""
import argparse
import getpass
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from guardian.config import load_config, resolve_path  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Parental Gateway")
    ap.add_argument("--config", default=os.path.join(HERE, "config.yaml"))
    ap.add_argument("--set-password", action="store_true", help="set the dashboard password and exit")
    ap.add_argument("--update-lists", action="store_true", help="download blocklists and exit")
    ap.add_argument("--no-download", action="store_true", help="don't refresh blocklists on start")
    args = ap.parse_args()

    cfg = load_config(args.config)

    if args.set_password:
        from guardian.auth import Auth
        from guardian.db import DB
        db = DB(resolve_path(cfg, cfg["database"]))
        pw = os.environ.get("GUARDIAN_PASSWORD") or getpass.getpass("New dashboard password (8+ chars): ")
        if not os.environ.get("GUARDIAN_PASSWORD") and getpass.getpass("Again: ") != pw:
            sys.exit("passwords didn't match")
        Auth(db).set_password(pw)
        db.close()
        print("password set")
        return

    if args.update_lists:
        from guardian.lists import ListManager
        lm = ListManager(cfg)
        lm.update()
        for k, v in lm.status.items():
            print(f"{k:22} {v['entries']:>8}")
        return

    from guardian.app import Guardian
    from guardian.webapp import create_app

    g = Guardian(cfg)
    g.start(download_lists=not args.no_download)

    import uvicorn
    web = cfg["web"]
    print(f"[web] dashboard on http://{web['host']}:{web['port']}  (mode: {cfg['mode']})")
    try:
        uvicorn.run(create_app(g), host=web["host"], port=int(web["port"]), log_level="warning")
    except KeyboardInterrupt:
        pass
    finally:
        print("[exit] shutting down")
        g.stop()


if __name__ == "__main__":
    main()
