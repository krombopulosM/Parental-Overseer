"""Entry point: starts the filtering DNS server (background threads) and the
web dashboard (foreground). Run with:  python run.py
"""
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from guardian.db import DB
from guardian.policy import Policy
from guardian.resolver import start_dns
from guardian.webapp import create_app


def main():
    with open(os.path.join(HERE, "config.yaml"), "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    cfg["__base__"] = HERE

    db_path = cfg.get("database", "guardian.db")
    if not os.path.isabs(db_path):
        db_path = os.path.join(HERE, db_path)

    db = DB(db_path)
    policy = Policy(db, cfg)
    start_dns(db, policy, cfg)

    import uvicorn
    app = create_app(db, policy, cfg)
    web = cfg["web"]
    print(f"[web] dashboard on http://{web['host']}:{web['port']}")
    try:
        uvicorn.run(app, host=web["host"], port=web["port"], log_level="warning")
    except KeyboardInterrupt:
        print("\n[exit] shutting down")


if __name__ == "__main__":
    main()
