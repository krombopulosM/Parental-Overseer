"""Parental Gateway entry point.

    python run.py                    # start (mode comes from config.yaml / config.local.yaml)
    python run.py --set-password     # set or reset the dashboard password
    python run.py --update-lists     # download blocklists now and exit
    python run.py --config other.yaml
    python run.py --supervise        # what the Pi's service runs: keeps a worker running and
                                     # switches workers with no gap for updates/restarts
    python run.py --selftest         # check this copy works (run before an update goes live)
    python run.py --diagnostics      # write a diagnostics zip (logs, status, settings) to send for help
"""
import argparse
import getpass
import os
import signal
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def wait_for_port(host: str, port: int, timeout: float = 15):
    """Without SO_REUSEPORT (Windows) the old process may hold the port briefly."""
    import socket
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
                return
            except OSError:
                time.sleep(0.5)


def default_data_dir() -> str:
    if os.environ.get("GUARDIAN_DATA_DIR"):
        return os.environ["GUARDIAN_DATA_DIR"]
    from guardian.supervisor import managed_root
    root = managed_root(os.path.realpath(HERE))
    return os.path.join(root, "data") if root else HERE


def main():
    ap = argparse.ArgumentParser(description="Parental Gateway")
    ap.add_argument("--config", default=os.path.join(HERE, "config.yaml"))
    ap.add_argument("--set-password", action="store_true", help="set the dashboard password and exit")
    ap.add_argument("--update-lists", action="store_true", help="download blocklists and exit")
    ap.add_argument("--no-download", action="store_true", help="don't refresh blocklists on start")
    ap.add_argument("--supervise", action="store_true", help="run under the supervisor (seamless updates)")
    ap.add_argument("--selftest", action="store_true", help="check this copy of the program works, then exit")
    ap.add_argument("--diagnostics", nargs="?", const="", metavar="OUT.zip",
                    help="write a diagnostics bundle to send when asking for help, then exit")
    ap.add_argument("--include-activity", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--no-anonymise", action="store_true", help=argparse.SUPPRESS)
    # used by the supervisor
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--slot", type=int, default=0, help=argparse.SUPPRESS)
    ap.add_argument("--ready-fd", type=int, default=None, help=argparse.SUPPRESS)
    ap.add_argument("--takeover", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--adopt", type=int, default=None, help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.supervise:
        from guardian.supervisor import SUPPORTED, Supervisor
        if not SUPPORTED:
            sys.exit("--supervise (seamless updates) runs on the Raspberry Pi / Linux. On this computer, "
                     "start the gateway with: python run.py")
        data = default_data_dir()
        os.makedirs(data, exist_ok=True)
        from guardian.logs import capture
        capture(data, "supervisor")
        passthrough = ["--no-download"] if args.no_download else []
        sys.exit(Supervisor(os.path.realpath(HERE), data, passthrough).run(adopt_pid=args.adopt, slot=args.slot))

    if args.selftest:
        from guardian.selftest import run as selftest
        sys.exit(selftest(args.config))

    from guardian.config import load_config, resolve_data_path
    cfg = load_config(args.config)

    if args.set_password:
        from guardian.auth import Auth
        from guardian.db import DB
        db = DB(resolve_data_path(cfg, cfg["database"]))
        pw = os.environ.get("GUARDIAN_PASSWORD") or getpass.getpass("New dashboard password (8+ chars): ")
        if not os.environ.get("GUARDIAN_PASSWORD") and getpass.getpass("Again: ") != pw:
            sys.exit("passwords didn't match")
        Auth(db).set_password(pw)
        db.close()
        print("password set")
        return

    if args.diagnostics is not None:
        from guardian.diagnostics import build
        blob, name = build(cfg, None, include_activity=args.include_activity, anonymise=not args.no_anonymise)
        out = args.diagnostics or os.path.join(os.getcwd(), name)
        if os.path.isdir(out):
            out = os.path.join(out, name)
        try:
            with open(out, "wb") as fh:
                fh.write(blob)
        except OSError:
            from guardian.config import data_dir
            out = os.path.join(data_dir(cfg), name)
            with open(out, "wb") as fh:
                fh.write(blob)
        print(f"Diagnostics written to {out} ({len(blob) // 1024} KB). Send this file to whoever is helping you.")
        return

    if args.update_lists:
        from guardian.lists import ListManager
        lm = ListManager(cfg)
        lm.update()
        for k, v in lm.status.items():
            print(f"{k:22} {v['entries']:>8}")
        return

    serve(cfg, args)


def serve(cfg, args):
    import time

    import uvicorn

    from guardian.config import data_dir
    from guardian.logs import capture
    capture(data_dir(cfg), "gateway")

    from guardian.app import Guardian
    from guardian.handover import REUSEPORT, signal_ready, web_socket
    from guardian.webapp import create_app

    g = Guardian(cfg)
    try:
        g.start(download_lists=not args.no_download, queue_num=args.slot, takeover=args.takeover)
    except Exception as e:
        print(f"[exit] could not start: {e}", flush=True)
        os._exit(3)

    web = cfg["web"]
    if not REUSEPORT:
        wait_for_port(web["host"], int(web["port"]))
    sock = web_socket(web["host"], int(web["port"]))
    print(f"[web] dashboard on http://{web['host']}:{web['port']}  (mode: {cfg['mode']})")

    stopping = {"sig": None}

    class Server(uvicorn.Server):
        def handle_exit(self, sig, frame):
            stopping["sig"] = stopping["sig"] or sig
            super().handle_exit(sig, frame)

    server = Server(uvicorn.Config(create_app(g), log_level="warning", timeout_graceful_shutdown=3))

    def announce_ready():
        deadline = time.time() + 60
        while time.time() < deadline and not server.started:
            time.sleep(0.05)
        if server.started and g.ready():
            signal_ready(args.ready_fd)
            print("[ready] serving", flush=True)
        else:
            print("[ready] not ready - the supervisor will keep the previous version", flush=True)
    threading.Thread(target=announce_ready, name="ready", daemon=True).start()

    if hasattr(signal, "SIGUSR2"):
        # A newer worker failed to start after taking the firewall: take it back.
        def reclaim(*_):
            def go():
                if g.gateway is not None:
                    g.gateway.queue_num = g.queue_num
                    g.gateway.setup(devices=g._device_sets())
                    print("[handover] took the firewall back", flush=True)
            threading.Thread(target=go, daemon=True).start()
        signal.signal(signal.SIGUSR2, reclaim)

    try:
        server.run(sockets=[sock])
    except KeyboardInterrupt:
        pass
    # SIGTERM from the supervisor = a newer version has taken over (hand-over);
    # SIGINT / Ctrl-C = the service is stopping.
    handover = stopping["sig"] == signal.SIGTERM and bool(os.environ.get("GUARDIAN_SUPERVISOR_PID"))
    print("[exit] handing over" if handover else "[exit] shutting down", flush=True)
    g.shutdown(handover=handover)
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
