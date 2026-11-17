"""`python run.py --selftest`: does this copy of the program work?

Run against a freshly downloaded version *before* it's allowed anywhere near the
network. It imports every module, loads this machine's settings, and pushes a
few lookups and packets through the real filtering code in memory - nothing is
bound, nothing is changed. Exit code 0 = good.
"""
from __future__ import annotations

import importlib
import os
import pkgutil
import socket
import struct
import sys
import time
import traceback


def _syn(src, dst, dport) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", 40000, dport, 1000, 0, 5 << 4, 0x02, 65535, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return ip + tcp


def run(config_path: str) -> int:
    t0 = time.time()
    steps = []

    def step(name, fn):
        try:
            fn()
            steps.append((name, True, ""))
        except Exception as e:
            steps.append((name, False, f"{type(e).__name__}: {e}"))
            traceback.print_exc()

    def imports():
        import guardian
        skip = {"guardian.gateway.nfq"} if not sys.platform.startswith("linux") else set()
        for m in pkgutil.walk_packages(guardian.__path__, "guardian."):
            if m.name not in skip:
                try:
                    importlib.import_module(m.name)
                except ImportError as e:
                    if "netfilterqueue" in str(e) or "scapy" in str(e):
                        continue                    # optional, platform-specific
                    raise

    box = {}

    def config():
        from .config import load_config
        box["cfg"] = load_config(config_path)

    def pipeline():
        from dnslib import DNSRecord

        from .alerts import AlertSink
        from .dnscache import DnsCache
        from .identity import Identity
        from .inspector import FlowLabels, Inspector
        from .lists import ListManager
        from .policy import Policy
        from .resolver import DnsTunnelDetector, GuardianResolver, QueryStats
        cfg = box["cfg"]
        lists = ListManager(cfg)
        lists.load()
        alerts = AlertSink()
        policy = Policy(cfg, None, lists, Identity(cfg), alerts)
        policy.forced_group = next((n for n, g in cfg["groups"].items() if g.get("filtered")), None)
        cache = DnsCache(60)
        insp = Inspector(cfg, policy, lists, cache, alerts, FlowLabels())
        # a filtered device connecting somewhere it never looked up must not get through
        v = insp.inspect(_syn("192.0.2.50", "198.51.100.200", 443))
        if policy.forced_group and v.action == "accept" and cfg["protections"].get("direct_ip") == "enforce":
            raise AssertionError(f"direct-address check let a connection through: {v}")
        # the dashboard name is answered without the internet

        class Sched:
            def is_paused(self, *a):
                return False, ""

        class H:
            client_address = ("192.0.2.50", 5353)
        res = GuardianResolver(cfg, policy, lists, cache, None, alerts, Sched(), QueryStats(),
                               DnsTunnelDetector({}, alerts))
        from .localname import names
        r = res.resolve(DNSRecord.question(names(cfg)[1]), H())
        if not r.rr:
            raise AssertionError("dashboard name not answered")

    def webapp():
        from .webapp import create_app  # noqa: F401  (builds routes at import time)

    step("imports", imports)
    step("settings", config)
    if "cfg" in box:
        step("filtering pipeline", pipeline)
    step("dashboard", webapp)
    ok = all(s[1] for s in steps)
    for name, good, err in steps:
        print(f"  [{'ok' if good else 'FAIL'}] {name}{'' if good else ': ' + err}")
    print(f"selftest {'passed' if ok else 'FAILED'} in {time.time() - t0:.1f}s ({os.path.dirname(config_path)})")
    return 0 if ok else 1
