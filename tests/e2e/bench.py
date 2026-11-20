#!/usr/bin/env python3
"""Speed benchmark: what does the gateway cost a filtered device?

Builds the same miniature network as run_e2e.py and measures, for the kid's
device (filtered: every check applies) and the parent's laptop (unfiltered),
DNS latency, TLS connection set-up, time to first byte and throughput through
the gateway. The difference between the two is the cost of the checks.

    sudo python3 tests/e2e/bench.py [results.json]

Absolute numbers depend on the machine (here: virtual links, so throughput is
CPU-bound); compare kid vs parent, and runs before/after a change.
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_e2e as e  # noqa: E402


def cpu_seconds(pid):
    try:
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        return None


def main():
    out = {}
    try:
        e.build_network()
        e.write_config()
        e.start_processes()
        e.touch("pg-parent")
        parent = e.device_id("10.50.0.20")
        e.api("post", f"/api/devices/{parent}", {"group": "adults", "name": "Parent laptop"})
        time.sleep(2)
        worker = e.sup_state()["worker_pid"]
        for ns, suite in (("pg-parent", "bench_parent"), ("pg-kid", "bench_kid")):
            c0 = cpu_seconds(worker)
            r = e.sh(e.nsx(ns, f"{e.PY} {HERE}/client.py {suite}"), check=False)
            c1 = cpu_seconds(worker)
            line = [ln for ln in r.stdout.splitlines() if ln.startswith("{")]
            out[suite.split("_")[1]] = json.loads(line[-1]) if line else {"error": r.stderr[-400:]}
            out[suite.split("_")[1]]["gateway_cpu_s"] = round(c1 - c0, 2) if c0 is not None and c1 else None
        st = e.api("get", "/api/system")
        out["inspector"] = {k: v for k, v in (st.get("inspector") or {}).items() if k in ("packets",)}
        out["gateway"] = {k: (st.get("gateway") or {}).get(k) for k in ("backend", "fastpath", "nfq_handled")}
    finally:
        e.cleanup()
    print(json.dumps(out, indent=1))
    if len(sys.argv) > 1:
        json.dump(out, open(sys.argv[1], "w"), indent=1)


if __name__ == "__main__":
    main()
