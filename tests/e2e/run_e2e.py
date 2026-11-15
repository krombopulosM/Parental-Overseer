#!/usr/bin/env python3
"""End-to-end test of gateway mode, using Linux network namespaces as a
miniature home network:

    pg-kid (10.50.0.10) ─┐
    pg-kid2 (10.50.0.11) ├── lan0 bridge ── pg-gw (the real Parental Gateway) ── wan0 ── pg-inet (fake internet)
    pg-parent (10.50.0.20)┤                 nftables + NFQUEUE inspector
    pg-console (10.50.0.30)┘

Needs root on Linux (works on the Raspberry Pi too). Usage:
    sudo python3 tests/e2e/run_e2e.py [--keep]
"""
import json
import os
import subprocess
import sys
import time

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
W = "/tmp/pg-e2e"
PY = sys.executable
NAMESPACES = ["pg-inet", "pg-gw", "pg-kid", "pg-kid2", "pg-parent", "pg-console"]
LAN = [("pg-kid", "10.50.0.10", "02:00:00:00:00:10"), ("pg-kid2", "10.50.0.11", "02:00:00:00:00:11"),
       ("pg-parent", "10.50.0.20", "02:00:00:00:00:20"), ("pg-console", "10.50.0.30", "02:00:00:00:00:30")]
INET_IPS = ["198.51.100.10", "198.51.100.53", "198.51.100.66", "198.51.100.77", "198.51.100.78",
            "198.51.100.79", "198.51.100.80", "9.9.9.9", "192.168.1.1"]
results: list[dict] = []
procs: list[subprocess.Popen] = []


def sh(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)


def nsx(ns, cmd):
    return f"ip netns exec {ns} {cmd}"


def cleanup():
    for p in procs:
        p.terminate()
    for ns in NAMESPACES:
        sh(f"ip netns del {ns}", check=False)


def build_network():
    cleanup()
    for ns in NAMESPACES:
        sh(f"ip netns add {ns}")
        sh(f"ip -n {ns} link set lo up")
    sh("ip link add pgw-wan type veth peer name pgw-wanp")
    sh("ip link set pgw-wan netns pg-gw && ip -n pg-gw link set pgw-wan name wan0")
    sh("ip link set pgw-wanp netns pg-inet")
    sh("ip -n pg-gw addr add 203.0.113.1/24 dev wan0 && ip -n pg-gw link set wan0 up")
    sh("ip -n pg-inet addr add 203.0.113.2/24 dev pgw-wanp && ip -n pg-inet link set pgw-wanp up")
    for ip in INET_IPS:
        sh(f"ip -n pg-inet addr add {ip}/32 dev lo")
    sh("ip -n pg-gw route add default via 203.0.113.2")
    sh("ip -n pg-gw link add lan0 type bridge && ip -n pg-gw addr add 10.50.0.1/24 dev lan0 "
       "&& ip -n pg-gw link set lan0 up")
    for i, (ns, ip, mac) in enumerate(LAN):
        sh(f"ip link add pgv{i} type veth peer name pgp{i}")
        sh(f"ip link set pgv{i} netns {ns} && ip -n {ns} link set pgv{i} name eth0")
        sh(f"ip link set pgp{i} netns pg-gw && ip -n pg-gw link set pgp{i} master lan0 up")
        sh(f"ip -n {ns} link set eth0 address {mac} && ip -n {ns} addr add {ip}/24 dev eth0 "
           f"&& ip -n {ns} link set eth0 up && ip -n {ns} route add default via 10.50.0.1")


def write_config():
    os.makedirs(W, exist_ok=True)
    for f in os.listdir(W):
        if f.startswith("guardian.db") or f.endswith(".log"):
            os.remove(os.path.join(W, f))
    b = os.path.join(ROOT, "blocklists", "builtin")
    open(f"{W}/adult.txt", "w").write("adult-site.test\n")
    open(f"{W}/vpn-test.txt", "w").write("198.51.100.66\n")
    with open(os.path.join(ROOT, "config.yaml")) as fh:
        cfg = yaml.safe_load(fh)
    cfg.update(mode="gateway", database=f"{W}/guardian.db", lists_cache_dir=f"{W}/cache")
    cfg["dns"].update(listen_port=53, upstreams=["198.51.100.53"])
    cfg["web"] = {"host": "0.0.0.0", "port": 8080}
    cfg["categories"] = {
        "ads": {"files": [f"{b}/ads.txt"]},
        "adult": {"files": [f"{W}/adult.txt", f"{b}/adult.txt"]},
        "gambling": {"files": []},
        "bypass": {"files": [f"{b}/vpn.txt", f"{b}/doh.txt", f"{b}/bypass.txt"]},
    }
    cfg["ip_lists"] = {"vpn": {"files": [f"{b}/vpn-ips.txt", f"{W}/vpn-test.txt"]},
                       "doh": {"files": [f"{b}/doh-ips.txt"]}}
    cfg["enforcement"]["consistency_exempt"] = f"{b}/consistency-exempt.txt"
    cfg["detector"].update(interval=2, min_duration=4, min_bytes=2_000_000, window=30,
                           silence_min_bytes=1_000_000, learning_days=0)
    cfg["flows"]["poll_interval"] = 1
    cfg["gateway"].update(wan_interface="wan0", lan_interfaces=["lan0"], lan_ip="10.50.0.1",
                          lan_subnets=["10.50.0.0/24"], dhcp_leases=None)
    with open(f"{W}/config.yaml", "w") as fh:
        yaml.safe_dump(cfg, fh)


def start_processes():
    if not os.path.exists(f"{W}/cert.pem"):
        sh(f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {W}/key.pem -out {W}/cert.pem "
           f"-days 3 -subj /CN=e2e.test")
    procs.append(subprocess.Popen(["ip", "netns", "exec", "pg-inet", PY, f"{HERE}/servers.py", f"{W}/cert.pem",
                                   f"{W}/key.pem"], stdout=open(f"{W}/servers.log", "w"), stderr=subprocess.STDOUT))
    env = dict(os.environ, GUARDIAN_PASSWORD="e2e-password")
    subprocess.run([PY, f"{ROOT}/run.py", "--config", f"{W}/config.yaml", "--set-password"], env=env,
                   check=True, capture_output=True)
    gw = subprocess.Popen(["ip", "netns", "exec", "pg-gw", PY, f"{ROOT}/run.py", "--config", f"{W}/config.yaml",
                           "--no-download"], stdout=open(f"{W}/gateway.log", "w"), stderr=subprocess.STDOUT)
    procs.append(gw)
    for _ in range(60):
        if sh(nsx("pg-parent", "curl -s -o /dev/null -w %{http_code} http://10.50.0.1:8080/api/session"),
              check=False).stdout == "200":
            return gw
        time.sleep(0.5)
    print(open(f"{W}/gateway.log").read())
    raise SystemExit("gateway did not come up")


# ----------------------------------------------------------------- API (from the parent's laptop)
API_SCRIPT = r'''
import httpx, json, sys
c = httpx.Client(base_url="http://10.50.0.1:8080", timeout=20)
H = {"X-Guardian": "1"}
assert c.post("/api/login", json={"password": "e2e-password"}, headers=H).status_code == 200
op = json.loads(sys.argv[1])
if op["do"] == "get":
    print(json.dumps(c.get(op["path"]).json()))
else:
    r = c.post(op["path"], json=op.get("body", {}), headers=H)
    print(json.dumps({"status": r.status_code, "body": r.json()}))
'''


def api(do, path, body=None):
    op = json.dumps({"do": do, "path": path, "body": body or {}})
    with open(f"{W}/api.py", "w") as fh:
        fh.write(API_SCRIPT)
    out = sh(nsx("pg-parent", f"{PY} {W}/api.py '{op}'"), check=False)
    if out.returncode != 0:
        raise RuntimeError(out.stderr[-500:])
    return json.loads(out.stdout)


def device_id(ip):
    for _ in range(20):
        for d in api("get", "/api/devices")["devices"]:
            if d["ip"] == ip and d["mac"]:
                return d["device_id"]
        time.sleep(0.5)
    raise RuntimeError(f"device {ip} never appeared")


def touch(ns):
    sh(nsx(ns, f"{PY} -c \"from dnslib import DNSRecord; DNSRecord.question('site.test').send('10.50.0.1', 53, timeout=3)\""))


def run_suite(ns, suite, section):
    out = sh(nsx(ns, f"{PY} {HERE}/client.py {suite}"), check=False)
    if out.returncode != 0:
        results.append({"section": section, "name": f"suite {suite} crashed", "ok": False, "got": out.stderr[-300:]})
    for line in out.stdout.splitlines():
        r = json.loads(line)
        r["section"] = section
        results.append(r)


def record(section, name, ok, got=""):
    results.append({"section": section, "name": name, "ok": bool(ok), "got": got})


def main():
    if os.geteuid() != 0:
        raise SystemExit("run as root")
    keep = "--keep" in sys.argv
    try:
        build_network()
        write_config()
        gw = start_processes()

        touch("pg-parent")
        touch("pg-console")
        parent, console = device_id("10.50.0.20"), device_id("10.50.0.30")
        api("post", f"/api/devices/{parent}", {"group": "adults", "name": "Parent laptop"})
        api("post", f"/api/devices/{console}", {"group": "consoles", "name": "Games console"})
        time.sleep(1)

        run_suite("pg-kid", "kid", "Kid's phone (unknown device -> strictest group)")
        run_suite("pg-parent", "parent", "Parent laptop (adults group)")
        run_suite("pg-console", "console", "Games console (consoles group)")

        kid = device_id("10.50.0.10")
        api("post", f"/api/devices/{kid}/pause", {"minutes": 30})
        time.sleep(1)
        run_suite("pg-kid", "kid_paused", "Pause button")
        api("post", f"/api/devices/{kid}/pause", {"minutes": 0})
        time.sleep(1)
        run_suite("pg-kid", "kid_basic", "Pause button")

        run_suite("pg-kid2", "tunnel", "Behaviour detector (disguised tunnel)")

        # ---- Phase 2: what the dashboard shows
        time.sleep(2)
        sec = "Traffic monitoring (Phase 2)"
        flows = api("get", "/api/flows?limit=500")
        allf = flows["live"] + flows["recent"]
        site = [f for f in allf if f["client_ip"] == "10.50.0.10" and f["domain"] == "site.test"]
        record(sec, "kid's HTTPS connection labelled site.test from the TLS handshake",
               site and site[0]["domain_src"] == "sni", site[:1])
        record(sec, "byte counts recorded", site and site[0]["bytes_down"] > 0 and site[0]["bytes_up"] > 0,
               site and (site[0]["bytes_up"], site[0]["bytes_down"]))
        kid2 = device_id("10.50.0.11")
        det = api("get", f"/api/devices/{kid2}")
        svc = {s["service"]: s for s in det["services"]}
        t = svc.get("tunnel.test")
        record(sec, "per-service usage: tunnel.test minutes + MB for kid2",
               t and t["minutes"] >= 1 and t["bytes_down"] > 2_000_000, t)
        devs = api("get", "/api/devices")["devices"]
        record(sec, "the gateway itself is never listed as a device",
               not any(d["ip"] == "10.50.0.1" for d in devs), [d["ip"] for d in devs])
        record(sec, "no LAN-internal traffic counted as a service",
               not any(f["dst_ip"].startswith("10.50.0.") for f in allf), "")
        blocked_flows = [f for f in allf if f["verdict"] == "blocked"]
        record(sec, "blocked connections visible with reasons", len(blocked_flows) >= 5,
               f"{len(blocked_flows)} blocked flows")

        sec = "Alerts raised (Phase 3)"
        kinds = {}
        for a in api("get", "/api/alerts?limit=500")["alerts"]:
            kinds.setdefault(a["kind"], a)
        for k in ["no_dns", "dns_bypass_site", "sni_mismatch", "no_sni", "ech", "vpn_server", "doh_server",
                  "protocol_violation", "evasion", "server_first", "http_proxy", "blocked_udp", "blocked_port",
                  "bypass_domain", "tunnel_behaviour", "new_device"]:
            record(sec, k, k in kinds, (kinds.get(k) or {}).get("detail", "")[:110])
        dyn = api("get", "/api/rules")["dyn_blocks"]
        record(sec, "tunnel destination auto-blocked", any(d["ip"] == "198.51.100.79" for d in dyn), dyn[:1])

        # ---- Tamper resistance: kill the inspector
        gw.terminate()
        gw.wait(timeout=20)
        time.sleep(1)
        run_suite("pg-kid", "kid_failclosed", "Gateway service stopped (fail closed)")
        run_suite("pg-parent", "parent_failclosed", "Gateway service stopped (fail closed)")
    finally:
        report()
        if not keep:
            cleanup()
        else:
            print(f"namespaces kept; logs in {W}")
    sys.exit(0 if results and all(r["ok"] for r in results) else 1)


def report():
    section = None
    for r in results:
        if r["section"] != section:
            section = r["section"]
            print(f"\n== {section}")
        mark = "PASS" if r["ok"] else "FAIL"
        extra = "" if r["ok"] else f"   got={r.get('got')!r} want={r.get('want')!r}"
        print(f"  [{mark}] {r['name']}{extra}")
    n_ok = sum(r["ok"] for r in results)
    print(f"\n{n_ok}/{len(results)} checks passed")


if __name__ == "__main__":
    main()
