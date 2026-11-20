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
UP = f"{W}/upstream"          # a git repository standing in for the project's GitHub
INST = f"{W}/inst"            # the installed layout: releases/, current, venvs/, data/
DATA = f"{INST}/data"
NAMESPACES = ["pg-inet", "pg-gw", "pg-kid", "pg-kid2", "pg-parent", "pg-console"]
LAN = [("pg-kid", "10.50.0.10", "02:00:00:00:00:10"), ("pg-kid2", "10.50.0.11", "02:00:00:00:00:11"),
       ("pg-parent", "10.50.0.20", "02:00:00:00:00:20"), ("pg-console", "10.50.0.30", "02:00:00:00:00:30")]
INET_IPS = ["198.51.100.10", "198.51.100.53", "198.51.100.54", "198.51.100.66", "198.51.100.77",
            "198.51.100.78", "198.51.100.79", "198.51.100.80", "198.51.100.81", "198.51.100.82",
            "198.51.100.83", "198.51.100.84", "198.51.100.85", "198.51.100.86", "198.51.100.87",
            "198.51.100.88", "198.51.100.89", "198.51.100.90", "198.51.100.91", "198.51.100.92", "9.9.9.9",
            "192.168.1.1"]
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
    for ip in INET_IPS + [f"198.51.101.{i}" for i in range(1, 31)]:
        sh(f"ip -n pg-inet addr add {ip}/32 dev lo")
    sh("ip -n pg-gw route add default via 203.0.113.2")
    sh("ip -n pg-gw link add lan0 type bridge mcast_snooping 0 && ip -n pg-gw addr add 10.50.0.1/24 dev lan0 "
       "&& ip -n pg-gw link set lan0 up")       # behave like an ordinary switch: flood multicast
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
        "vpn": {"files": [f"{b}/vpn.txt"]}, "tor": {"files": [f"{b}/tor.txt"]},
        "proxy": {"files": [f"{b}/bypass.txt"]}, "doh": {"files": [f"{b}/doh.txt"]},
        "torrent": {"files": [f"{b}/torrent.txt"]},
        "filehost": {"files": [f"{b}/filehost.txt"]},
        "mirrors": {"files": [f"{b}/mirrors.txt"]},
        "unsafe_search": {"files": [f"{b}/unsafe_search.txt"]},
    }
    cfg["adult"] = {**cfg.get("adult", {}), "family_dns": ["198.51.100.54"]}
    open(f"{W}/popular.txt", "w").write("site.test\nshared-cdn.test\nplain.test\n")
    open(f"{W}/tor-test.txt", "w").write("198.51.100.87\n")
    cfg["reputation"] = {"popularity_files": [f"{W}/popular.txt"], "popularity_urls": []}
    cfg["vpn"] = {**cfg.get("vpn", {}), "unknown_min_bytes": 20_000_000}
    cfg["escalation"] = {**cfg.get("escalation", {}), "pause_minutes": 0}   # keep the test devices online
    cfg["ip_lists"] = {"vpn": {"files": [f"{b}/vpn-ips.txt", f"{W}/vpn-test.txt"]},
                       "tor": {"files": [f"{W}/tor-test.txt"]},
                       "doh": {"files": [f"{b}/doh-ips.txt"]}}
    cfg["enforcement"]["consistency_exempt"] = f"{b}/consistency-exempt.txt"
    cfg["detector"].update(interval=2, min_duration=4, min_bytes=2_000_000, window=30,
                           silence_min_bytes=1_000_000, learning_days=0)
    cfg["flows"]["poll_interval"] = 1
    cfg["downloads"].update(min_bytes=3_000_000)
    cfg["gateway"].update(wan_interface="wan0", lan_interfaces=["lan0"], lan_ip="10.50.0.1",
                          lan_subnets=["10.50.0.0/24"], dhcp_leases=None)
    cfg["updates"] = {"enabled": False, "auto_install": False, "source": "", "branch": "main", "subdir": ""}
    import shutil
    shutil.rmtree(DATA, ignore_errors=True)
    os.makedirs(DATA, exist_ok=True)
    with open(f"{DATA}/config.local.yaml", "w") as fh:      # this machine's settings, as setup-pi.sh does
        yaml.safe_dump(cfg, fh)


def git(*args, cwd=UP):
    return subprocess.run(["git", "-c", "user.email=e2e@test", "-c", "user.name=e2e", *args], cwd=cwd,
                          check=True, capture_output=True, text=True).stdout


def install_like_the_pi():
    """Publish this working tree as version 1 in a local git repo, and install it
    with tools/install.py into the same layout setup-pi.sh makes."""
    import shutil
    for d in (UP, f"{INST}/releases", f"{INST}/venvs"):
        shutil.rmtree(d, ignore_errors=True)
    shutil.copytree(ROOT, UP, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", "guardian.db*",
                                                             "config.local.yaml", "cache", ".pytest_cache"))
    git("init", "-q", "-b", "main")
    git("add", "-A")
    git("commit", "-q", "-m", "Version 1")
    # The test machine already has every package: pre-make the environment the
    # requirements map to, so no download is needed (a Pi builds it with pip).
    sys.path.insert(0, ROOT)
    from guardian import updater
    key = updater.requirements_hash(UP, True)
    os.makedirs(f"{INST}/venvs/{key}/bin", exist_ok=True)
    if not os.path.exists(f"{INST}/venvs/{key}/bin/python"):
        os.symlink(PY, f"{INST}/venvs/{key}/bin/python")
    out = subprocess.run([PY, f"{ROOT}/tools/install.py", "--root", INST, "--source-dir", UP, "--gateway"],
                         env=dict(os.environ, GUARDIAN_DATA_DIR=DATA), capture_output=True, text=True)
    if out.returncode != 0:
        print(out.stdout, out.stderr)
        raise SystemExit("install failed")


def sup_state():
    with open(f"{DATA}/supervisor.json") as fh:
        return json.load(fh)


def wait_for_worker_change(old_pid, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st = sup_state()
            if st.get("worker_pid") and st["worker_pid"] != old_pid:
                time.sleep(1)
                return st
        except (OSError, ValueError):
            pass
        time.sleep(0.3)
    return sup_state()


def start_processes():
    if not os.path.exists(f"{W}/cert.pem"):
        sh(f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {W}/key.pem -out {W}/cert.pem "
           f"-days 3 -subj /CN=e2e.test")
    procs.append(subprocess.Popen(["ip", "netns", "exec", "pg-inet", PY, f"{HERE}/servers.py", f"{W}/cert.pem",
                                   f"{W}/key.pem"], stdout=open(f"{W}/servers.log", "w"), stderr=subprocess.STDOUT))
    install_like_the_pi()
    env = dict(os.environ, GUARDIAN_PASSWORD="e2e-password", GUARDIAN_DATA_DIR=DATA)
    subprocess.run([PY, f"{INST}/current/run.py", "--set-password"], env=env, check=True, capture_output=True)
    # pretend the gateway was last alive an hour ago (power cut / unplugged)
    import sqlite3
    c = sqlite3.connect(f"{W}/guardian.db")
    c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('heartbeat', ?)", (str(time.time() - 3600),))
    c.commit()
    c.close()
    # what the Pi's systemd unit runs: the supervisor, from <root>/current
    gw = subprocess.Popen(["ip", "netns", "exec", "pg-gw", f"{INST}/current/.venv/bin/python",
                           f"{INST}/current/run.py", "--supervise", "--no-download"],
                          env=dict(os.environ, GUARDIAN_DATA_DIR=DATA),
                          stdout=open(f"{W}/gateway.log", "w"), stderr=subprocess.STDOUT)
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
elif op["do"] == "raw":
    r = c.get(op["path"])
    print(json.dumps({"status": r.status_code, "len": len(r.text),
                      "markers": [m for m in op["body"]["markers"] if m in r.text]}))
elif op["do"] == "zip":
    import io, zipfile
    r = c.post(op["path"], json=op["body"].get("opts", {}), headers=H)
    z = zipfile.ZipFile(io.BytesIO(r.content))
    blobs = {n: z.read(n) for n in z.namelist()}
    print(json.dumps({"status": r.status_code, "disposition": r.headers.get("content-disposition"),
                      "names": sorted(blobs), "size": len(r.content),
                      "found": {s: sorted(n for n, b in blobs.items() if s.encode() in b) for s in op["body"]["search"]}}))
elif op["do"] == "badlogin":
    for _ in range(op["body"]["n"]):
        httpx.post("http://10.50.0.1:8080/api/login", json={"password": "wrong-guess"}, headers=H)
    print(json.dumps({"ok": True}))
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
    """ok=None records an explicit SKIP (shown, not counted as a pass)."""
    results.append({"section": section, "name": name, "ok": None if ok is None else bool(ok), "got": got})


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
        for k in ["dns_bypass_site", "sni_mismatch", "no_sni", "ech", "vpn_server", "doh_server",
                  "protocol_violation", "evasion", "server_first", "http_proxy", "blocked_udp", "blocked_port",
                  "bypass_domain", "tunnel_behaviour", "new_device"]:
            record(sec, k, k in kinds, (kinds.get(k) or {}).get("detail", "")[:110])
        dyn = api("get", "/api/rules")["dyn_blocks"]
        record(sec, "tunnel destination auto-blocked", any(d["ip"] == "198.51.100.79" for d in dyn), dyn[:1])

        # ---- Torrents and countermeasures
        run_suite("pg-parent", "parent_dhcp", "Torrents")
        run_suite("pg-kid", "kid_torrent", "Torrents")
        run_suite("pg-kid", "kid_sneaky", "Countermeasures")
        api("badlogin", "", {"n": 3})
        run_suite("pg-kid", "kid_clone_parent", "Countermeasures")
        time.sleep(1.5)
        run_suite("pg-parent", "parent_quarantined", "Countermeasures")
        api("post", f"/api/devices/{parent}/trust")
        time.sleep(1)
        run_suite("pg-parent", "parent", "Countermeasures: after the parent clicks \"It's me\"")
        run_suite("pg-kid", "kid_scan", "Countermeasures")
        time.sleep(1.5)
        run_suite("pg-kid", "kid_paused_after_attack", "Countermeasures")
        run_suite("pg-kid", "kid_l2_attacks", "Countermeasures")
        time.sleep(2)

        sec = "Countermeasure alerts (each rejected + flagged with confidence)"
        alerts = api("get", "/api/alerts?limit=1000")["alerts"]
        first = {}
        for a in alerts:
            first.setdefault(a["kind"], a)
        for k in ["torrent", "torrent_site", "torrent_peers", "torrent_lan", "custom_dns", "hidden_router",
                  "gateway_probe", "port_scan", "arp_spoof", "ip_spoof", "rogue_dhcp", "rogue_ra", "mac_spoof",
                  "dashboard_bruteforce", "gateway_offline"]:
            a = first.get(k)
            if k == "rogue_ra" and not os.path.exists("/proc/sys/net/ipv6"):
                record(sec, k, None, "kernel booted with IPv6 disabled - can't carry an IPv6 router "
                                     "advertisement (covered by unit test test_rogue_ra_and_torrent_lan)")
                continue
            record(sec, k, a is not None and a["confidence"] is not None,
                   f"{a['confidence']}% deliberate - {a['detail'][:90]}" if a else "missing")
        unscored = [a["kind"] for a in alerts if a["category"] != "info" and a["confidence"] is None]
        record(sec, "every alert carries a confidence score", not unscored, unscored[:5])
        devs = {d["ip"]: d for d in api("get", "/api/devices")["devices"]}
        record(sec, "kid auto-paused after attacking the network", devs["10.50.0.10"]["paused"],
               devs["10.50.0.10"]["paused_reason"])
        record(sec, "parent trusted again after 'It's me'", not devs["10.50.0.20"]["suspect"], "")

        sec = "Health dashboard"
        h = api("get", "/api/health?days=7")
        card = next(c for c in h["devices"] if c["device_id"] == kid)
        record(sec, "kid's card status is 'tampering'", card["status"] == "tampering", card["status"])
        record(sec, "attempts counted per category", all(card["by_category"][c] > 0 for c in
               ("vpn", "dns", "disguise", "torrent", "tamper")), card["by_category"])
        record(sec, "24-hour chart has data", sum(sum(v) for v in h["hourly"].values()) > 20,
               {c: sum(v) for c, v in h["hourly"].items()})
        record(sec, "blocked sites counted", card["blocked_total"] > 0, card["blocked_total"])
        record(sec, "gateway outage shows in checks", any(c["name"] == "Gateway uptime" and c["level"] == "warn"
                                                          for c in h["checks"]), h["checks"])
        nd = next(a for a in alerts if a["kind"] in ("no_dns", "no_sni"))
        r = api("post", f"/api/alerts/{nd['id']}/review", {"verdict": "fp"})
        h2 = api("get", "/api/health?days=7")
        record(sec, "'Not a bypass' review recorded and calibrates", h2["reviews"]["fp"] == h["reviews"]["fp"] + 1 and
               "no longer be blocked" in r["body"]["note"], r["body"])

        api("post", f"/api/devices/{kid}/pause", {"minutes": 0})
        time.sleep(1)

        # ---- Activity analysis: a game with YouTube in the background
        sec = "Live activity analysis"
        play = subprocess.Popen(["ip", "netns", "exec", "pg-console", PY, f"{HERE}/client.py", "console_play"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(14)
        lv = api("get", f"/api/live/{console}")
        now = lv["now"] or {}
        record(sec, "console: 'playing a game with YouTube in the background'",
               now.get("activity") == "gaming" and "video" in now.get("background", []) and
               "YouTube" in now.get("headline", ""), now.get("headline"))
        record(sec, "live series by activity (gaming + video both present)",
               any(p.get("gaming") for p in lv["series"]) and any(p.get("video") for p in lv["series"]),
               f"{len(lv['series'])} points")
        game_flow = [f for f in lv["flows"] if f["activity"] == "gaming"]
        record(sec, "the game connection itself is classified as gaming", bool(game_flow),
               [(f["dst_ip"], f["dst_port"], f["activity"]) for f in lv["flows"]][:5])
        overview = api("get", "/api/live")
        record(sec, "Live overview lists the console with its headline",
               any(d["device_id"] == console and "game" in d["headline"] for d in overview["devices"]),
               [(d["label"], d["headline"]) for d in overview["devices"]])
        play.wait(timeout=60)
        time.sleep(2)
        tl = api("get", f"/api/devices/{console}")["timeline"]
        record(sec, "today's timeline records the gaming session", any(t["activity"] == "gaming" for t in tl),
               [(t["activity"], t["headline"]) for t in tl])

        # ---- Download guard
        sec = "Download guard"
        run_suite("pg-kid", "kid_download", sec)
        dls = api("get", "/api/downloads")
        pend = [d for d in dls["pending"] if d["site"] == "mediafire.com"]
        record(sec, "held download waiting for review with a suspicion score",
               bool(pend) and pend[0]["score"] >= 50, pend[0]["reasons"] if pend else dls["pending"])
        if pend:
            r = api("post", f"/api/downloads/{pend[0]['id']}/approve")
            record(sec, "parent approves", r["status"] == 200, r["body"].get("note"))
            time.sleep(0.5)
            run_suite("pg-kid", "kid_download_retry", sec)
        run_suite("pg-kid", "kid_http_exe", sec)
        dls = api("get", "/api/downloads")
        exe = [d for d in dls["pending"] if d["filename"] == "FreeRobux-Setup.exe"]
        record(sec, "the .exe is waiting for review, file name shown", bool(exe), exe[:1])
        if exe:
            r = api("post", f"/api/downloads/{exe[0]['id']}/deny")
            record(sec, "parent denies", r["status"] == 200, r["body"].get("note"))
            run_suite("pg-kid", "kid_after_deny", sec)
        al = [a for a in api("get", "/api/alerts?limit=1000")["alerts"] if a["kind"] == "download_held"]
        record(sec, "held downloads also raise alerts with confidence",
               len(al) >= 2 and all(a["confidence"] for a in al), [(a["domain"], a["confidence"]) for a in al])

        # ---- Adult content: beyond the blocklists
        sec = "Adult content protection"
        run_suite("pg-kid", "kid_adult", sec)
        run_suite("pg-parent", "parent_adult", sec)
        rv = api("get", "/api/downloads")
        vid = [d for d in rv["pending"] if d.get("kind") == "video" and d["site"] == "unknown-tube.test"]
        record(sec, "unknown video waiting on the Reviews page", bool(vid), vid[0]["reasons"] if vid else rv["pending"])
        kinds = {a["kind"] for a in api("get", "/api/alerts?limit=1000")["alerts"]}
        for k in ["adult_site", "adult_keyword", "adult_family_dns", "adult_proxy", "content_mirror",
                  "unsafe_search", "video_held"]:
            record(sec, f"alert: {k}", k in kinds, "")
        h = api("get", "/api/health?days=7")
        record(sec, "Health counts the 'Adult content' category", h["totals"].get("adult", 0) > 0, h["totals"])

        sec = "VPN & Tor technology (servers on no list)"
        run_suite("pg-kid2", "kid2_vpn_app", sec)
        run_suite("pg-kid", "kid_tor", sec)
        run_suite("pg-console", "console_tor", sec)
        run_suite("pg-kid", "kid_unknown_dest", sec)
        alerts = api("get", "/api/alerts?limit=2000")["alerts"]
        by = {}
        for a in alerts:
            by.setdefault(a["kind"], []).append(a)
        fp = by.get("vpn_fingerprint", [])
        record(sec, "alert: tunnel software recognised on a new server (fingerprint kept as evidence)",
               bool(fp) and bool(fp[0].get("ref")), fp[0]["detail"][:120] if fp else "")
        record(sec, "alert: Tor named as Tor", "tor" in by, "")
        held = [d for d in api("get", "/api/downloads")["pending"] if d.get("kind") == "unknown"]
        record(sec, "unknown-destination tunnel waiting on the Reviews page", bool(held),
               held[0]["reasons"] if held else "")
        learned = api("get", "/api/rules")["fingerprints"]
        record(sec, "learned tunnel fingerprints listed", len(learned) >= 1,
               [(f["bad_label"], f["bad_source"]) for f in learned][:3])
        tool = [a for a in by.get("bypass_tool", []) if a["device_id"] == kid]
        record(sec, "escalation: the kid's device is named as running a bypass tool", bool(tool),
               tool[0]["detail"][:140] if tool else "")
        h = api("get", "/api/health?days=7")
        chk = [c for c in h["checks"] if c["name"] == "Unknown-destination protection"]
        record(sec, "Health: unknown-destination protection active", chk and chk[0]["level"] == "ok", chk)

        sec = "In-app guide"
        markers = ["How it works", "VPNs - what they are", "Stopping workarounds", "Adult content protection",
                   "Protecting the gateway itself", "Troubleshooting"]
        g = api("raw", "/static/docs.html", {"markers": markers})
        record(sec, "guide served to a signed-in parent", g["status"] == 200 and g["len"] > 20000, g["len"])
        record(sec, "guide covers features, how they work and the technology", g["markers"] == markers, g["markers"])
        ss = api("get", "/api/setup-summary")
        record(sec, "'your setup' summary reflects the live config", ss["mode"] == "gateway" and
               ss["adult"]["family_dns"] == ["198.51.100.54"], ss["adult"])

        # ---- First-run setup wizard (driven through its API, as the dashboard does)
        sec = "Setup wizard"
        w = api("get", "/api/wizard")
        chk = {c["title"]: c["status"] for c in w["environment"]["checks"]}
        record(sec, "detects the internet-side port (wan0)", chk.get("Internet side: wan0") == "ok", chk)
        record(sec, "detects the home-network port (lan0)", chk.get("Home network side: lan0") == "ok", chk)
        record(sec, "firewall reported as loaded", chk.get("Firewall") == "ok", chk)
        record(sec, "recognises the parent's own device", w["this_device"] == parent, w["this_device"])
        record(sec, "gateway ports are not offered as web settings", "dns_port" not in
               api("post", "/api/wizard/apply", {"values": {"dns_port": 5300}, "finish": False})["body"]["applied"])

        def kid_lookup(name):
            out = sh(nsx("pg-kid", f"{PY} -c \"from dnslib import DNSRecord; "
                                   f"r=DNSRecord.parse(DNSRecord.question('{name}').send('10.50.0.1', 53, timeout=3)); "
                                   f"print([str(a.rdata) for a in r.rr])\""), check=False)
            return out.stdout.strip()
        before = kid_lookup("archive.ph")
        cats = [c for c in w["values"]["categories"] if c != "mirrors"]
        r = api("post", "/api/wizard/apply", {"values": {"categories": cats}, "finish": False})
        after = kid_lookup("archive.ph")
        record(sec, "category change applies live, no restart (web archive unblocked for the kid)",
               r["body"]["restart_required"] == [] and before != after and "0.0.0.0" not in after, (before, after))
        api("post", "/api/wizard/apply", {"values": {"categories": cats + ["mirrors"]}, "finish": False})
        record(sec, "and blocked again", kid_lookup("archive.ph") == before, before)

        def restart_with(fail_open):
            r = api("post", "/api/wizard/apply", {"values": {"fail_open": fail_open}})
            before = sup_state()["worker_pid"]
            api("post", "/api/system/restart")
            wait_for_worker_change(before)
            for _ in range(60):
                if sh(nsx("pg-parent", "curl -s -o /dev/null -w %{http_code} http://10.50.0.1:8080/api/session"),
                      check=False).stdout == "200":
                    break
                time.sleep(0.5)
            return r["body"]["restart_required"]
        need = restart_with(True)
        record(sec, "fail-open/closed choice needs a restart", need == ["fail_open"], need)
        w2 = api("get", "/api/wizard")
        record(sec, "settings restart is a seamless hand-over (same service, new worker)",
               gw.poll() is None and w2["values"]["fail_open"] is True and w2["complete"], w2["values"]["fail_open"])
        restart_with(False)
        time.sleep(2)
        fw = [c for c in api("get", "/api/wizard")["environment"]["checks"] if c["title"] == "Firewall"]
        record(sec, "inspector running again after two restarts", fw and fw[0]["status"] == "ok", fw)
        rules = sh(nsx("pg-gw", "iptables -S FORWARD"), check=False).stdout
        q = [r for r in rules.splitlines() if "NFQUEUE" in r]
        record(sec, "no stale fail-open queue rule left behind", "--queue-bypass" not in rules and len(q) == 1, q)
        run_suite("pg-kid", "kid_basic", sec + ": filtering works after the restart")

        # ---- The dashboard's friendly address
        sec = "Dashboard address"

        def lookup(ns, name):
            out = sh(nsx(ns, f"{PY} -c \"from dnslib import DNSRecord; "
                             f"r=DNSRecord.parse(DNSRecord.question('{name}').send('10.50.0.1', 53, timeout=3)); "
                             f"print(','.join(str(a.rdata) for a in r.rr) or r.header.rcode)\""), check=False)
            return out.stdout.strip()
        record(sec, "family.home.arpa resolves to the gateway for the parent", lookup("pg-parent", "family.home.arpa") == "10.50.0.1",
               lookup("pg-parent", "family.home.arpa"))
        record(sec, "family.local resolves too", lookup("pg-parent", "family.local") == "10.50.0.1")
        record(sec, "a child's device can find the name", lookup("pg-kid", "family.home.arpa") == "10.50.0.1")
        code = sh(nsx("pg-parent", "curl -s -o /dev/null -w %{http_code} --max-time 5 "
                                   "--resolve family.home.arpa:80:10.50.0.1 http://family.home.arpa/api/session"),
                  check=False).stdout
        record(sec, "http://family.home.arpa opens the dashboard (port 80, no :8080)", code == "200", code)
        code = sh(nsx("pg-kid", "curl -s -o /dev/null -w %{http_code} --max-time 4 "
                                "--resolve family.home.arpa:80:10.50.0.1 http://family.home.arpa/"), check=False).stdout
        record(sec, "...but not from a child's device", code != "200", code)
        t0 = time.time()
        out = sh(nsx("pg-parent", "curl -s -o /dev/null -w %{http_code} --max-time 5 "
                                  "--resolve family.home.arpa:443:10.50.0.1 https://family.home.arpa/"), check=False)
        record(sec, "https:// is refused at once, so browsers fall back to http quickly",
               time.time() - t0 < 2 and out.stdout == "000", f"{time.time() - t0:.1f}s")
        api("post", "/api/wizard/apply", {"values": {"local_name": "smiths"}, "finish": False})
        record(sec, "renamed in the wizard: smiths.home.arpa works at once",
               lookup("pg-parent", "smiths.home.arpa") == "10.50.0.1" and lookup("pg-parent", "family.home.arpa") != "10.50.0.1")
        addr = api("get", "/api/address")
        record(sec, "address panel shows the name and a QR code", addr["primary"] == "http://smiths.local"
               and addr["qr_svg"].startswith("<svg"), addr["primary"])
        api("post", "/api/wizard/apply", {"values": {"local_name": "family"}, "finish": False})

        # ---- Protection switches, per group (the console's group; the kids keep theirs)
        sec = "Protection switches"

        def setp(group, key, value):
            r = api("post", "/api/protections", {"group": group, "key": key, "value": value})
            if r["status"] != 200:
                raise RuntimeError(r)
            time.sleep(1)
            return r["body"]
        b = setp("consoles", "tor", False)
        eff = {x["name"]: x["effective"] for x in b["groups"]}
        record(sec, "Tor off for consoles only", eff["consoles"]["tor"] is False and eff["kids"]["tor"] is True,
               {k: v["tor"] for k, v in eff.items()})
        run_suite("pg-console", "console_tor_off", sec)
        run_suite("pg-kid", "kid_tor", sec + ": the kid's group still blocks Tor")
        setp("consoles", "tor", None)
        run_suite("pg-console", "console_tor_on", sec)
        setp("consoles", "non_web", "allow")
        run_suite("pg-console", "console_open_vpn_on", sec)
        setp("consoles", "vpn", False)
        run_suite("pg-console", "console_open_vpn_off", sec)
        setp("consoles", "vpn", None)
        setp("consoles", "non_web", "games")
        run_suite("pg-console", "console_web_games", sec)
        run_suite("pg-console", "console_tor", sec + ": console back to normal")

        # ---- Seamless updates: a new version from the git repo, installed while
        # a child's device and the parent's laptop use the network non-stop
        sec = "Seamless update"
        upd = api("post", "/api/updates/settings", {"source": UP, "branch": "main", "subdir": "", "enabled": True,
                                                     "auto_install": False})
        record(sec, "update source set", upd["status"] == 200, upd["body"].get("detail") or upd["body"]["settings"])
        v1 = api("get", "/api/updates")["current"]
        with open(f"{UP}/VERSION", "w") as fh:
            fh.write("2.9.0\n")
        with open(f"{UP}/guardian/static/docs.html", "a") as fh:
            fh.write("\n<!-- update-marker-2.9.0 -->\n")
        git("commit", "-qam", "Better Tor detection")
        chk = api("post", "/api/updates/check")["body"]
        record(sec, "check finds the new version and what changed",
               chk["status"] == "available" and chk["latest"]["version"] == "2.9.0"
               and "Better Tor detection" in chk["latest"]["changes"], (chk["status"], chk.get("latest"), chk.get("error")))
        before = sup_state()
        nft_before = sh(nsx("pg-gw", "iptables -S FORWARD"), check=False).stdout
        env = dict(os.environ, PROBE_SECONDS="45")
        probes = [subprocess.Popen(["ip", "netns", "exec", ns, PY, f"{HERE}/client.py", suite], env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                  for ns, suite in (("pg-kid", "probe_kid"), ("pg-parent", "probe_parent"))]
        time.sleep(4)
        t0 = time.time()
        inst = api("post", "/api/updates/install")
        record(sec, "install started from the dashboard", inst["status"] == 200, inst["body"].get("detail"))
        st = {}
        while time.time() - t0 < 120:
            time.sleep(1)
            try:
                st = api("get", "/api/updates")
            except RuntimeError:
                continue
            if st.get("status") in ("installed", "failed"):
                break
        took = time.time() - t0
        record(sec, f"installed with no interruption ({took:.0f} s)", st.get("status") == "installed",
               (st.get("status"), st.get("message"), st.get("error")))
        for p in probes:
            out, err = p.communicate(timeout=120)
            for line in out.splitlines():
                r = json.loads(line)
                r["section"] = sec
                results.append(r)
            if p.returncode:
                record(sec, "probe crashed", False, err[-300:])
        after = sup_state()
        record(sec, "now running the new version", st.get("current", {}).get("version") == "2.9.0",
               st.get("current"))
        record(sec, "same service (supervisor), new worker, other queue",
               gw.poll() is None and after["supervisor_pid"] == before["supervisor_pid"]
               and after["worker_pid"] != before["worker_pid"] and after["slot"] != before["slot"],
               (before.get("slot"), after.get("slot")))
        q = [r for r in sh(nsx("pg-gw", "iptables -S FORWARD"), check=False).stdout.splitlines() if "NFQUEUE" in r]
        record(sec, "firewall moved to the new queue, old rule gone",
               len(q) == 1 and f"--queue-num {after['slot']}" in q[0], (q, [r for r in nft_before.splitlines() if "NFQUEUE" in r]))
        record(sec, "<root>/current points at the new release", os.path.realpath(f"{INST}/current") == after["release"])
        g = api("raw", "/static/docs.html", {"markers": ["update-marker-2.9.0"]})
        record(sec, "the new code is what's serving", g["markers"] == ["update-marker-2.9.0"])
        hist = st.get("history") or [{}]
        record(sec, "update history recorded", hist[0].get("ok") and hist[0]["to"]["version"] == "2.9.0", hist[:1])
        alerts = [a["kind"] for a in api("get", "/api/alerts?limit=50")["alerts"]]
        record(sec, "'update installed' noted in alerts", "update_installed" in alerts)

        # A broken version: the self-test stops it before it goes anywhere near the network
        sec = "Broken update is stopped"
        with open(f"{UP}/VERSION", "w") as fh:
            fh.write("3.0.0\n")
        with open(f"{UP}/guardian/localname.py", "a") as fh:
            fh.write("\n\ndef names(cfg):\n    raise RuntimeError('broken on purpose')\n")
        git("commit", "-qam", "A broken change")
        worker = sup_state()["worker_pid"]
        api("post", "/api/updates/check")
        api("post", "/api/updates/install")
        t0 = time.time()
        while time.time() - t0 < 120:
            time.sleep(1)
            st = api("get", "/api/updates")
            if st.get("status") in ("installed", "failed", "up_to_date"):
                break
        record(sec, "the update was refused by the self-test", st.get("status") == "failed"
               and "self-test" in (st.get("error") or ""), (st.get("status"), st.get("error")))
        record(sec, "still on the working version, same worker, nothing restarted",
               st.get("current", {}).get("version") == "2.9.0" and sup_state()["worker_pid"] == worker)
        run_suite("pg-kid", "kid_basic", sec + ": filtering unaffected")
        alerts = [a["kind"] for a in api("get", "/api/alerts?limit=50")["alerts"]]
        record(sec, "'update failed' noted in alerts", "update_failed" in alerts)

        # Going back to the previous version is a hand-over too
        sec = "Roll back"
        worker = sup_state()["worker_pid"]
        rb = api("post", "/api/updates/rollback")
        record(sec, "rollback started", rb["status"] == 200, rb["body"].get("detail"))
        wait_for_worker_change(worker)
        st = {}
        for _ in range(30):
            st = api("get", "/api/updates")
            if st.get("current", {}).get("version") == v1["version"]:
                break
            time.sleep(1)
        record(sec, "back on the previous version", st.get("current", {}).get("version") == v1["version"],
               st.get("current"))
        run_suite("pg-kid", "kid_basic", sec + ": filtering after the rollback")

        # ---- Diagnostics export (from the parent's laptop, as the dashboard button does)
        sec = "Diagnostics export"
        kid_mac = "02:00:00:00:00:10"
        d = api("zip", "/api/diagnostics", {"opts": {"note": "e2e: checking the export"},
                                            "search": [kid_mac, "10.50.0.10", "table inet guardian", "update complete",
                                                       "[ready] serving", "admin_hash", "e2e: checking the export"]})
        record(sec, "bundle downloads as a zip", d["status"] == 200 and "attachment" in (d["disposition"] or ""),
               (d["status"], d["size"]))
        record(sec, "contains the firewall rules", "system/nft-ruleset.txt" in d["found"]["table inet guardian"],
               d["found"]["table inet guardian"])
        record(sec, "contains the gateway's and the supervisor's logs (with the update hand-over)",
               "logs/gateway.log" in d["found"]["[ready] serving"] and "logs/supervisor.log" in d["found"]["update complete"],
               (d["found"]["[ready] serving"], d["found"]["update complete"]))
        record(sec, "the child's device address and MAC are anonymised everywhere",
               d["found"][kid_mac] == [] and d["found"]["10.50.0.10"] == [], (d["found"][kid_mac], d["found"]["10.50.0.10"]))
        record(sec, "no password hash in it", d["found"]["admin_hash"] == [] and "NOTE.txt" in d["found"]["e2e: checking the export"])
        out = sh(f"GUARDIAN_DATA_DIR={DATA} {PY} {INST}/current/run.py --diagnostics {W}", check=False)
        record(sec, "the command-line version works too (for when the dashboard won't open)",
               out.returncode == 0 and "Diagnostics written to" in out.stdout, out.stdout[-200:] + out.stderr[-200:])

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
    sys.exit(0 if results and all(r["ok"] is not False for r in results) else 1)


def report():
    section = None
    for r in results:
        if r["section"] != section:
            section = r["section"]
            print(f"\n== {section}")
        mark = "SKIP" if r["ok"] is None else ("PASS" if r["ok"] else "FAIL")
        extra = f"   ({r['got']})" if r["ok"] is None else \
            ("" if r["ok"] else f"   got={r.get('got')!r} want={r.get('want')!r}")
        print(f"  [{mark}] {r['name']}{extra}")
    n_ok = sum(1 for r in results if r["ok"])
    n_skip = sum(1 for r in results if r["ok"] is None)
    print(f"\n{n_ok}/{len(results) - n_skip} checks passed" + (f", {n_skip} skipped" if n_skip else ""))


if __name__ == "__main__":
    main()
