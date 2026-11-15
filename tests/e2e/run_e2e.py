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
INET_IPS = ["198.51.100.10", "198.51.100.53", "198.51.100.54", "198.51.100.66", "198.51.100.77",
            "198.51.100.78", "198.51.100.79", "198.51.100.80", "198.51.100.81", "198.51.100.82",
            "198.51.100.83", "198.51.100.84", "198.51.100.85", "198.51.100.86", "198.51.100.87",
            "198.51.100.88", "198.51.100.89", "198.51.100.90", "9.9.9.9", "192.168.1.1"]
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
        "bypass": {"files": [f"{b}/vpn.txt", f"{b}/doh.txt", f"{b}/bypass.txt"]},
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
    # pretend the gateway was last alive an hour ago (power cut / unplugged)
    import sqlite3
    c = sqlite3.connect(f"{W}/guardian.db")
    c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('heartbeat', ?)", (str(time.time() - 3600),))
    c.commit()
    c.close()
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
elif op["do"] == "raw":
    r = c.get(op["path"])
    print(json.dumps({"status": r.status_code, "len": len(r.text),
                      "markers": [m for m in op["body"]["markers"] if m in r.text]}))
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
        for k in ["no_dns", "dns_bypass_site", "sni_mismatch", "no_sni", "ech", "vpn_server", "doh_server",
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
        nd = next(a for a in alerts if a["kind"] == "no_dns")
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
            api("post", "/api/system/restart")
            time.sleep(2)
            for _ in range(60):
                if sh(nsx("pg-parent", "curl -s -o /dev/null -w %{http_code} http://10.50.0.1:8080/api/session"),
                      check=False).stdout == "200":
                    break
                time.sleep(0.5)
            return r["body"]["restart_required"]
        need = restart_with(True)
        record(sec, "fail-open/closed choice needs a restart", need == ["fail_open"], need)
        w2 = api("get", "/api/wizard")
        record(sec, "service restarted itself in place (same process) with the new setting",
               gw.poll() is None and w2["values"]["fail_open"] is True and w2["complete"], w2["values"]["fail_open"])
        restart_with(False)
        time.sleep(2)
        fw = [c for c in api("get", "/api/wizard")["environment"]["checks"] if c["title"] == "Firewall"]
        record(sec, "inspector running again after two restarts", fw and fw[0]["status"] == "ok", fw)
        rules = sh(nsx("pg-gw", "iptables -S FORWARD"), check=False).stdout
        record(sec, "no stale fail-open queue rule left behind", "--queue-bypass" not in rules,
               [r for r in rules.splitlines() if "NFQUEUE" in r])
        run_suite("pg-kid", "kid_basic", sec + ": filtering works after the restart")

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
