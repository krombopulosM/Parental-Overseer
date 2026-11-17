"""`python run.py --windows-check`: does blocking really work on this Windows PC?

Run from an Administrator command prompt. It starts a private copy of the
gateway in blocking mode (its own temporary settings and database - your real
ones aren't touched), treats this PC as a child's device, and then tries what a
child would: a normal site, an adult site, encrypted DNS, a bare IP address, a
known VPN server, a Tor-shaped connection, WireGuard, QUIC. Each result is
compared with what the Raspberry Pi would do. With --hotspot SECONDS it also
watches for devices on this PC's Mobile Hotspot.

The report is printed and saved as windows-check-report.txt (addresses
anonymised) - paste it back to whoever is helping you. When it finishes the
packet filter is released and the PC is back to normal.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request

RESULTS: list[dict] = []


def _rec(name, ok, got, want, note=""):
    RESULTS.append({"check": name, "ok": ok, "got": got, "want": want, "note": note})
    mark = "PASS" if ok else ("SKIP" if ok is None else "FAIL")
    print(f"  [{mark}] {name}: {got}" + (f"   (want {want})" if ok is False else ""), flush=True)


def _resolve(name):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)})
    except socket.gaierror as e:
        return f"refused ({e.errno})"


def _tls(ip, sni, timeout=6):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.socket()
    raw.settimeout(timeout)
    try:
        raw.connect((ip, 443))
        s = ctx.wrap_socket(raw, server_hostname=sni)
        s.close()
        return "connected"
    except (ConnectionResetError, ConnectionAbortedError):
        return "reset"
    except (socket.timeout, TimeoutError):
        return "timeout"
    except ssl.SSLError as e:
        return "reset" if "EOF" in str(e) or "reset" in str(e).lower() else f"tls error ({e.reason})"
    except OSError as e:
        return f"error ({e.errno})"
    finally:
        raw.close()


def _udp(ip, port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(payload, (ip, port))
    except OSError:
        pass
    finally:
        s.close()


def _flushdns():
    if shutil.which("ipconfig"):
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)


def run(config_path: str, hotspot_seconds: int = 0) -> int:
    print("Parental Gateway - Windows blocking check\n")
    if not sys.platform.startswith("win"):
        print("This check is for Windows. On Linux, run: sudo python3 tests/e2e/run_e2e.py")
        return 2
    from .environment import is_admin
    from .gateway.windivert import DivertHandle, available
    env = {"windows": platform.platform(), "python": sys.version.split()[0], "admin": is_admin()}
    ok, why = available()
    env["pydivert"] = ok or why
    if not is_admin():
        print("Please run this from an Administrator command prompt (right-click > Run as administrator).")
        return 2
    if not ok:
        print(f"Can't use the packet filter: {why}")
        return 2
    try:
        DivertHandle("false").close()
        env["driver"] = "loads"
    except Exception as e:
        print(f"The WinDivert driver couldn't be loaded: {e}\n"
              "If antivirus quarantined WinDivert64.sys, allow it (it's the packet filter this program uses).")
        return 2

    from .config import load_config, resolve_data_path
    real = load_config(config_path)
    tmp = tempfile.mkdtemp(prefix="pg-wincheck-")
    with open(os.path.join(tmp, "config.local.yaml"), "w") as fh:
        json.dump({"mode": "gateway", "database": os.path.join(tmp, "check.db"),
                   "lists_cache_dir": resolve_data_path(real, real.get("lists_cache_dir", "blocklists/cache")),
                   "dns": {"listen_host": "127.0.0.1", "listen_port": 5399},
                   "updates": {"enabled": False}, "windows": {"hotspot": True}}, fh)   # JSON is valid YAML
    os.environ["GUARDIAN_DATA_DIR"] = tmp
    cfg = load_config(config_path)
    from .app import Guardian
    g = Guardian(cfg)
    g.monitor = g.detector = None                     # the check needs blocking only
    gw = g.gateway
    gw._discover()
    g.db.update_device(gw.local_mac, name="This PC (check)", group="kids", set_group=True)
    g.db.flush()
    g.policy.reload()
    t0 = time.time()
    try:
        g.start(download_lists=False)
    except Exception as e:
        print(f"Couldn't start blocking: {e}")
        traceback.print_exc()
        return 1
    env["start_s"] = round(time.time() - t0, 1)
    env["handles"] = gw.status.get("handles")
    env["hotspot"] = gw.status.get("hotspot")
    env["lists"] = {k.split(":", 1)[1]: v["entries"] for k, v in g.lists.status.items()}
    print(f"Blocking is on for this PC (filters: {', '.join(env['handles'] or [])}). Trying what a child would…\n")
    _flushdns()
    time.sleep(0.5)
    try:
        r = _resolve("example.com")
        _rec("normal site resolves", isinstance(r, list), r, "addresses")
        r2 = _resolve("pornhub.com")
        _rec("adult site doesn't resolve", not isinstance(r2, list), r2, "refused")
        r3 = _resolve("dns.google")
        _rec("encrypted-DNS service doesn't resolve", not isinstance(r3, list), r3, "refused")
        try:
            with urllib.request.urlopen("https://example.com/", timeout=15) as resp:
                got = f"HTTP {resp.status}"
        except Exception as e:
            got = f"failed ({e})"
        _rec("normal website opens", got.startswith("HTTP 2"), got, "HTTP 200")
        got = _tls("1.1.1.1", "one.one.one.one")
        _rec("connecting to a bare IP address is blocked", got != "connected", got, "reset / timeout",
             "a hard-coded VPN or DNS address")
        vpn = None
        s = g.lists.ip_sets.get("vpn")
        if s is not None:
            for c in s.cidrs(4):
                vpn = c.split("/")[0]
                break
        if vpn:
            got = _tls(vpn, "vpn.example")
            _rec("a known VPN server is blocked", got != "connected", got, "reset / timeout", vpn)
            before = gw.stats["drop"]
            _udp(vpn, 51820, b"\x01\x00\x00\x00" + os.urandom(144))
            time.sleep(1)
            _rec("WireGuard handshake is dropped", gw.stats["drop"] > before, f"{gw.stats['drop'] - before} dropped",
                 "dropped")
        else:
            _rec("a known VPN server is blocked", None, "no VPN server list loaded", "",
                 "run python run.py --update-lists once, then retry")
        if isinstance(r, list) and r:
            got = _tls(r[0], "www.k3jd6a2bq7x.com")
            _rec("a Tor-shaped connection is blocked", got != "connected", got, "reset / timeout",
                 "made-up site name to a real address")
            before = gw.stats["drop"]
            _udp(r[0], 443, bytes([0xC3]) + b"\x00\x00\x00\x01" + os.urandom(1200))
            time.sleep(1)
            _rec("QUIC is turned off (browsers fall back to visible HTTPS)", gw.stats["drop"] > before,
                 f"{gw.stats['drop'] - before} dropped", "dropped")
        kinds = sorted({a["kind"] for a in g.db.alerts(since=t0 - 5, limit=500)})
        _rec("each block was recorded as an alert", bool({"no_dns", "vpn_server", "tor", "sni_mismatch"} & set(kinds)),
             kinds, "no_dns / vpn_server / tor …")
        if hotspot_seconds:
            print(f"\nHotspot: turn on Settings > Network > Mobile hotspot, connect a phone to it and browse for "
                  f"{hotspot_seconds} s…", flush=True)
            deadline = time.time() + hotspot_seconds
            while time.time() < deadline:
                time.sleep(2)
            env["hotspot"] = gw.hotspot_up()
            seen = sorted(gw.seen_hotspot_clients)
            _rec("hotspot devices go through the filter", bool(seen) if gw.hotspot_up() else None,
                 f"{len(seen)} device(s) seen" if gw.hotspot_up() else "hotspot is off", "at least 1",
                 "forwarded packets reached the inspector" if seen else "")
    finally:
        env["engine_stats"] = dict(gw.stats)
        env["inspector_stats"] = dict(g.inspector.stats)
        g.shutdown(handover=False)
        gw.teardown()
        _flushdns()
    failed = [r for r in RESULTS if r["ok"] is False]
    report = {"environment": env, "results": RESULTS, "passed": sum(1 for r in RESULTS if r["ok"]),
              "failed": len(failed)}
    from .diagnostics import Redactor
    text = Redactor(True).text(json.dumps(report, indent=1, default=str))
    out = os.path.join(os.getcwd(), "windows-check-report.txt")
    try:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError:
        out = os.path.join(tmp, "windows-check-report.txt")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(f"\n{report['passed']} passed, {len(failed)} failed. The packet filter is off again.")
    print(f"Report saved to {out} - paste its contents back to whoever is helping you.")
    return 0 if not failed else 1
