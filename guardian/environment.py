"""What is this machine, and is it ready to do its job?

Used by the setup wizard's "How it runs" step: detects the platform, admin
rights, network interfaces and capture support, and turns that into a short
checklist of things that are fine, worth a look, or blocking.
"""
from __future__ import annotations

import os
import platform
import socket
import sys


def _read(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return None


def is_admin() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_raspberry_pi() -> bool:
    model = _read("/proc/device-tree/model") or ""
    return "raspberry pi" in model.lower()


def default_route_iface() -> str | None:
    """Interface carrying the default route (Linux): the likely internet side."""
    text = _read("/proc/net/route")
    if not text:
        return None
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) > 2 and parts[1] == "00000000":
            return parts[0]
    return None


def _ipv4_addrs() -> dict[str, list[str]]:
    """Interface -> IPv4 addresses (Linux, via `ip -4 -o addr`)."""
    import subprocess
    out: dict[str, list[str]] = {}
    try:
        text = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True,
                              timeout=3).stdout
    except Exception:
        return out
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet":
            out.setdefault(parts[1].split("@")[0], []).append(parts[3])
    return out


def interfaces() -> list[dict]:
    if not sys.platform.startswith("linux") or not os.path.isdir("/sys/class/net"):
        return []
    addrs = _ipv4_addrs()
    wan = default_route_iface()
    res = []
    for name in sorted(os.listdir("/sys/class/net")):
        if name == "lo":
            continue
        base = f"/sys/class/net/{name}"
        kind = "wifi" if os.path.isdir(f"{base}/wireless") else (
            "virtual" if not os.path.exists(f"{base}/device") else "ethernet")
        res.append({"name": name, "mac": _read(f"{base}/address"), "state": _read(f"{base}/operstate"),
                    "kind": kind, "ipv4": addrs.get(name, []), "default_route": name == wan})
    return res


def port_bindable(port: int, host: str = "0.0.0.0") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def capture_available() -> bool:
    try:
        from .flows.sniffer import SnifferBackend
        return bool(SnifferBackend.available())
    except Exception:
        return False


def detect(cfg: dict, guardian=None) -> dict:
    mode = cfg.get("mode", "monitor")
    gw = cfg.get("gateway") or {}
    env = {
        "platform": platform.system() or sys.platform, "release": platform.release(),
        "python": platform.python_version(), "hostname": socket.gethostname(),
        "raspberry_pi": is_raspberry_pi(), "admin": is_admin(),
        "systemd": bool(os.environ.get("INVOCATION_ID")), "mode": mode,
        "interfaces": interfaces(), "wan_guess": default_route_iface(),
        "configured": {"wan": gw.get("wan_interface"),
                       "lan": (gw.get("lan_interfaces") or [None])[0] or gw.get("lan_interface"),
                       "lan_ip": gw.get("lan_ip")},
        "dns_port": (cfg.get("dns") or {}).get("listen_port"),
        "web": {"host": (cfg.get("web") or {}).get("host"), "port": (cfg.get("web") or {}).get("port")},
    }
    checks = []

    def check(status, title, detail):
        checks.append({"status": status, "title": title, "detail": detail})

    names = {i["name"] for i in env["interfaces"]}
    if mode == "gateway":
        check("ok" if sys.platform.startswith("linux") else "bad", "Linux",
              "Gateway mode runs on Linux (the Raspberry Pi).")
        check("ok" if env["admin"] else "bad", "Running as root",
              "Needed to manage the firewall and hand out addresses." if env["admin"] else
              "Gateway mode must run as root - use the systemd service that setup-pi.sh installs.")
        for role in ("wan", "lan"):
            ifn = env["configured"][role]
            label = "Internet side" if role == "wan" else "Home network side"
            if not ifn:
                check("bad", label, "No interface configured - run deploy/setup-pi.sh.")
            elif ifn not in names and names:
                check("bad", f"{label}: {ifn}", "This interface doesn't exist on this machine. "
                      "Run deploy/setup-pi.sh again to pick the right one.")
            else:
                info = next((i for i in env["interfaces"] if i["name"] == ifn), {})
                up = info.get("state") in ("up", "unknown", None)
                check("ok" if up else "warn", f"{label}: {ifn}",
                      ", ".join(info.get("ipv4") or []) or ("up" if up else "cable unplugged or link down"))
        if env["configured"]["wan"] and env["wan_guess"] and env["configured"]["wan"] != env["wan_guess"]:
            check("warn", "Default route", f"The internet route currently goes via {env['wan_guess']}, not "
                  f"{env['configured']['wan']}. That's expected only while you're setting up.")
        if guardian is not None and guardian.gateway is not None:
            st = guardian.gateway.status or {}
            nfq = guardian.nfq
            if not st.get("applied"):
                check("bad", "Firewall", f"Rules not loaded: {st.get('error') or 'not started yet'}")
            elif nfq is not None and not nfq.running:
                check("bad", "Firewall", f"Rules loaded, but the inspector isn't running"
                      f"{': ' + nfq.error if nfq.error else ''}. Children's new connections wait until it is.")
            else:
                check("ok", "Firewall", f"Rules loaded, inspector running ({guardian.gateway.backend} backend).")
    else:
        check("ok", "Monitor mode", "Runs alongside your normal network: it filters devices that use it for "
              "DNS and watches traffic this machine can see. Nothing is blocked at the network level.")
        check("ok" if env["admin"] else "warn", "Administrator rights",
              "Present." if env["admin"] else
              "Not running as administrator - port 53 and traffic capture usually need it.")
        cap = capture_available()
        check("ok" if cap else "warn", "Traffic capture",
              "Available (scapy + packet driver)." if cap else
              "Not available - install Npcap (Windows) or run as root (Linux) to see live activity. "
              "DNS filtering still works.")
        running = env["dns_port"]
        if guardian is not None and getattr(guardian, "dns_servers", None):
            check("ok", f"DNS on port {running}", "Listening." + (
                "" if running == 53 else " Devices only use port 53, so this port is for testing; "
                "choose 53 below to filter real devices."))
        elif running == 53 or port_bindable(53):
            check("ok", "Port 53 available", "This machine can serve DNS to devices.")
        else:
            check("warn", "Port 53", "Port 53 is busy or needs administrator rights.")
    if guardian is not None:
        bad_lists = [k for k, v in (guardian.lists.status or {}).items() if not v.get("entries")]
        check("ok" if not bad_lists else "warn", "Blocklists",
              "Loaded." if not bad_lists else
              f"Some lists are empty until the first download finishes: {', '.join(sorted(bad_lists)[:5])}.")
    env["checks"] = checks
    return env
