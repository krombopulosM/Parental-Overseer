"""The ready-made Raspberry Pi card ("appliance").

The card has no keyboard or screen, so on every start this:

1. reads settings the Card Maker left on the card's boot partition
   (``parental-gateway.txt``: the dashboard password's hash, the dashboard name)
   and applies them, then removes the password hash from the file;
2. works out which network port is which - the one where the ISP router hands
   out an address is the internet side, the other wired port is the home side -
   so either cable can go in either port;
3. with only one wired port (no USB adapter yet) runs as a DNS filter on the
   home network instead, and switches to full gateway mode when a second port
   appears (a udev rule re-runs this);
4. hands the system parts (home-side address, DHCP, mDNS) to deploy/netsetup.sh.

Run as ``python -m guardian.appliance boot`` by parental-gateway-appliance.service.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import subprocess
import sys
import time

SETTINGS_FILE = "parental-gateway.txt"
SETTINGS_SIZE = 4096                    # exactly one FAT cluster: the Card Maker patches it in place
MARKER = "# PGW-SETTINGS v1"
BOOT_DIRS = ("/boot/firmware", "/boot")
KEYS = ("password_hash", "dashboard_name", "lan_ip", "ssh_public_key")
ADMIN_USER = "pgadmin"
APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = "appliance-state.json"

TEMPLATE = f"""{MARKER}
# Parental Gateway - settings for the first start.
#
# The Card Maker fills these in for you. You can also edit this file with any
# text editor (it's on the card's "bootfs" drive). The gateway reads it each time
# it starts; a password is applied once and then removed from this file.
#
#   password_hash   the dashboard password, as written by the Card Maker
#                   (to reset a forgotten password, use the Card Maker's
#                   "Change the password on a card")
#   dashboard_name  the name you type to open the dashboard, e.g. family
#                   -> http://family.local
#   lan_ip          the gateway's address on your home network
#   ssh_public_key  optional, for technical users: lets this key log in over
#                   SSH as "pgadmin" (SSH is off unless this is set)
#
"""


# --------------------------------------------------------------- the settings file
def render_settings(values: dict | None = None) -> bytes:
    """The settings file, padded to exactly SETTINGS_SIZE bytes."""
    values = values or {}
    body = TEMPLATE + "".join(f"{k}={values.get(k, '') or ''}\n" for k in KEYS)
    for k, v in values.items():
        if k not in KEYS and v not in (None, ""):
            body += f"{k}={v}\n"
    raw = body.encode()
    if len(raw) > SETTINGS_SIZE - 2:
        raise ValueError("settings too long")
    return raw + b"#" + b" " * (SETTINGS_SIZE - len(raw) - 2) + b"\n"


def parse_settings(text: str | bytes) -> dict:
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip().lower(), v.strip()
        if v:
            out[k] = v
    return out


def find_settings(boot_dirs=None) -> str | None:
    for d in boot_dirs or BOOT_DIRS:
        p = os.path.join(d, SETTINGS_FILE)
        if os.path.isfile(p):
            return p
    return None


def apply_settings(path: str, db, local_cfg_path: str) -> list[str]:
    """Apply the card's settings; return what changed. The password hash is
    removed from the file afterwards (rewritten in place, same size)."""
    from .auth import Auth
    with open(path, "rb") as fh:
        vals = parse_settings(fh.read())
    done = []
    h = vals.pop("password_hash", None)
    if h:
        Auth(db).set_password_hash(h)
        done.append("password")
    updates = {}
    name = vals.get("dashboard_name", "").lower()
    if name:
        from .localname import valid_label
        if valid_label(name):
            updates.setdefault("web", {})["local_name"] = name
    lan_ip = vals.get("lan_ip")
    if lan_ip:
        try:
            iface = ipaddress.ip_interface(lan_ip if "/" in lan_ip else lan_ip + "/24")
            if iface.ip.is_private:
                updates.setdefault("appliance", {})["lan_ip"] = str(iface.ip)
                updates["appliance"]["lan_prefix"] = iface.network.prefixlen
        except ValueError:
            pass
    key = vals.get("ssh_public_key", "")
    if key and enable_ssh_key(key):
        done.append("ssh")
    if updates:
        before = read_local(local_cfg_path)
        merged = merge_local(local_cfg_path, updates)
        if merged != before:
            done += sorted(updates)
    if h:
        with open(path, "r+b") as fh:
            fh.write(render_settings(vals))
            fh.flush()
            os.fsync(fh.fileno())
    return done


SSH_KEY_RE = r"^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com) [A-Za-z0-9+/=]{40,}( [^\n]{0,200})?$"


def enable_ssh_key(key: str, home: str | None = None, run=subprocess.run) -> bool:
    import pwd
    import re
    key = key.strip()
    if not re.match(SSH_KEY_RE, key):
        return False
    try:
        pw = pwd.getpwnam(ADMIN_USER)
    except KeyError:
        return False
    home = home or pw.pw_dir
    d = os.path.join(home, ".ssh")
    os.makedirs(d, mode=0o700, exist_ok=True)
    path = os.path.join(d, "authorized_keys")
    try:
        with open(path) as fh:
            if key in fh.read():
                return False
    except FileNotFoundError:
        pass
    with open(path, "a") as fh:
        fh.write(key + "\n")
    os.chmod(path, 0o600)
    for p in (d, path):
        try:
            os.chown(p, pw.pw_uid, pw.pw_gid)
        except PermissionError:
            pass
    run(["systemctl", "enable", "--no-block", "--now", "ssh.service"], check=False)
    return True


# --------------------------------------------------------------- local config
def read_local(path: str) -> dict:
    import yaml
    try:
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError:
        return {}


def _deep(dst: dict, src: dict):
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep(dst[k], v)
        else:
            dst[k] = v


def merge_local(path: str, updates: dict) -> dict:
    import yaml
    cfg = read_local(path)
    _deep(cfg, updates)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path + ".tmp", "w") as fh:
        fh.write("# Machine-specific settings - written by the gateway and its setup wizard.\n"
                 "# Deep-merged over config.yaml.\n")
        yaml.safe_dump(cfg, fh, sort_keys=False, default_flow_style=False)
    os.replace(path + ".tmp", path)
    return cfg


# --------------------------------------------------------------- which port is which
def wired_interfaces(sys_net="/sys/class/net") -> list[str]:
    """Physical wired interfaces, built-in first (eth0 before a USB adapter)."""
    out = []
    for n in sorted(os.listdir(sys_net)):
        d = os.path.join(sys_net, n)
        if n == "lo" or os.path.isdir(os.path.join(d, "wireless")) or not os.path.exists(os.path.join(d, "device")):
            continue
        out.append(n)
    return sorted(out, key=lambda n: (not n.startswith("eth"), n))


def default_route_interface() -> str | None:
    try:
        r = subprocess.run(["ip", "-j", "-4", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        routes = json.loads(r.stdout or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    routes.sort(key=lambda x: x.get("metric", 0))
    return routes[0].get("dev") if routes else None


def choose_roles(wired: list[str], route_if: str | None, configured: tuple | None = None):
    """(wan, lan) - lan is None with a single port.

    A previous choice is kept while both its ports exist. Otherwise the port the
    ISP router gave an address to is the internet side; without one (router not
    up yet) the built-in port is."""
    if configured and configured[0] in wired and configured[1] in wired and configured[0] != configured[1]:
        return configured
    if not wired:
        return None, None
    wan = route_if if route_if in wired else wired[0]
    others = [w for w in wired if w != wan]
    return wan, (others[0] if others else None)


def wait_for_route(timeout: float) -> str | None:
    end = time.time() + timeout
    while True:
        r = default_route_interface()
        if r in wired_interfaces() or time.time() >= end:
            return r
        time.sleep(2)


def settle(timeout: int = 30):
    """Let the system finish naming network ports (a USB adapter can appear as
    eth1 and be renamed a moment later)."""
    try:
        subprocess.run(["udevadm", "settle", f"--timeout={timeout}"], capture_output=True, timeout=timeout + 5)
    except (OSError, subprocess.SubprocessError):
        pass


# --------------------------------------------------------------- dashboard setup window
def boot_age(proc_uptime="/proc/uptime") -> float:
    try:
        with open(proc_uptime) as fh:
            return float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        return float("inf")


def home_network(cfg: dict) -> list:
    nets = []
    if cfg.get("mode") == "gateway":
        for s in (cfg.get("gateway") or {}).get("lan_subnets") or []:
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                pass
    return nets


def setup_from_network(cfg: dict, ip: str, age: float | None = None) -> tuple[bool, str]:
    """On the card there's no keyboard to choose the password on: allow it from the
    home network for a while after the gateway starts. Restarting it (unplugging
    the power) opens the window again - someone who can do that can also take
    the card out, so it gives nothing away."""
    a = cfg.get("appliance") or {}
    minutes = float(a.get("setup_window_minutes") or 0)
    if not minutes:
        return False, ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, ""
    nets = home_network(cfg)
    inside = any(addr in n for n in nets) if nets else (addr.is_private and not addr.is_loopback)
    if not inside:
        return False, "Choose the password from a device on your home network."
    age = boot_age() if age is None else age
    if age > minutes * 60:
        return False, (f"For safety, the password can only be chosen in the first {int(minutes)} minutes after "
                       "the gateway starts. Unplug its power for 10 seconds, plug it back in, then reload this page.")
    return True, ""


# --------------------------------------------------------------- boot
def _netsetup(args: list[str]):
    script = os.path.join(APP_ROOT, "deploy", "netsetup.sh")
    r = subprocess.run(["bash", script, *args], capture_output=True, text=True, timeout=120)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r.returncode


def boot(route_timeout: float = 45.0) -> dict:
    from .config import data_dir, load_config, resolve_data_path
    from .db import DB
    cfg = load_config(os.path.join(APP_ROOT, "config.yaml"))
    local_path = os.path.join(data_dir(cfg), "config.local.yaml")
    report = {"time": time.time()}

    path = find_settings()
    if path:
        db = DB(resolve_data_path(cfg, cfg["database"]))
        try:
            report["applied"] = apply_settings(path, db, local_path)
        finally:
            db.close()
        cfg = load_config(os.path.join(APP_ROOT, "config.yaml"))

    gw = cfg.get("gateway") or {}
    a = cfg.get("appliance") or {}
    configured = (gw.get("wan_interface"), (gw.get("lan_interfaces") or [None])[0])
    settle()
    wired = wired_interfaces()
    route_if = default_route_interface()
    if not (configured[0] in wired and configured[1] in wired):
        route_if = wait_for_route(route_timeout)
        settle()
        wired = wired_interfaces()                   # names can change while waiting
    wan, lan = choose_roles(wired, route_if, configured if cfg.get("mode") == "gateway" else None)
    lan_ip = a.get("lan_ip") or "192.168.50.1"
    prefix = int(a.get("lan_prefix") or 24)
    report.update(wired=wired, route=route_if, wan=wan, lan=lan)

    old_mode = cfg.get("mode")
    if wan and lan:
        net = str(ipaddress.ip_interface(f"{lan_ip}/{prefix}").network)
        merge_local(local_path, {"mode": "gateway", "dns": {"listen_port": 53},
                                 "web": {"host": "0.0.0.0"},
                                 "gateway": {"wan_interface": wan, "lan_interfaces": [lan],
                                             "lan_ip": lan_ip, "lan_subnets": [net]}})
        report["mode"] = "gateway"
        report["netsetup"] = _netsetup(["gateway", wan, lan, f"{lan_ip}/{prefix}"])
    else:
        # One port: a DNS filter on the home network until the USB adapter is plugged in.
        merge_local(local_path, {"mode": "monitor", "dns": {"listen_port": 53, "listen_host": "0.0.0.0"},
                                 "web": {"host": "0.0.0.0"}})
        report["mode"] = "one_port"
        report["netsetup"] = _netsetup(["one_port", wan or ""])
    report["mode_changed"] = old_mode != ("gateway" if report["mode"] == "gateway" else "monitor")
    # The gateway must restart to use different ports (its firewall rules name them).
    report["changed"] = report["mode_changed"] or (report["mode"] == "gateway" and (wan, lan) != configured)
    with open(os.path.join(data_dir(cfg), STATE), "w") as fh:
        json.dump(report, fh)
    return report


def state(cfg: dict) -> dict | None:
    from .config import data_dir
    try:
        with open(os.path.join(data_dir(cfg), STATE)) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m guardian.appliance")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("boot", help="apply the card's settings and set up the network ports")
    b.add_argument("--restart-if-changed", action="store_true",
                   help="restart the gateway if its ports or mode changed (a port was plugged in or renamed)")
    sub.add_parser("settings-template", help="print the empty settings file")
    args = ap.parse_args(argv)
    if args.cmd == "settings-template":
        sys.stdout.buffer.write(render_settings())
        return 0
    rep = boot()
    print(json.dumps(rep))
    if args.restart_if_changed and rep.get("changed"):
        subprocess.run(["systemctl", "--no-block", "restart", "parental-gateway.service"], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())

