#!/usr/bin/env bash
# Turn a Raspberry Pi (Raspberry Pi OS Bookworm, 64-bit) into the family gateway.
#
#   ISP router ──(eth0, WAN)── Raspberry Pi ──(eth1, LAN: USB Ethernet adapter)── Wi-Fi access point
#
# Usage (from the project folder on the Pi):
#   sudo ./deploy/setup-pi.sh
# It lists the network interfaces and asks which faces the internet and which
# faces your home. Or answer up front with environment variables, e.g.:
#   sudo WAN_IF=eth0 LAN_IF=eth1 LAN_IP=192.168.50.1 ./deploy/setup-pi.sh
#
# Safe to re-run: it updates the installed copy and leaves your database,
# password and config.local.yaml alone.
set -euo pipefail

APP_DIR=${APP_DIR:-/opt/parental-gateway}
DATA_DIR="$APP_DIR/data"
LOCAL_CFG="$DATA_DIR/config.local.yaml"
[ -f "$LOCAL_CFG" ] || { [ -f "$APP_DIR/config.local.yaml" ] && LOCAL_CFG_OLD="$APP_DIR/config.local.yaml"; }

# ---- which port is which? -------------------------------------------------
# Defaults: what a previous run chose, else the interface carrying the default
# route (internet side) and the first other wired interface (home side).
prev() {  # value of "key: x", "key: [x]" or "key:\n  - x" in the existing local config
  local f="$LOCAL_CFG"; [ -f "$f" ] || f="${LOCAL_CFG_OLD:-}"
  [ -n "$f" ] && [ -f "$f" ] || return 0
  awk -v k="$1" '
    want { if ($1 == "-") { print $2; exit } else exit }
    $1 == k":" { v = $2; gsub(/[][,]/, "", v); if (v != "") { print v; exit } want = 1 }' "$f"
}
ROUTE_IF=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
WIRED=$(for d in /sys/class/net/*; do n=${d##*/}; [ "$n" = lo ] && continue
        [ -d "$d/wireless" ] && continue; [ -e "$d/device" ] && echo "$n"; done)
DEF_WAN=$(prev wan_interface); DEF_WAN=${DEF_WAN:-${ROUTE_IF:-eth0}}
DEF_LAN=$(prev lan_interfaces); DEF_LAN=${DEF_LAN:-$(echo "$WIRED" | grep -vx "$DEF_WAN" | head -1)}; DEF_LAN=${DEF_LAN:-eth1}
if [ -t 0 ] && [ -z "${WAN_IF:-}" ] && [ -z "${LAN_IF:-}" ]; then
  echo "Network interfaces on this Pi:"
  for d in /sys/class/net/*; do n=${d##*/}; [ "$n" = lo ] && continue
    kind=ethernet; [ -d "$d/wireless" ] && kind=wifi; [ -e "$d/device" ] || kind=virtual
    addr=$(ip -4 -o addr show dev "$n" 2>/dev/null | awk '{print $4}' | paste -sd, -)
    note=""; [ "$n" = "$ROUTE_IF" ] && note="  <- internet route goes this way"
    printf "  %-12s %-9s %-6s %-18s%s\n" "$n" "$kind" "$(cat "$d/operstate" 2>/dev/null)" "${addr:--}" "$note"
  done
  echo
  echo "The INTERNET side is the port cabled to your ISP router."
  read -r -p "Internet-side interface [$DEF_WAN]: " WAN_IF
  echo "The HOME side is the port cabled to your Wi-Fi access point / switch (often a USB Ethernet adapter)."
  read -r -p "Home-network interface [$DEF_LAN]: " LAN_IF
  [ "${WAN_IF:-$DEF_WAN}" != "${LAN_IF:-$DEF_LAN}" ] || { echo "The two sides must be different interfaces."; exit 1; }
fi
WAN_IF=${WAN_IF:-$DEF_WAN}
LAN_IF=${LAN_IF:-$DEF_LAN}
LAN_IP=${LAN_IP:-192.168.50.1}
LAN_PREFIX=${LAN_PREFIX:-24}
DHCP_START=${DHCP_START:-192.168.50.100}
DHCP_END=${DHCP_END:-192.168.50.250}
SRC="$(cd "$(dirname "$0")/.." && pwd)"

[ "$(id -u)" = 0 ] || { echo "Please run with sudo."; exit 1; }
ip link show "$WAN_IF" >/dev/null 2>&1 || { echo "WAN interface $WAN_IF not found (set WAN_IF=...)"; exit 1; }
ip link show "$LAN_IF" >/dev/null 2>&1 || {
  echo "LAN interface $LAN_IF not found. Plug in the USB Ethernet adapter, or set LAN_IF=... (see: ip link)"; exit 1; }
LAN_NET=$(python3 -c "import ipaddress; print(ipaddress.ip_interface('$LAN_IP/$LAN_PREFIX').network)")

echo "==> Installing packages"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3-venv python3-dev build-essential \
  libnetfilter-queue-dev nftables conntrack dnsmasq tcpdump avahi-daemon avahi-utils git

# An installation from before seamless updates runs without the supervisor: stop
# it once (the firewall stays up, so filtered devices wait) - this is the only
# time setup ever interrupts the gateway. With the supervisor running, a re-run
# is installed like any update: alongside, then handed over with no gap.
SUPERVISED=0
if systemctl is-active -q parental-gateway 2>/dev/null; then
  if grep -q -- "--supervise" /etc/systemd/system/parental-gateway.service 2>/dev/null; then
    SUPERVISED=1
  else
    echo "==> Stopping the old service once to move it to the new layout"
    systemctl stop parental-gateway
  fi
fi

echo "==> Installing app to $APP_DIR (releases/, current, data/)"
mkdir -p "$APP_DIR"
INSTALL_OUT=$(python3 "$SRC/tools/install.py" --root "$APP_DIR" --gateway --python /usr/bin/python3 \
              $([ "$SUPERVISED" = 1 ] && echo --switch) | tee /dev/stderr | tail -1)
PY="$APP_DIR/current/.venv/bin/python"
export GUARDIAN_DATA_DIR="$DATA_DIR"

echo "==> Writing $LOCAL_CFG (internet: $WAN_IF, home: $LAN_IF)"
# Merge, don't overwrite: the dashboard's setup wizard keeps its choices in the same file.
WAN_IF="$WAN_IF" LAN_IF="$LAN_IF" LAN_IP="$LAN_IP" LAN_NET="$LAN_NET" LOCAL_CFG="$LOCAL_CFG" \
INSTALL_OUT="$INSTALL_OUT" "$PY" - <<'PY'
import json, os, yaml
path = os.environ["LOCAL_CFG"]
cfg = {}
if os.path.exists(path):
    with open(path) as fh:
        cfg = yaml.safe_load(fh) or {}
cfg["mode"] = "gateway"
cfg.setdefault("dns", {})["listen_port"] = 53
web = cfg.setdefault("web", {})
web["host"] = "0.0.0.0"
web.setdefault("port", 8080)
gw = cfg.setdefault("gateway", {})
gw.update(wan_interface=os.environ["WAN_IF"], lan_interfaces=[os.environ["LAN_IF"]],
          lan_ip=os.environ["LAN_IP"], lan_subnets=[os.environ["LAN_NET"]])
# Updates come from where this copy came from (if it's a git checkout), unless set already.
try:
    origin = json.loads(os.environ.get("INSTALL_OUT") or "{}").get("origin") or {}
except ValueError:
    origin = {}
upd = cfg.setdefault("updates", {})
if origin.get("source") and not upd.get("source"):
    upd.update(source=origin["source"], branch=origin.get("branch") or "main", subdir=origin.get("subdir") or "")
with open(path + ".tmp", "w") as fh:
    fh.write("# Machine-specific settings - written by setup-pi.sh and the dashboard's setup wizard.\n"
             "# Deep-merged over config.yaml.\n")
    yaml.safe_dump(cfg, fh, sort_keys=False, default_flow_style=False)
os.replace(path + ".tmp", path)
PY

echo "==> Kernel settings"
cat > /etc/sysctl.d/90-parental-gateway.conf <<EOF
# Forwarding stays OFF at boot; the gateway switches it on only after its
# firewall rules are loaded, so there is never an unfiltered window.
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
net.netfilter.nf_conntrack_acct=1
EOF
printf "nf_conntrack\nnfnetlink_queue\nnft_queue\n" > /etc/modules-load.d/parental-gateway.conf
for m in nf_conntrack nfnetlink_queue nft_queue; do modprobe "$m" 2>/dev/null || true; done
sysctl -q --system || true

echo "==> LAN address $LAN_IP/$LAN_PREFIX on $LAN_IF"
if command -v nmcli >/dev/null && systemctl is-active -q NetworkManager; then
  nmcli -t con delete pg-lan >/dev/null 2>&1 || true
  nmcli con add type ethernet ifname "$LAN_IF" con-name pg-lan ipv4.method manual \
    ipv4.addresses "$LAN_IP/$LAN_PREFIX" ipv6.method disabled connection.autoconnect yes >/dev/null
  nmcli con up pg-lan >/dev/null || true
elif [ -f /etc/dhcpcd.conf ]; then
  grep -q "# parental-gateway" /etc/dhcpcd.conf || cat >> /etc/dhcpcd.conf <<EOF

# parental-gateway
interface $LAN_IF
static ip_address=$LAN_IP/$LAN_PREFIX
nohook wpa_supplicant
EOF
  systemctl restart dhcpcd || true
else
  echo "   !! Couldn't find NetworkManager or dhcpcd - give $LAN_IF the address $LAN_IP/$LAN_PREFIX yourself."
fi

echo "==> DHCP server (dnsmasq hands out addresses; DNS is answered by the gateway)"
cat > /etc/dnsmasq.d/parental-gateway.conf <<EOF
port=0
interface=$LAN_IF
bind-interfaces
dhcp-range=$DHCP_START,$DHCP_END,12h
dhcp-option=option:router,$LAN_IP
dhcp-option=option:dns-server,$LAN_IP
# search domain: "family" alone finds family.home.arpa (the dashboard)
dhcp-option=option:domain-name,home.arpa
dhcp-option=option:domain-search,home.arpa
dhcp-authoritative
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
EOF
systemctl enable -q dnsmasq
systemctl restart dnsmasq

echo "==> Announcing the dashboard name on the home network (mDNS)"
# Only on the home side: nothing about this network is announced towards the ISP router.
AVAHI_CONF=/etc/avahi/avahi-daemon.conf
if [ -f "$AVAHI_CONF" ]; then
  if grep -q "^#\?allow-interfaces=" "$AVAHI_CONF"; then
    sed -i "s/^#\?allow-interfaces=.*/allow-interfaces=$LAN_IF/" "$AVAHI_CONF"
  else
    sed -i "/^\[server\]/a allow-interfaces=$LAN_IF" "$AVAHI_CONF"
  fi
fi
systemctl enable -q avahi-daemon 2>/dev/null || true
systemctl restart avahi-daemon 2>/dev/null || true
DASH_NAME=$("$PY" - "$APP_DIR/current" <<'PY' 2>/dev/null || echo family
import sys; sys.path.insert(0, sys.argv[1])
from guardian.config import load_config
from guardian.localname import base_name
print(base_name(load_config(sys.argv[1] + "/config.yaml")))
PY
)

if ss -lunp 2>/dev/null | grep -q "systemd-resolve.*:53 "; then
  echo "==> Freeing port 53 from systemd-resolved's stub listener"
  mkdir -p /etc/systemd/resolved.conf.d
  printf "[Resolve]\nDNSStubListener=no\n" > /etc/systemd/resolved.conf.d/parental-gateway.conf
  systemctl restart systemd-resolved
fi

echo "==> Service"
sed "s#/opt/parental-gateway#$APP_DIR#g" "$APP_DIR/current/deploy/parental-gateway.service" \
  > /etc/systemd/system/parental-gateway.service
systemctl daemon-reload
systemctl enable -q parental-gateway

if ! "$PY" - "$APP_DIR/current" <<'PY'
import sys; sys.path.insert(0, sys.argv[1])
from guardian.config import load_config, resolve_data_path
from guardian.db import DB
from guardian.auth import Auth
cfg = load_config(sys.argv[1] + "/config.yaml")
db = DB(resolve_data_path(cfg, cfg["database"]))
ok = Auth(db).has_password(); db.close(); sys.exit(0 if ok else 1)
PY
then
  echo "==> Choose the dashboard password"
  (cd "$APP_DIR/current" && "$PY" run.py --set-password)
fi

# Already supervised: the new version took over above, nothing to restart.
[ "$SUPERVISED" = 1 ] || systemctl restart parental-gateway
sleep 3
systemctl --no-pager --lines=8 status parental-gateway || true

cat <<EOF

Done. Open the dashboard from any device at home:

    http://$DASH_NAME.local
    (or http://$DASH_NAME.home.arpa, or http://$LAN_IP)

The name can be changed in the dashboard's setup wizard.
Updates are checked every hour and installed with no interruption
(System -> Updates in the dashboard).

Finish the setup:
  1. Put your Wi-Fi access point in "access point / bridge" mode (no DHCP or NAT of its own)
     and plug it into $LAN_IF. Every device must get its address from the Pi.
  2. Turn OFF the Wi-Fi on the ISP router and change its admin password - otherwise
     the kids can just join the ISP router's Wi-Fi and skip the Pi entirely.
  3. Open the dashboard and sign in: the setup wizard walks you through the protection
     level, what to block, whose devices are whose, bedtime and privacy.
     Everything stays filtered until you assign it.
  4. Keep the Pi and the routers somewhere the kids can't reach: unplugging cables
     is the one bypass software can't stop.
EOF
