#!/usr/bin/env bash
# Turn a Raspberry Pi (Raspberry Pi OS Bookworm, 64-bit) into the family gateway.
#
#   ISP router ──(eth0, WAN)── Raspberry Pi ──(eth1, LAN: USB Ethernet adapter)── Wi-Fi access point
#
# Usage (from the project folder on the Pi):
#   sudo ./deploy/setup-pi.sh
# Override defaults with environment variables, e.g.:
#   sudo WAN_IF=eth0 LAN_IF=eth1 LAN_IP=192.168.50.1 ./deploy/setup-pi.sh
#
# Safe to re-run: it updates the installed copy and leaves your database,
# password and config.local.yaml alone.
set -euo pipefail

WAN_IF=${WAN_IF:-eth0}
LAN_IF=${LAN_IF:-eth1}
LAN_IP=${LAN_IP:-192.168.50.1}
LAN_PREFIX=${LAN_PREFIX:-24}
DHCP_START=${DHCP_START:-192.168.50.100}
DHCP_END=${DHCP_END:-192.168.50.250}
APP_DIR=${APP_DIR:-/opt/parental-gateway}
SRC="$(cd "$(dirname "$0")/.." && pwd)"

[ "$(id -u)" = 0 ] || { echo "Please run with sudo."; exit 1; }
ip link show "$WAN_IF" >/dev/null 2>&1 || { echo "WAN interface $WAN_IF not found (set WAN_IF=...)"; exit 1; }
ip link show "$LAN_IF" >/dev/null 2>&1 || {
  echo "LAN interface $LAN_IF not found. Plug in the USB Ethernet adapter, or set LAN_IF=... (see: ip link)"; exit 1; }
LAN_NET=$(python3 -c "import ipaddress; print(ipaddress.ip_interface('$LAN_IP/$LAN_PREFIX').network)")

echo "==> Installing packages"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3-venv python3-dev build-essential \
  libnetfilter-queue-dev nftables conntrack dnsmasq

echo "==> Installing app to $APP_DIR"
mkdir -p "$APP_DIR"
tar -C "$SRC" --exclude=.venv --exclude='guardian.db*' --exclude=config.local.yaml \
    --exclude=blocklists/cache --exclude=__pycache__ -cf - . | tar -C "$APP_DIR" -xf -
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt" -r "$APP_DIR/requirements-gateway.txt"

if [ ! -f "$APP_DIR/config.local.yaml" ]; then
  echo "==> Writing $APP_DIR/config.local.yaml"
  cat > "$APP_DIR/config.local.yaml" <<EOF
# Raspberry Pi overrides (deep-merged over config.yaml)
mode: gateway
dns:
  listen_port: 53
web:
  host: 0.0.0.0
  port: 8080
gateway:
  wan_interface: $WAN_IF
  lan_interfaces: [$LAN_IF]
  lan_ip: $LAN_IP
  lan_subnets: [$LAN_NET]
EOF
fi

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
dhcp-authoritative
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
EOF
systemctl enable -q dnsmasq
systemctl restart dnsmasq

if ss -lunp 2>/dev/null | grep -q "systemd-resolve.*:53 "; then
  echo "==> Freeing port 53 from systemd-resolved's stub listener"
  mkdir -p /etc/systemd/resolved.conf.d
  printf "[Resolve]\nDNSStubListener=no\n" > /etc/systemd/resolved.conf.d/parental-gateway.conf
  systemctl restart systemd-resolved
fi

echo "==> Service"
sed "s#/opt/parental-gateway#$APP_DIR#g" "$APP_DIR/deploy/parental-gateway.service" \
  > /etc/systemd/system/parental-gateway.service
systemctl daemon-reload
systemctl enable -q parental-gateway

if ! "$APP_DIR/.venv/bin/python" - "$APP_DIR" <<'PY'
import sys; sys.path.insert(0, sys.argv[1])
from guardian.config import load_config, resolve_path
from guardian.db import DB
from guardian.auth import Auth
cfg = load_config(sys.argv[1] + "/config.yaml")
db = DB(resolve_path(cfg, cfg["database"]))
ok = Auth(db).has_password(); db.close(); sys.exit(0 if ok else 1)
PY
then
  echo "==> Choose the dashboard password"
  (cd "$APP_DIR" && .venv/bin/python run.py --set-password)
fi

systemctl restart parental-gateway
sleep 3
systemctl --no-pager --lines=8 status parental-gateway || true

cat <<EOF

Done. Dashboard: http://$LAN_IP:8080  (from a device plugged into the LAN side)

Finish the setup:
  1. Put your Wi-Fi access point in "access point / bridge" mode (no DHCP or NAT of its own)
     and plug it into $LAN_IF. Every device must get its address from the Pi.
  2. Turn OFF the Wi-Fi on the ISP router and change its admin password - otherwise
     the kids can just join the ISP router's Wi-Fi and skip the Pi entirely.
  3. In the dashboard, move your own devices into "adults". Everything else stays
     filtered until you assign it.
  4. Keep the Pi and the routers somewhere the kids can't reach: unplugging cables
     is the one bypass software can't stop.
EOF
