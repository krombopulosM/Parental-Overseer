#!/usr/bin/env bash
# The system side of the Pi's network roles. Used by setup-pi.sh and, on the
# ready-made card, by `python -m guardian.appliance boot` at every start.
#
#   netsetup.sh gateway  <wan-if> <lan-if> <lan-ip/prefix>
#       home side gets a fixed address, DHCP is served on it (dnsmasq), the
#       dashboard name is announced on it (mDNS), and nowhere else.
#   netsetup.sh one_port <if>
#       a single port on the existing home network: no DHCP of our own (the
#       router does that), mDNS on that port.
#
# Safe to run again and again: services are only restarted when their
# configuration actually changed.
set -euo pipefail

MODE=${1:?mode}
changed() {  # changed <file> <content>: write if different, return 0 if it changed
  local f=$1 c=$2
  if [ -f "$f" ] && [ "$(cat "$f")" = "$c" ]; then return 1; fi
  mkdir -p "$(dirname "$f")"; printf "%s\n" "$c" > "$f.tmp" && mv "$f.tmp" "$f"; return 0
}
running() { systemctl is-active -q "$1" 2>/dev/null; }
# At boot this runs before dnsmasq/avahi start: never wait for them (that would deadlock).
sc() { systemctl ${SYSTEMCTL_NO_BLOCK:+--no-block} "$@"; }

DNSMASQ_CONF=/etc/dnsmasq.d/parental-gateway.conf
AVAHI_CONF=/etc/avahi/avahi-daemon.conf

avahi_on() {  # announce the dashboard name only on this interface
  local ifc=$1
  [ -f "$AVAHI_CONF" ] || return 0
  local before; before=$(cat "$AVAHI_CONF")
  if grep -q "^#\?allow-interfaces=" "$AVAHI_CONF"; then
    sed -i "s/^#\?allow-interfaces=.*/allow-interfaces=$ifc/" "$AVAHI_CONF"
  else
    sed -i "/^\[server\]/a allow-interfaces=$ifc" "$AVAHI_CONF"
  fi
  systemctl enable -q avahi-daemon 2>/dev/null || true
  if [ "$before" != "$(cat "$AVAHI_CONF")" ] && running avahi-daemon; then sc restart avahi-daemon || true; fi
}

wan_dhcp() {  # the internet side gets its address from the ISP router - make sure something asks for it
  local ifc=$1
  [ -n "$ifc" ] && command -v nmcli >/dev/null && running NetworkManager || return 0
  nmcli dev set "$ifc" managed yes >/dev/null 2>&1 || true
  cur=$(nmcli -g connection.interface-name con show pg-wan 2>/dev/null || true)
  if [ "$cur" != "$ifc" ]; then
    nmcli -t con delete pg-wan >/dev/null 2>&1 || true
    nmcli con add type ethernet ifname "$ifc" con-name pg-wan ipv4.method auto ipv6.method auto \
      connection.autoconnect yes connection.autoconnect-priority 100 >/dev/null
  fi
  # Raspberry Pi OS gives ports named usb* (USB-gadget style, also some USB adapters)
  # a self-assigned address only, so "connected" isn't enough: our DHCP profile must
  # be the active one. Don't wait for the router (it may still be starting up).
  active=$(nmcli -g GENERAL.CONNECTION dev show "$ifc" 2>/dev/null || true)
  [ "$active" = pg-wan ] || nmcli --wait 0 con up pg-wan >/dev/null 2>&1 || true
}

free_port_53() {
  if ss -lunp 2>/dev/null | grep -q "systemd-resolve.*:53 "; then
    mkdir -p /etc/systemd/resolved.conf.d
    printf "[Resolve]\nDNSStubListener=no\n" > /etc/systemd/resolved.conf.d/parental-gateway.conf
    sc restart systemd-resolved || true
  fi
}

case "$MODE" in
gateway)
  WAN_IF=${2:?wan}; LAN_IF=${3:?lan}; LAN_CIDR=${4:?lan-ip/prefix}
  read -r LAN_IP PREFIX DHCP_START DHCP_END < <(python3 - "$LAN_CIDR" <<'PY'
import ipaddress, sys
i = ipaddress.ip_interface(sys.argv[1]); n = i.network
hosts = list(n.hosts()) if n.num_addresses <= 4096 else None
lo, hi = (n.network_address + 100, n.network_address + 250) if n.prefixlen <= 24 else (hosts[len(hosts)//2], hosts[-1])
print(i.ip, n.prefixlen, lo, hi)
PY
)
  echo "==> home side: $LAN_IF $LAN_IP/$PREFIX, internet side: $WAN_IF"
  if command -v nmcli >/dev/null && running NetworkManager; then
    cur=$(nmcli -g ipv4.addresses,connection.interface-name con show pg-lan 2>/dev/null | paste -sd' ' || true)
    if [ "$cur" != "$LAN_IP/$PREFIX $LAN_IF" ]; then
      nmcli -t con delete pg-lan >/dev/null 2>&1 || true
      nmcli con add type ethernet ifname "$LAN_IF" con-name pg-lan ipv4.method manual \
        ipv4.addresses "$LAN_IP/$PREFIX" ipv6.method disabled connection.autoconnect yes \
        connection.autoconnect-priority 100 >/dev/null
    fi
    nmcli --wait 15 con up pg-lan >/dev/null 2>&1 || true
    wan_dhcp "$WAN_IF"
  elif [ -f /etc/dhcpcd.conf ]; then
    if ! grep -q "# parental-gateway" /etc/dhcpcd.conf; then
      printf "\n# parental-gateway\ninterface %s\nstatic ip_address=%s/%s\nnohook wpa_supplicant\n" \
        "$LAN_IF" "$LAN_IP" "$PREFIX" >> /etc/dhcpcd.conf
      sc restart dhcpcd || true
    fi
  else
    ip addr replace "$LAN_IP/$PREFIX" dev "$LAN_IF" || true
    ip link set "$LAN_IF" up || true
  fi
  if changed "$DNSMASQ_CONF" "port=0
interface=$LAN_IF
bind-interfaces
dhcp-range=$DHCP_START,$DHCP_END,12h
dhcp-option=option:router,$LAN_IP
dhcp-option=option:dns-server,$LAN_IP
# search domain: \"family\" alone finds family.home.arpa (the dashboard)
dhcp-option=option:domain-name,home.arpa
dhcp-option=option:domain-search,home.arpa
dhcp-authoritative
dhcp-leasefile=/var/lib/misc/dnsmasq.leases"; then
    running dnsmasq && sc restart dnsmasq || true
  fi
  systemctl enable -q dnsmasq 2>/dev/null || true
  running dnsmasq || sc start dnsmasq 2>/dev/null || true
  avahi_on "$LAN_IF"
  ;;
one_port)
  IFC=${2:-}
  echo "==> one port${IFC:+ ($IFC)}: filtering lookups on the existing home network"
  # Never hand out addresses here: the router already does, and two DHCP servers break the network.
  if [ -f "$DNSMASQ_CONF" ]; then rm -f "$DNSMASQ_CONF"; running dnsmasq && sc stop dnsmasq || true; fi
  systemctl disable -q dnsmasq 2>/dev/null || true
  [ -n "$IFC" ] && avahi_on "$IFC"
  wan_dhcp "$IFC"
  ;;
*) echo "usage: $0 gateway <wan> <lan> <ip/prefix> | one_port <if>" >&2; exit 2 ;;
esac
free_port_53
