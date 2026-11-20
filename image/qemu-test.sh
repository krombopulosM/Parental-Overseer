#!/usr/bin/env bash
# Boot the card image in an emulated Raspberry Pi 3 (QEMU) between a fake
# internet and a child's device, and check it works with no hands on it:
#
#   fake internet (DHCP, DNS, web) ──eth A── emulated Pi ──eth B── child's device
#
#   sudo image/qemu-test.sh <image.img.xz> [image.json]
#
# The card is written with the Card Maker (password + SSH key), so this also
# tests that. Needs: qemu-system-aarch64, mtools, parted, dnsmasq, busybox
# (udhcpc), curl, dig, ssh. Takes 5-15 minutes (the Pi is emulated, slowly).
set -euo pipefail
IMG_XZ=${1:?image.img.xz}
INFO=${2:-}
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
W=${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/pg-qemu.XXXXXX")}
PASSWORD="card-maker-pw-1"
BOOT_TIMEOUT=${BOOT_TIMEOUT:-1800}
PASS=0; FAIL=0
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
NS_VM=pgq-vm NS_INET=pgq-inet NS_KID=pgq-kid
inet() { ip netns exec $NS_INET "$@"; }
kid()  { ip netns exec $NS_KID "$@"; }

cleanup() {
  set +e
  if [ "${HOLD:-0}" = 1 ]; then echo "HOLD=1: the emulated Pi is still running (namespaces $NS_VM $NS_INET $NS_KID, work dir $W)"; return; fi
  [ -f "$W/qemu.pid" ] && kill "$(cat "$W/qemu.pid")" 2>/dev/null
  for p in "$W"/*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
  sleep 1
  for n in $NS_VM $NS_INET $NS_KID; do ip netns del $n 2>/dev/null; done
  rm -rf /etc/netns/$NS_KID
  [ "${KEEP:-0}" = 1 ] || rm -rf "$W"
}
trap cleanup EXIT

echo "==> Writing the card with the Card Maker (work dir $W)"
ssh-keygen -q -t ed25519 -N "" -f "$W/key" -C qemu-test
printf '%s\n' "$PASSWORD" | python3 "$REPO/cardmaker/__main__.py" write --output "$W/card.img" --image "$IMG_XZ" \
  ${INFO:+--info-file "$INFO"} --password-stdin --ssh-key-file "$W/key.pub" -y --name family \
  2>&1 | tail -2 || true
[ -s "$W/card.img" ] || { echo "Card Maker didn't write the card"; exit 1; }
truncate -s 8G "$W/card.img"                     # the emulated SD card must be a power of two

P1=$(parted -s -m "$W/card.img" unit B print | awk -F: '$1==1 {gsub("B","",$2); print $2}')
for f in kernel8.img bcm2710-rpi-3-b-plus.dtb; do mcopy -n -i "$W/card.img@@$P1" "::$f" "$W/$f"; done
# QEMU's emulated Pi 3 differs from a real one in three ways that matter here:
#  - the boot ramdisk (initramfs) fails under it, so the kernel mounts the card directly
#    (the ramdisk's only job on this card is growing the partition, not needed for a test);
#  - the Pi 3's main serial port belongs to Bluetooth, so the log uses the early console;
#  - its watchdog resets the machine, so systemd doesn't arm it.
CMDLINE="root=/dev/mmcblk0p2 rootfstype=ext4 fsck.repair=yes rootwait earlycon=pl011,0x3f201000 keep_bootcon"
CMDLINE="$CMDLINE systemd.watchdog_sec=0 dwc_otg.fiq_fsm_enable=0 dwc_otg.lpm_enable=0"

echo "==> Networks: fake internet, emulated Pi, child's device"
for n in $NS_VM $NS_INET $NS_KID; do ip netns del $n 2>/dev/null || true; ip netns add $n; done
ip -n $NS_VM link set lo up; ip -n $NS_INET link set lo up; ip -n $NS_KID link set lo up
ip -n $NS_VM tuntap add tap-a mode tap; ip -n $NS_VM tuntap add tap-b mode tap
ip -n $NS_VM link add br-a type bridge; ip -n $NS_VM link add br-b type bridge
ip -n $NS_VM link add va type veth peer name inet0 netns $NS_INET
ip -n $NS_VM link add vb type veth peer name kid0 netns $NS_KID
for l in tap-a va; do ip -n $NS_VM link set $l master br-a; done
for l in tap-b vb; do ip -n $NS_VM link set $l master br-b; done
for l in tap-a tap-b va vb br-a br-b; do ip -n $NS_VM link set $l up; done
# The fake internet: an "ISP router" with DHCP and DNS, the public DNS servers
# the gateway uses, and some web sites.
ip -n $NS_INET addr add 10.77.0.1/24 dev inet0; ip -n $NS_INET link set inet0 up
for a in 1.1.1.1 9.9.9.9 1.1.1.3 1.0.0.3 93.184.216.34 45.32.1.1; do ip -n $NS_INET addr add $a/32 dev lo; done
cat > "$W/inet-dnsmasq.conf" <<EOF
interface=inet0
interface=lo
bind-dynamic
no-resolv
dhcp-range=10.77.0.100,10.77.0.150,1h
dhcp-option=option:router,10.77.0.1
dhcp-option=option:dns-server,10.77.0.1
address=/site.test/93.184.216.34
address=/example.com/93.184.216.34
address=/pornhub.com/93.184.216.34
address=/vps.test/45.32.1.1
# Nothing else resolves. (A catch-all answer would also give the VPN providers' names
# that address, and the gateway would then rightly block it as a VPN server.)
pid-file=$W/inet-dnsmasq.pid
dhcp-leasefile=$W/inet.leases
log-facility=$W/inet-dnsmasq.log
log-dhcp
EOF
inet dnsmasq -C "$W/inet-dnsmasq.conf"
mkdir -p "$W/www"; echo "hello from the internet" > "$W/www/index.html"
(cd "$W/www" && inet python3 -m http.server 80 --bind 0.0.0.0 >/dev/null 2>&1 & echo $! > "$W/www.pid")

echo "==> Booting the emulated Pi (this is slow: several minutes)"
ip netns exec $NS_VM qemu-system-aarch64 -M raspi3b -m 1G -smp 4 \
  -kernel "$W/kernel8.img" -dtb "$W/bcm2710-rpi-3-b-plus.dtb" \
  -append "$CMDLINE" -drive "file=$W/card.img,format=raw,if=sd" \
  -netdev tap,id=na,ifname=tap-a,script=no,downscript=no -device usb-net,netdev=na,mac=b8:27:eb:00:00:0a \
  -netdev tap,id=nb,ifname=tap-b,script=no,downscript=no -device usb-net,netdev=nb,mac=b8:27:eb:00:00:0b \
  -usb -device usb-kbd -display none -serial "file:$W/serial.log" -monitor none \
  -pidfile "$W/qemu.pid" -daemonize
T0=$(date +%s)

# The child's device asks for an address, as a phone joining the Wi-Fi would.
cat > "$W/udhcpc.sh" <<'EOF'
#!/bin/sh
case "$1" in bound|renew)
  ip addr flush dev "$interface"; ip addr add "$ip/${mask:-24}" dev "$interface"
  for r in $router; do ip route replace default via "$r"; break; done
  mkdir -p /etc/netns/pgq-kid; : > /etc/netns/pgq-kid/resolv.conf
  for d in $dns; do echo "nameserver $d" >> /etc/netns/pgq-kid/resolv.conf; done
  echo "$ip $router $dns" > "$LEASE_FILE";;
esac
EOF
chmod +x "$W/udhcpc.sh"
ip -n $NS_KID link set kid0 up
echo -n "    waiting for the Pi to hand the child's device an address"
LEASE=""
while [ $(( $(date +%s) - T0 )) -lt "$BOOT_TIMEOUT" ]; do
  if LEASE_FILE="$W/lease" kid busybox udhcpc -i kid0 -n -q -t 3 -T 3 -s "$W/udhcpc.sh" >/dev/null 2>&1; then
    LEASE=$(cat "$W/lease"); break
  fi
  echo -n "."
done
echo
BOOT_S=$(( $(date +%s) - T0 ))
if [ -z "$LEASE" ]; then
  bad "the Pi gave the child's device an address (no answer in ${BOOT_TIMEOUT}s)"
  tail -40 "$W/serial.log"; exit 1
fi
read -r KID_IP GW DNS <<<"$LEASE"
ok "the Pi gave the child's device an address: $KID_IP, gateway $GW, DNS $DNS (${BOOT_S}s after power-on, emulated)"

echo "==> The child's device (home side)"
for i in $(seq 1 60); do kid curl -s -m 5 -o /dev/null "http://$GW:8080/api/session" && break; sleep 5; done
check "dashboard answers on the home side" kid curl -sf -m 10 "http://$GW:8080/api/session"
check "dashboard name resolves through the Pi (family.home.arpa)" \
  sh -c "ip netns exec $NS_KID dig +short +time=5 @$GW family.home.arpa | grep -qx '$GW'"
check "http://family.home.arpa opens the dashboard (port 80)" \
  sh -c "ip netns exec $NS_KID curl -sfL -m 15 --resolve family.home.arpa:80:$GW http://family.home.arpa/ | grep -q 'Parental Gateway'"
check "password set by the Card Maker signs in" \
  sh -c "ip netns exec $NS_KID curl -sf -m 15 -H 'X-Guardian: 1' -H 'Content-Type: application/json' \
         -d '{\"password\":\"$PASSWORD\"}' http://$GW:8080/api/login | grep -q ok"
check "a wrong password doesn't" \
  sh -c "! ip netns exec $NS_KID curl -sf -m 15 -H 'X-Guardian: 1' -H 'Content-Type: application/json' \
         -d '{\"password\":\"guess-guess\"}' http://$GW:8080/api/login"
for i in $(seq 1 24); do kid curl -sf -m 5 -o /dev/null http://site.test/ && break; sleep 5; done
check "allowed site loads through the Pi" \
  sh -c "ip netns exec $NS_KID curl -sf -m 20 http://site.test/ | grep -q 'hello from the internet'"
check "adult site's name isn't given out" \
  sh -c "ip netns exec $NS_KID dig +time=5 @$GW pornhub.com | grep -q 'status: NXDOMAIN'"
check "encrypted-DNS server's name isn't given out (dns.google)" \
  sh -c "ip netns exec $NS_KID dig +time=5 @$GW dns.google | grep -q 'status: NXDOMAIN'"
check "connection straight to an IP address (no lookup) is refused" \
  sh -c "! ip netns exec $NS_KID curl -s -m 10 -o /dev/null http://45.32.1.1/"
check "the ISP router's network can't be reached from the home side" \
  sh -c "! ip netns exec $NS_KID curl -s -m 8 -o /dev/null http://10.77.0.1/"

echo "==> Inside the Pi (SSH with the key from the Card Maker)"
SSH=(ssh -i "$W/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -o LogLevel=ERROR pgadmin@"$GW")
if kid "${SSH[@]}" true; then
  ok "SSH key from the Card Maker works (SSH is otherwise off)"
  kid "${SSH[@]}" 'sudo cat /opt/parental-gateway/data/appliance-state.json; echo;
    echo "--- settings file on the card:"; grep -c pbkdf2 /boot/firmware/parental-gateway.txt || true;
    echo "--- memory:"; free -m;
    echo "--- services running:"; systemctl list-units --type=service --state=running --no-legend --plain | awk "{print \$1}";
    echo "--- failed:"; systemctl --failed --no-legend --plain;
    echo "--- gateway processes (RSS MB):"; ps -eo rss=,args= | grep "[r]un.py" | awk "{printf \"%d %s %s\n\", \$1/1024, \$3, \$4}";
    echo "--- network:"; nmcli -t dev; ip -br addr; ip route;
    echo "--- port choices this boot:"; sudo journalctl -b --no-pager -o short-monotonic -t python -u parental-gateway-appliance -u parental-gateway-replug | grep -E "wired|Started|Finished" | cut -c1-230;
    echo "--- gateway started:"; sudo journalctl -b --no-pager -o short-monotonic -u parental-gateway | grep -E "Started|firewall active|restart" | cut -c1-160;
    echo "--- firewall ports:"; sudo nft list chain inet guardian forward | grep -E "iifname|oifname" | head -6;
    echo "--- boot:"; systemd-analyze 2>/dev/null | head -1;
    echo "--- disk:"; df -h / | tail -1;
    echo "--- mdns:"; sudo grep "\[mdns\]" /opt/parental-gateway/data/logs/gateway.log | tail -1' > "$W/inside.txt" 2>&1 || true
  sed 's/^/    /' "$W/inside.txt"
  grep -q '"mode": "gateway"' "$W/inside.txt" && ok "chose gateway mode by itself" || bad "chose gateway mode by itself"
  grep -q '\[mdns\] announcing family.local' "$W/inside.txt" && ok "announces family.local on the home network" \
    || bad "announces family.local on the home network"
  grep -q -- "--- settings file on the card:" "$W/inside.txt" && \
    [ "$(sed -n '/settings file on the card/{n;p}' "$W/inside.txt")" = 0 ] && ok "password hash was removed from the card" \
    || bad "password hash was removed from the card"
else
  bad "SSH key from the Card Maker works"
fi
cp "$W/serial.log" "${TMPDIR:-/tmp}/pg-qemu-serial.log" 2>/dev/null || true
echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
