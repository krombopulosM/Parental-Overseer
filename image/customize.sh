#!/bin/bash
# Runs inside the image (arm64 chroot) during image/build.sh: installs the
# gateway and turns Raspberry Pi OS Lite into an appliance that runs only it.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
APP=/opt/parental-gateway
ADMIN=pgadmin

# Don't start services inside the chroot.
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d
if [ -n "${BUILD_CA:-}" ]; then
  cp "$BUILD_CA" /usr/local/share/ca-certificates/pg-build-ca.crt && update-ca-certificates >/dev/null 2>&1 || true
fi
APT_BACKUP=""
if [ "${APT_HTTPS:-0}" = 1 ]; then          # build machine only reaches the mirrors over HTTPS
  APT_BACKUP=$(mktemp -d)
  cp -a /etc/apt/sources.list.d "$APT_BACKUP/"; [ -f /etc/apt/sources.list ] && cp /etc/apt/sources.list "$APT_BACKUP/"
  sed -i 's#http://#https://#g' /etc/apt/sources.list.d/* /etc/apt/sources.list 2>/dev/null || true
fi

echo "--> packages"
apt-get update -q
apt-get install -y -q --no-install-recommends \
  python3-venv python3-dev build-essential libnetfilter-queue-dev nftables conntrack \
  dnsmasq-base dnsmasq avahi-daemon avahi-utils git ca-certificates unattended-upgrades

echo "--> removing what an appliance doesn't need"
# cloud-init (slow first boot; the Card Maker sets things up instead), Bluetooth,
# Wi-Fi drivers and firmware (the Pi's radios are off), desktop disk mounting,
# Raspberry Pi Connect, manual pages, camera apps, USB gadget mode.
REMOVE="cloud-init rpi-cloud-init-mods bluez bluez-firmware udisks2 rpi-connect-lite man-db
        rpicam-apps-lite rpi-usb-gadget firmware-atheros firmware-mediatek firmware-libertas
        firmware-brcm80211 wpasupplicant"
KEEP_RE='^(network-manager|openssh-server|avahi-daemon|dnsmasq|nftables|python3|systemd|raspi-firmware|linux-image)'
GO=""
for p in $REMOVE; do
  dpkg -s "$p" >/dev/null 2>&1 || continue
  # Skip anything whose removal would take something we need with it.
  if apt-get -s purge "$p" 2>/dev/null | awk '/^Purg|^Remv/ {print $2}' | grep -Eq "$KEEP_RE"; then
    echo "    keeping $p (needed by the network stack)"
    continue
  fi
  GO="$GO $p"
done
# One go: the boot ramdisk is rebuilt once, not once per package (slow under emulation).
[ -n "$GO" ] && apt-get purge -y -q $GO >/dev/null
apt-get autoremove -y -q --purge >/dev/null
rm -rf /etc/cloud /var/lib/cloud

echo "--> the gateway"
python3 /tmp/pg-src/tools/install.py --root "$APP" --gateway --python /usr/bin/python3 --skip-selftest
PY="$APP/current/.venv/bin/python"
mkdir -p "$APP/data"
GUARDIAN_DATA_DIR="$APP/data" PG_VERSION="$PG_VERSION" PG_BASE="$PG_BASE" PG_UPDATE_URL="$PG_UPDATE_URL" "$PY" - <<'PY'
import os, sys
sys.path.insert(0, "/opt/parental-gateway/current")
from guardian.appliance import merge_local
merge_local("/opt/parental-gateway/data/config.local.yaml", {
    "mode": "gateway",
    "dns": {"listen_port": 53},
    "web": {"host": "0.0.0.0", "port": 8080, "local_name": "family"},
    "appliance": {"setup_window_minutes": 30, "image": os.environ["PG_VERSION"], "base": os.environ["PG_BASE"]},
    "updates": {"source": os.environ["PG_UPDATE_URL"], "branch": "main", "subdir": ""},
})
PY
install -m 644 "$APP/current/deploy/parental-gateway.service" /etc/systemd/system/parental-gateway.service
install -m 644 "$APP/current/deploy/appliance/parental-gateway-appliance.service" /etc/systemd/system/
install -m 644 "$APP/current/deploy/appliance/parental-gateway-replug.service" /etc/systemd/system/
install -m 644 "$APP/current/deploy/appliance/90-parental-gateway.rules" /etc/udev/rules.d/
systemctl enable parental-gateway-appliance.service parental-gateway.service avahi-daemon.service >/dev/null
# DHCP is switched on by the gateway's network set-up, and only on the home-side port.
systemctl disable dnsmasq.service >/dev/null 2>&1 || true
cat > /usr/local/bin/parental-gateway-diagnostics <<EOF
#!/bin/sh
# Writes a diagnostics zip (logs, status, settings, firewall) to send when asking for help.
#   sudo parental-gateway-diagnostics [output.zip]
export GUARDIAN_DATA_DIR="$APP/data"
exec "$APP/current/.venv/bin/python" "$APP/current/run.py" --diagnostics "\$@"
EOF
chmod 755 /usr/local/bin/parental-gateway-diagnostics

echo "--> kernel settings"
cat > /etc/sysctl.d/90-parental-gateway.conf <<EOF
# Forwarding stays OFF at boot; the gateway switches it on only after its
# firewall rules are loaded, so there is never an unfiltered window.
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
net.netfilter.nf_conntrack_acct=1
EOF
printf "nf_conntrack\nnfnetlink_queue\nnft_queue\n" > /etc/modules-load.d/parental-gateway.conf

echo "--> appliance tuning"
echo family > /etc/hostname
sed -i 's/^127\.0\.1\.1.*/127.0.1.1\tfamily/' /etc/hosts
grep -q "^127.0.1.1" /etc/hosts || printf '127.0.1.1\tfamily\n' >> /etc/hosts
# No interactive first-boot user wizard: an admin account that can only be reached
# with an SSH key the Card Maker puts on the card (SSH is off otherwise).
systemctl disable userconfig.service >/dev/null 2>&1 || true
systemctl mask userconfig.service >/dev/null 2>&1 || true
id "$ADMIN" >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo,adm "$ADMIN"
passwd -l "$ADMIN" >/dev/null
echo "$ADMIN ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/010-pgadmin && chmod 440 /etc/sudoers.d/010-pgadmin
systemctl disable ssh.service ssh.socket >/dev/null 2>&1 || true
# Fewer writes to the card: logs in memory (the gateway keeps its own in data/logs),
# no access-time updates.
mkdir -p /etc/systemd/journald.conf.d
printf "[Journal]\nStorage=volatile\nRuntimeMaxUse=32M\n" > /etc/systemd/journald.conf.d/parental-gateway.conf
sed -i -E '/\s\/\s/ s/defaults(,noatime)?/defaults,noatime/' /etc/fstab
# Security updates for the system install themselves; the gateway updates itself.
cat > /etc/apt/apt.conf.d/52parental-gateway <<'EOF'
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Raspberry Pi Foundation,codename=${distro_codename},label=Raspberry Pi Foundation";
};
// Kernel fixes need a restart: at 04:30 (about a minute without internet).
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
EOF
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
# Console message for anyone who plugs in a screen.
cat > /etc/issue <<'EOF'
Parental Gateway \n - open the dashboard from any device at home: http://family.local

EOF
printf '' > /etc/motd

echo "--> tidy"
apt-get clean
rm -rf /var/lib/apt/lists/* /root/.cache /var/cache/debconf/*-old /usr/share/man/* 2>/dev/null || true
find /usr/share/doc -type f ! -name copyright -delete 2>/dev/null || true      # keep the licences
if [ -n "$APT_BACKUP" ]; then
  rm -rf /etc/apt/sources.list.d && cp -a "$APT_BACKUP/sources.list.d" /etc/apt/
  [ -f "$APT_BACKUP/sources.list" ] && cp "$APT_BACKUP/sources.list" /etc/apt/
  rm -rf "$APT_BACKUP"
fi
if [ -n "${BUILD_CA:-}" ]; then rm -f /usr/local/share/ca-certificates/pg-build-ca.crt && update-ca-certificates --fresh >/dev/null 2>&1 || true; fi
rm -f /usr/sbin/policy-rc.d
rm -f /etc/ssh/ssh_host_*      # each card makes its own on first start
echo "--> customised"
