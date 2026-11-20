#!/usr/bin/env bash
# Build the ready-made Parental Gateway card image from Raspberry Pi OS Lite (64-bit).
#
#   sudo image/build.sh [--base <url-or-.img.xz>] [--out <dir>] [--source <git-dir>] [--branch main]
#
# Needs: a Linux machine (x86 is fine), root, and these tools: qemu-user-static
# (with binfmt registered), parted, e2fsprogs, mtools, xz, git, curl.
# Output in <out>: parental-gateway-<version>-arm64.img.xz, its .sha256, and
# os_list.json (a Raspberry Pi Imager repository describing it).
#
# The boot partition (FAT) is edited with mtools, so the build machine's kernel
# needs no FAT support; the system partition is loop-mounted and customised in
# a chroot (arm64, through qemu) by image/customize.sh.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
BASE_INDEX=https://downloads.raspberrypi.com/raspios_lite_arm64/images/
BASE=""
OUT="$REPO/image/out"
SOURCE="$REPO"
BRANCH=""
UPDATE_URL=${UPDATE_URL:-https://github.com/krombopulosM/Parental-Overseer.git}
GROW_MB=${GROW_MB:-1200}
KEEP_WORK=${KEEP_WORK:-0}
while [ $# -gt 0 ]; do
  case "$1" in
    --base) BASE=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --source) SOURCE=$2; shift 2 ;;
    --branch) BRANCH=$2; shift 2 ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
for t in parted e2fsck resize2fs mcopy mdir xz git curl losetup chroot zerofree; do
  command -v $t >/dev/null || { echo "missing tool: $t"; exit 1; }; done
[ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ] || {
  echo "arm64 emulation isn't registered (install qemu-user-static, or: docker run --privileged --rm tonistiigi/binfmt --install arm64)"; exit 1; }

mkdir -p "$OUT"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/pg-image.XXXXXX")
MNT="$WORK/root"
LOOP=""
cleanup() {
  set +e
  for m in dev/pts dev proc sys run; do mountpoint -q "$MNT/$m" && umount -l "$MNT/$m"; done
  mountpoint -q "$MNT" && umount "$MNT"
  [ -n "$LOOP" ] && losetup -d "$LOOP"
  [ "$KEEP_WORK" = 1 ] || rm -rf "$WORK"
}
trap cleanup EXIT

# ------------------------------------------------------------------ base image
if [ -z "$BASE" ]; then
  latest=$(curl -fsSL "$BASE_INDEX" | grep -o 'raspios_lite_arm64-[0-9-]*/' | sort -u | tail -1)
  file=$(curl -fsSL "$BASE_INDEX$latest" | grep -o '[0-9a-z_.-]*-lite\.img\.xz"' | head -1 | tr -d '"')
  BASE="$BASE_INDEX$latest$file"
fi
if [ -f "$BASE" ]; then
  BASE_XZ=$BASE
else
  BASE_XZ="$OUT/$(basename "$BASE")"
  if [ ! -f "$BASE_XZ" ]; then
    echo "==> Downloading $BASE"
    curl -fL --retry 3 -o "$BASE_XZ.part" "$BASE" && mv "$BASE_XZ.part" "$BASE_XZ"
  fi
  curl -fsSL -o "$BASE_XZ.sha256" "$BASE.sha256"
  echo "==> Checking the download"
  (cd "$(dirname "$BASE_XZ")" && echo "$(cut -d' ' -f1 "$BASE_XZ.sha256")  $(basename "$BASE_XZ")" | sha256sum -c -)
fi
BASE_NAME=$(basename "$BASE_XZ" .img.xz)

# ------------------------------------------------------------------ source
SRC="$WORK/src"
echo "==> Taking the app from $SOURCE (committed state${BRANCH:+, branch $BRANCH})"
git clone -q --depth 1 ${BRANCH:+--branch "$BRANCH"} "file://$SOURCE" "$SRC"
git -C "$SRC" remote set-url origin "$UPDATE_URL"
if [ -n "$(git -C "$SOURCE" status --porcelain)" ]; then
  echo "    (uncommitted changes in $SOURCE are included; this build won't know its exact commit)"
  (cd "$SOURCE" && git ls-files -z -co --exclude-standard | xargs -0 cp --parents -t "$SRC" 2>/dev/null || true)
fi
VERSION=$(python3 -c "import sys; sys.path.insert(0, '$SRC'); from guardian.updater import read_version; print(read_version('$SRC'))")
COMMIT=$(git -C "$SRC" rev-parse --short HEAD)
[ -n "$(git -C "$SOURCE" status --porcelain)" ] && COMMIT="$COMMIT-dirty"
NAME="parental-gateway-$VERSION-arm64"

# ------------------------------------------------------------------ unpack + grow
IMG="$WORK/$NAME.img"
echo "==> Unpacking $BASE_NAME"
xz -dc -T0 "$BASE_XZ" > "$IMG"
truncate -s "+${GROW_MB}M" "$IMG"
parted -s "$IMG" resizepart 2 100%
part() {  # part <n> -> "start size" in bytes
  parted -s -m "$IMG" unit B print | awk -F: -v n="$1" '$1==n {gsub("B","",$2); gsub("B","",$4); print $2, $4}'
}
read -r P1_START P1_SIZE < <(part 1)
read -r P2_START P2_SIZE < <(part 2)
FAT="$IMG@@$P1_START"
LOOP=$(losetup -f --show -o "$P2_START" --sizelimit "$P2_SIZE" "$IMG")
e2fsck -fy "$LOOP" >/dev/null || true
resize2fs "$LOOP" >/dev/null
mkdir -p "$MNT"
mount "$LOOP" "$MNT"

# The boot partition's files are staged into the system partition's /boot/firmware
# for the chroot (kernel and initramfs updates write there), then copied back.
echo "==> Staging the boot partition"
rm -rf "$MNT/boot/firmware" && mkdir -p "$MNT/boot/firmware"
mcopy -s -n -i "$FAT" ::/ "$MNT/boot/firmware/" >/dev/null

# ------------------------------------------------------------------ customise (chroot)
echo "==> Customising (arm64 chroot - this takes a while)"
mkdir -p "$MNT/tmp/pg-src"
cp -a "$SRC/." "$MNT/tmp/pg-src/"
cp "$HERE/customize.sh" "$MNT/tmp/customize.sh"
for m in proc sys dev dev/pts run; do mkdir -p "$MNT/$m"; done
mount -t proc proc "$MNT/proc"
mount -t sysfs sys "$MNT/sys"
mount --bind /dev "$MNT/dev"
mount --bind /dev/pts "$MNT/dev/pts"
mount -t tmpfs tmpfs "$MNT/run"
cp -L /etc/resolv.conf "$WORK/resolv.conf"
mv "$MNT/etc/resolv.conf" "$WORK/resolv.conf.image" 2>/dev/null || true
cp "$WORK/resolv.conf" "$MNT/etc/resolv.conf"
# Build machines behind an HTTPS-intercepting proxy: trust its CA for the build only.
CA_ENV=()
if [ -n "${BUILD_CA:-}" ] && [ -f "$BUILD_CA" ]; then
  cp "$BUILD_CA" "$MNT/tmp/build-ca.crt"
  CA_ENV=(BUILD_CA=/tmp/build-ca.crt PIP_CERT=/tmp/build-ca.crt SSL_CERT_FILE=/tmp/build-ca.crt REQUESTS_CA_BUNDLE=/tmp/build-ca.crt)
fi
chroot "$MNT" /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8 \
  ${https_proxy:+https_proxy=$https_proxy} ${HTTPS_PROXY:+HTTPS_PROXY=$HTTPS_PROXY} \
  "${CA_ENV[@]}" PG_VERSION="$VERSION" PG_COMMIT="$COMMIT" PG_UPDATE_URL="$UPDATE_URL" \
  PG_BASE="$BASE_NAME" APT_HTTPS="${APT_HTTPS:-0}" \
  /bin/bash /tmp/customize.sh
rm -f "$MNT/etc/resolv.conf"
if [ -e "$WORK/resolv.conf.image" ] || [ -L "$WORK/resolv.conf.image" ]; then mv "$WORK/resolv.conf.image" "$MNT/etc/resolv.conf"; fi
rm -rf "$MNT/tmp/pg-src" "$MNT/tmp/customize.sh" "$MNT/tmp/build-ca.crt"
for m in dev/pts dev proc sys run; do umount -l "$MNT/$m"; done

# ------------------------------------------------------------------ boot partition
echo "==> Writing the boot partition"
mdeltree -i "$FAT" ::/overlays >/dev/null 2>&1 || true
mdel -i "$FAT" '::*' >/dev/null 2>&1 || true
rm -f "$MNT/boot/firmware/user-data" "$MNT/boot/firmware/meta-data" "$MNT/boot/firmware/network-config"
python3 - "$MNT/boot/firmware" <<'PY'
import re, sys
d = sys.argv[1]
cfg = open(f"{d}/config.txt").read()
# Headless appliance: no display stack, sound, camera, Bluetooth or Wi-Fi radio.
for k in ("dtoverlay=vc4-kms-v3d", "camera_auto_detect=1", "display_auto_detect=1", "max_framebuffers=2"):
    cfg = cfg.replace(k + "\n", "# " + k + "   (parental gateway: headless)\n")
cfg = cfg.replace("dtparam=audio=on", "dtparam=audio=off")
cfg = cfg.rstrip() + """

[all]
# --- Parental Gateway appliance ---
# Only the network ports are used: radios off, least memory for graphics.
# To use the Pi's own Wi-Fi or Bluetooth, delete the two dtoverlay lines below.
dtoverlay=disable-bt
dtoverlay=disable-wifi
gpu_mem=16
"""
open(f"{d}/config.txt", "w").write(cfg)
cmd = open(f"{d}/cmdline.txt").read().strip()
cmd = re.sub(r"\s+ds=nocloud\S*", "", cmd)
open(f"{d}/cmdline.txt", "w").write(cmd + "\n")
PY
# The settings file first, so it gets the first free clusters and is one
# contiguous 4096-byte block the Card Maker can patch in place.
python3 -c "import sys; sys.path.insert(0, '$SRC'); from guardian.appliance import render_settings; sys.stdout.buffer.write(render_settings())" \
  > "$WORK/parental-gateway.txt"
mcopy -i "$FAT" "$WORK/parental-gateway.txt" ::/parental-gateway.txt
rm -f "$MNT/boot/firmware/parental-gateway.txt"
mcopy -s -i "$FAT" "$MNT/boot/firmware/"* ::/
printf 'Parental Gateway %s (%s) built on %s from %s\n' "$VERSION" "$COMMIT" "$(date -u +%F)" "$BASE_NAME" > "$WORK/issue-pg.txt"
mcopy -o -i "$FAT" "$WORK/issue-pg.txt" ::/parental-gateway-version.txt
find "$MNT/boot/firmware" -mindepth 1 -delete

# ------------------------------------------------------------------ shrink + pack
echo "==> Tidying the system partition"
fstrim "$MNT" 2>/dev/null || true
umount "$MNT"
e2fsck -fy "$LOOP" >/dev/null || true
zerofree "$LOOP" || true
losetup -d "$LOOP"; LOOP=""

# Check the settings block is where the Card Maker will look for it.
OFFSET=$(python3 - "$IMG" "$P1_START" "$P1_SIZE" "$SRC" <<'PY'
import sys
sys.path.insert(0, sys.argv[4])
from guardian.appliance import MARKER, SETTINGS_SIZE, render_settings
img, start, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
want = render_settings()
hits = []
with open(img, "rb") as fh:
    pos = start
    while pos < start + size:
        fh.seek(pos)
        block = fh.read(1 << 20)
        i = block.find(MARKER.encode())
        while i != -1:
            if (pos + i) % 512 == 0:
                fh.seek(pos + i)
                if fh.read(SETTINGS_SIZE) == want:
                    hits.append(pos + i)
            i = block.find(MARKER.encode(), i + 1)
        pos += len(block)
assert len(hits) == 1, f"settings block found {len(hits)} times"
print(hits[0])
PY
)
echo "==> Settings block at byte $OFFSET"

echo "==> Compressing"
xz -T0 -6 -c "$IMG" > "$OUT/$NAME.img.xz"
IMG_SIZE=$(stat -c %s "$IMG")
IMG_SHA=$(sha256sum "$IMG" | cut -d' ' -f1)
XZ_SIZE=$(stat -c %s "$OUT/$NAME.img.xz")
(cd "$OUT" && sha256sum "$NAME.img.xz" > "$NAME.img.xz.sha256")
XZ_SHA=$(cut -d' ' -f1 "$OUT/$NAME.img.xz.sha256")
RELEASE_URL=${RELEASE_URL:-https://github.com/krombopulosM/Parental-Overseer/releases/latest/download}
python3 - "$OUT" <<PY
import json, sys
out = sys.argv[1]
info = {"name": "Parental Gateway $VERSION", "version": "$VERSION", "commit": "$COMMIT",
        "description": "Turns a Raspberry Pi into the family internet gateway: filtering, VPN/Tor blocking, dashboard.",
        "url": "$RELEASE_URL/$NAME.img.xz", "extract_size": $IMG_SIZE, "extract_sha256": "$IMG_SHA",
        "image_download_size": $XZ_SIZE, "image_download_sha256": "$XZ_SHA",
        "release_date": __import__("datetime").date.today().isoformat(),
        "devices": ["pi5-64bit", "pi4-64bit", "pi3-64bit"],
        "settings_offset": $OFFSET, "base": "$BASE_NAME"}
json.dump({"os_list": [info]}, open(f"{out}/os_list.json", "w"), indent=2)
json.dump(info, open(f"{out}/$NAME.json", "w"), indent=2)
PY
[ "$KEEP_WORK" = 1 ] && cp --reflink=auto "$IMG" "$OUT/$NAME.img"
echo "==> Done: $OUT/$NAME.img.xz ($((XZ_SIZE / 1048576)) MB)"
