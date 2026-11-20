"""Card Maker: everything except the windows and the per-OS disk handling.

Writing a card:
  1. download the image (or use a file you have), check its SHA-256;
  2. stream it through xz into the card in 4 MiB blocks, putting the card's
     settings (the dashboard password's *hash*, the name) into the settings
     block on the boot partition on the way;
  3. read the whole card back and compare, so a bad card or reader is caught
     here rather than as a Pi that won't start.
"""
from __future__ import annotations

import hashlib
import json
import lzma
import os
import struct
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from guardian.appliance import MARKER, SETTINGS_FILE, SETTINGS_SIZE, parse_settings, render_settings  # noqa: E402
from guardian.auth import Auth  # noqa: E402

INFO_URL = os.environ.get("PG_IMAGE_INFO",
                          "https://github.com/krombopulosM/Parental-Overseer/releases/latest/download/os_list.json")
CHUNK = 4 << 20
USER_AGENT = "ParentalGatewayCardMaker/1"


class CardError(Exception):
    pass


# --------------------------------------------------------------- settings
def make_settings(password: str | None = None, name: str | None = None, ssh_key: str | None = None,
                  lan_ip: str | None = None) -> bytes:
    vals = {}
    if password:
        vals["password_hash"] = Auth.make_hash(password)
    if name:
        from guardian.localname import valid_label
        name = name.strip().lower()
        if not valid_label(name):
            raise CardError("The name can only use letters, numbers and hyphens (e.g. family).")
        vals["dashboard_name"] = name
    if ssh_key:
        vals["ssh_public_key"] = " ".join(ssh_key.split())
    if lan_ip:
        vals["lan_ip"] = lan_ip.strip()
    return render_settings(vals)


def card_volumes() -> list[str]:
    """Mounted volumes that are a Parental Gateway card's boot partition
    (for "change the password on a card")."""
    roots = []
    if sys.platform == "win32":
        import string
        roots = [f"{c}:\\" for c in string.ascii_uppercase[2:]]
    elif sys.platform == "darwin":
        roots = [os.path.join("/Volumes", v) for v in _ls("/Volumes")]
    else:
        user = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
        for base in ("/media", f"/media/{user}", f"/run/media/{user}", "/mnt"):
            roots += [os.path.join(base, v) for v in _ls(base)]
    return [r for r in roots if os.path.isfile(os.path.join(r, SETTINGS_FILE))]


def _ls(d):
    try:
        return sorted(os.listdir(d))
    except OSError:
        return []


def update_card(volume: str, password: str | None = None, name: str | None = None,
                ssh_key: str | None = None) -> list[str]:
    """Change settings on an existing card (in place, same size)."""
    path = os.path.join(volume, SETTINGS_FILE)
    with open(path, "rb") as fh:
        raw = fh.read()
    if not raw.startswith(MARKER.encode()):
        raise CardError(f"{path} isn't a Parental Gateway settings file.")
    vals = parse_settings(raw)
    changed = []
    if password:
        vals["password_hash"] = Auth.make_hash(password)
        changed.append("password")
    if name:
        vals["dashboard_name"] = name.strip().lower()
        changed.append("name")
    if ssh_key:
        vals["ssh_public_key"] = " ".join(ssh_key.split())
        changed.append("ssh")
    new = render_settings(vals)
    with open(path, "r+b") as fh:
        fh.write(new)
        fh.flush()
        os.fsync(fh.fileno())
    return changed


# --------------------------------------------------------------- image info + download
def fetch_info(url: str = INFO_URL, timeout: float = 20) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.load(r)
    lst = data.get("os_list") or []
    if not lst:
        raise CardError("No image is listed in the download information.")
    return lst[0]


def cache_dir() -> str:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    d = os.path.join(base, "ParentalGatewayCardMaker")
    os.makedirs(d, exist_ok=True)
    return d


def sha256_file(path: str, progress=None) -> str:
    h = hashlib.sha256()
    size = os.path.getsize(path)
    done = 0
    with open(path, "rb") as fh:
        while True:
            b = fh.read(CHUNK)
            if not b:
                break
            h.update(b)
            done += len(b)
            if progress:
                progress("check-download", done, size)
    return h.hexdigest()


def download(info: dict, progress=None, dest_dir: str | None = None, opener=urllib.request.urlopen) -> str:
    """The image file, downloaded once and kept (checked against its SHA-256)."""
    url, want = info["url"], (info.get("image_download_sha256") or "").lower()
    dest = os.path.join(dest_dir or cache_dir(), os.path.basename(url.split("?")[0]))
    if os.path.exists(dest) and want and sha256_file(dest, progress) == want:
        return dest
    part = dest + ".part"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    h = hashlib.sha256()
    with opener(req, timeout=60) as r, open(part, "wb") as out:
        total = int(r.headers.get("Content-Length") or info.get("image_download_size") or 0)
        done = 0
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            out.write(b)
            h.update(b)
            done += len(b)
            if progress:
                progress("download", done, total)
    if want and h.hexdigest() != want:
        os.remove(part)
        raise CardError("The download was damaged on the way (its checksum doesn't match). Please try again.")
    os.replace(part, dest)
    return dest


# --------------------------------------------------------------- image layout
def _open_image(path: str):
    return lzma.open(path, "rb") if path.endswith(".xz") else open(path, "rb")


def image_size(path: str, info: dict | None = None) -> int | None:
    if info and info.get("extract_size"):
        return int(info["extract_size"])
    if not path.endswith(".xz"):
        return os.path.getsize(path)
    return None


def boot_partition(first_sector: bytes) -> tuple[int, int]:
    """(start, size) in bytes of the first partition in an MBR."""
    if len(first_sector) < 512 or first_sector[510:512] != b"\x55\xaa":
        raise CardError("This doesn't look like a Raspberry Pi card image.")
    entry = first_sector[446:462]
    lba, count = struct.unpack("<II", entry[8:16])
    return lba * 512, count * 512


def find_settings_offset(path: str) -> int:
    """Where the settings block is (scans the boot partition; for images without
    the information file)."""
    with _open_image(path) as fh:
        first = fh.read(512)
        start, size = boot_partition(first)
        pos = 512
        hits = []
        marker = MARKER.encode()
        carry = b""
        while pos < start + size:
            b = fh.read(CHUNK)
            if not b:
                break
            buf = carry + b
            base = pos - len(carry)
            i = buf.find(marker)
            while i != -1:
                if (base + i) % 512 == 0 and start <= base + i < start + size:
                    hits.append(base + i)
                i = buf.find(marker, i + 1)
            carry = buf[-len(marker):]
            pos += len(b)
    hits = sorted(set(hits))
    if len(hits) != 1:
        raise CardError("Couldn't find the settings block in this image.")
    return hits[0]


class Patcher:
    """Replaces bytes [offset, offset+len(data)) of a stream as it goes past,
    checking the original there starts with the settings marker."""

    def __init__(self, offset: int, data: bytes, expect_prefix: bytes = MARKER.encode()):
        self.offset, self.data, self.expect = offset, data, expect_prefix
        self.seen = bytearray()
        self.done = False

    def __call__(self, pos: int, chunk: bytes) -> bytes:
        end = pos + len(chunk)
        lo, hi = max(pos, self.offset), min(end, self.offset + len(self.data))
        if lo >= hi:
            return chunk
        if len(self.seen) < len(self.expect):
            self.seen += chunk[lo - pos:hi - pos][:len(self.expect) - len(self.seen)]
            if len(self.seen) >= len(self.expect) and bytes(self.seen[:len(self.expect)]) != self.expect:
                raise CardError("The settings block isn't where the image information says. "
                                "The image may be from a different version - download it again.")
        b = bytearray(chunk)
        b[lo - pos:hi - pos] = self.data[lo - self.offset:hi - self.offset]
        if hi == self.offset + len(self.data):
            self.done = True
        return bytes(b)


# --------------------------------------------------------------- write + verify
def write_image(image: str, target, *, settings: bytes | None = None, offset: int | None = None,
                size: int | None = None, progress=None, verify: bool = True) -> dict:
    """Write `image` (.img or .img.xz) to `target` (an object from drives.open_target,
    or a path to a file). Returns {"bytes", "sha256", "verified"}."""
    if isinstance(target, str):
        from .drives import FileTarget
        target = FileTarget(target)
    patch = None
    if settings is not None:
        if offset is None:
            if progress:
                progress("prepare", 0, 1)
            offset = find_settings_offset(image)
        patch = Patcher(offset, settings)
    total = size or image_size(image)
    if total and target.size and total > target.size:
        raise CardError(f"The card is too small: the image needs {total / 1e9:.1f} GB.")
    h = hashlib.sha256()
    pos = 0
    t0 = time.time()
    with _open_image(image) as src:
        target.begin()
        try:
            while True:
                b = src.read(CHUNK)
                if not b:
                    break
                if patch:
                    b = patch(pos, b)
                if len(b) % 512:
                    b += b"\0" * (512 - len(b) % 512)
                target.write(b)
                h.update(b)
                pos += len(b)
                if progress:
                    progress("write", pos, total or 0)
            target.flush()
        finally:
            target.end()
    if patch and not patch.done:
        raise CardError("The image ended before its settings block - it may be damaged.")
    digest = h.hexdigest()
    result = {"bytes": pos, "sha256": digest, "seconds": round(time.time() - t0, 1), "verified": False}
    if verify:
        h2 = hashlib.sha256()
        done = 0
        for b in target.read_back(pos, CHUNK):
            h2.update(b)
            done += len(b)
            if progress:
                progress("verify", done, pos)
        if done != pos or h2.hexdigest() != digest:
            raise CardError("The card didn't read back the same as what was written. "
                            "The card or card reader may be faulty - try another.")
        result["verified"] = True
    return result
