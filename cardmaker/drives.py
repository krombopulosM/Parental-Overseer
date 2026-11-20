"""Finding SD cards and USB drives, and writing to them, on Windows, macOS and Linux.

Only removable / USB / SD-card drives between 4 GB and 2 TB are ever offered,
never the computer's own system disk."""
from __future__ import annotations

import json
import os
import plistlib
import subprocess
import sys
from dataclasses import dataclass, field

MIN_SIZE = 4 * 10**9 * 0.9            # "4 GB" cards hold a little under 4e9 bytes
MAX_SIZE = 2 * 10**12


@dataclass
class Drive:
    id: str                            # what the user picks: sdb, disk4, 2
    path: str                          # what gets written: /dev/sdb, /dev/rdisk4, \\.\PhysicalDrive2
    name: str
    size: int
    bus: str = ""
    mounts: list = field(default_factory=list)

    @property
    def label(self) -> str:
        gb = self.size / 1e9
        kind = {"usb": "USB", "mmc": "SD card", "sd": "SD card", "secure digital": "SD card"}.get(self.bus.lower(), self.bus)
        return f"{self.name or 'Drive'} - {gb:.0f} GB" + (f" ({kind})" if kind else "")


def _sane(d: Drive) -> bool:
    return MIN_SIZE <= d.size <= MAX_SIZE


# --------------------------------------------------------------- Linux
def parse_lsblk(text: str) -> list[Drive]:
    data = json.loads(text)
    out = []
    for dev in data.get("blockdevices", []):
        if dev.get("type") != "disk":
            continue
        tran = (dev.get("tran") or "").lower()
        removable = bool(dev.get("rm")) or bool(dev.get("hotplug")) or tran in ("usb", "mmc") or \
            str(dev.get("name", "")).startswith("mmcblk")
        mounts = []
        for node in [dev] + list(dev.get("children") or []):
            mps = node.get("mountpoints") or ([node.get("mountpoint")] if node.get("mountpoint") else [])
            mounts += [m for m in mps if m]
        system = any(m in ("/", "/boot", "/boot/efi", "/usr", "/home", "[SWAP]") or m.startswith("/boot") for m in mounts)
        if not removable or system:
            continue
        name = " ".join(x for x in ((dev.get("vendor") or "").strip(), (dev.get("model") or "").strip()) if x)
        d = Drive(id=dev["name"], path=dev.get("path") or f"/dev/{dev['name']}", name=name,
                  size=int(dev.get("size") or 0), bus=tran or ("mmc" if dev["name"].startswith("mmcblk") else ""),
                  mounts=mounts)
        if _sane(d):
            out.append(d)
    return out


def _linux_drives() -> list[Drive]:
    cols = "NAME,PATH,SIZE,RM,HOTPLUG,TRAN,TYPE,VENDOR,MODEL,MOUNTPOINTS"
    r = subprocess.run(["lsblk", "-J", "-b", "-o", cols], capture_output=True, text=True)
    if r.returncode != 0:                                   # older util-linux: MOUNTPOINT only
        r = subprocess.run(["lsblk", "-J", "-b", "-o", cols.replace("MOUNTPOINTS", "MOUNTPOINT")],
                           capture_output=True, text=True, check=True)
    return parse_lsblk(r.stdout)


# --------------------------------------------------------------- macOS
def parse_diskutil(list_plist: bytes, info: dict) -> list[Drive]:
    """info: disk id -> plist bytes of `diskutil info -plist <id>`."""
    lst = plistlib.loads(list_plist)
    out = []
    for disk in lst.get("WholeDisks", []):
        try:
            i = plistlib.loads(info[disk])
        except (KeyError, plistlib.InvalidFileException):
            continue
        if i.get("Internal", True) and not i.get("RemovableMedia") and not i.get("Ejectable"):
            continue
        if i.get("VirtualOrPhysical") == "Virtual":
            continue
        d = Drive(id=disk, path=f"/dev/r{disk}", name=i.get("MediaName") or i.get("IORegistryEntryName") or "",
                  size=int(i.get("TotalSize") or i.get("Size") or 0), bus=i.get("BusProtocol") or "")
        if _sane(d):
            out.append(d)
    return out


def _mac_drives() -> list[Drive]:
    lst = subprocess.run(["diskutil", "list", "-plist", "external", "physical"], capture_output=True, check=True).stdout
    info = {}
    for disk in plistlib.loads(lst).get("WholeDisks", []):
        info[disk] = subprocess.run(["diskutil", "info", "-plist", disk], capture_output=True, check=True).stdout
    return parse_diskutil(lst, info)


# --------------------------------------------------------------- Windows
PS_LIST = ("Get-Disk | Select-Object Number,FriendlyName,Size,BusType,IsSystem,IsBoot,IsOffline "
           "| ConvertTo-Json -Compress")


def parse_windows(text: str) -> list[Drive]:
    data = json.loads(text or "[]")
    if isinstance(data, dict):
        data = [data]
    out = []
    for disk in data:
        bus = str(disk.get("BusType") or "")
        if isinstance(disk.get("BusType"), int):          # older PowerShell gives the enum number
            bus = {7: "USB", 12: "SD", 13: "MMC"}.get(disk["BusType"], str(disk["BusType"]))
        if bus not in ("USB", "SD", "MMC") or disk.get("IsSystem") or disk.get("IsBoot"):
            continue
        n = int(disk["Number"])
        d = Drive(id=str(n), path=rf"\\.\PhysicalDrive{n}", name=(disk.get("FriendlyName") or "").strip(),
                  size=int(disk.get("Size") or 0), bus=bus)
        if _sane(d):
            out.append(d)
    return out


def _windows_drives() -> list[Drive]:
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_LIST],
                       capture_output=True, text=True, check=True, creationflags=_NO_WINDOW)
    return parse_windows(r.stdout)


_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def list_drives() -> list[Drive]:
    if sys.platform == "win32":
        return _windows_drives()
    if sys.platform == "darwin":
        return _mac_drives()
    return _linux_drives()


def is_admin() -> bool:
    if sys.platform == "win32":
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


# --------------------------------------------------------------- write targets
class FileTarget:
    """A plain file (or a device node) - also what the tests use."""
    size = None

    def __init__(self, path: str):
        self.path = path
        self.fd = None
        try:
            st = os.stat(path)
            if not os.path.isfile(path):
                with open(path, "rb") as fh:
                    self.size = fh.seek(0, os.SEEK_END)
        except OSError:
            pass

    def _open_flags(self):
        return os.O_WRONLY | (os.O_CREAT if not os.path.exists(self.path) or os.path.isfile(self.path) else 0) | \
            getattr(os, "O_BINARY", 0)

    def begin(self):
        self.fd = os.open(self.path, self._open_flags(), 0o644)
        if os.path.isfile(self.path):
            os.ftruncate(self.fd, 0)
        self._since_sync = 0

    def write(self, b: bytes):
        view = memoryview(b)
        while view:
            n = os.write(self.fd, view)
            view = view[n:]
        self._since_sync += len(b)
        if self._since_sync >= 64 << 20 and hasattr(os, "fsync"):
            os.fsync(self.fd)                 # keeps the progress bar honest (no huge cache to flush at the end)
            self._since_sync = 0

    def flush(self):
        os.fsync(self.fd)

    def end(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def read_back(self, length: int, chunk: int):
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            if hasattr(os, "posix_fadvise"):
                os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)     # read the card, not the cache
            left = length
            while left > 0:
                b = os.read(fd, min(chunk, left))
                if not b:
                    break
                left -= len(b)
                yield b
        finally:
            os.close(fd)


class LinuxDrive(FileTarget):
    def __init__(self, drive: Drive):
        super().__init__(drive.path)
        self.drive = drive
        self.size = drive.size

    def begin(self):
        for m in sorted(set(self.drive.mounts), key=len, reverse=True):
            subprocess.run(["umount", m], capture_output=True)
        # O_EXCL on a block device: refuse if anything (a mount) still holds it.
        self.fd = os.open(self.path, os.O_WRONLY | os.O_EXCL)
        self._since_sync = 0

    def end(self):
        super().end()
        subprocess.run(["blockdev", "--rereadpt", self.path], capture_output=True)


class MacDrive(FileTarget):
    def __init__(self, drive: Drive):
        super().__init__(drive.path)
        self.drive = drive
        self.size = drive.size

    def begin(self):
        r = subprocess.run(["diskutil", "unmountDisk", f"/dev/{self.drive.id}"], capture_output=True, text=True)
        if r.returncode != 0:
            raise OSError(f"Couldn't unmount the card: {r.stderr.strip() or r.stdout.strip()}")
        self.fd = os.open(self.path, os.O_WRONLY)
        self._since_sync = 0

    def end(self):
        super().end()
        subprocess.run(["diskutil", "eject", f"/dev/{self.drive.id}"], capture_output=True)

    def read_back(self, length, chunk):
        subprocess.run(["diskutil", "unmountDisk", f"/dev/{self.drive.id}"], capture_output=True)
        yield from super().read_back(length, chunk)


class WindowsDrive(FileTarget):
    """\\\\.\\PhysicalDriveN. Windows keeps volumes on a disk mounted while it is
    written, so the disk is first wiped of partitions with diskpart's "clean"."""

    def __init__(self, drive: Drive):
        super().__init__(drive.path)
        self.drive = drive
        self.size = drive.size

    def _diskpart(self, *cmds):
        script = "\n".join([f"select disk {self.drive.id}", *cmds, "exit"]) + "\n"
        r = subprocess.run(["diskpart"], input=script, capture_output=True, text=True, creationflags=_NO_WINDOW)
        if r.returncode != 0:
            raise OSError("diskpart: " + (r.stdout.strip().splitlines() or ["failed"])[-1])

    def begin(self):
        self._diskpart("clean")
        self.fd = os.open(self.path, os.O_RDWR | os.O_BINARY)
        self._since_sync = 0

    def end(self):
        super().end()
        try:
            self._diskpart("rescan")
        except OSError:
            pass


def open_target(drive: Drive):
    if sys.platform == "win32":
        return WindowsDrive(drive)
    if sys.platform == "darwin":
        return MacDrive(drive)
    return LinuxDrive(drive)
