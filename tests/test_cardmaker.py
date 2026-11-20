"""The Card Maker: finding drives safely, writing and checking a card, the
settings block, and changing the password on an existing card."""
import hashlib
import io
import json
import lzma
import os
import plistlib
import struct

import pytest

from cardmaker import core, drives
from guardian import appliance as ap
from guardian.auth import Auth

P1_START, P1_SIZE = 2048 * 512, 16 * 1024 * 1024


def make_image(path, settings_at=P1_START + 8 * 4096, decoy=True):
    """A small fake card image: MBR, a 'boot partition' holding the settings block,
    and a 'system partition' that also contains the marker text (as the real one
    does, inside the app's source) - which must not be mistaken for it."""
    size = P1_START + P1_SIZE + 4 * 1024 * 1024
    img = bytearray(os.urandom(size))
    mbr = bytearray(512)
    mbr[446:462] = bytes([0, 0, 0, 0, 0x0C, 0, 0, 0]) + struct.pack("<II", P1_START // 512, P1_SIZE // 512)
    mbr[510:512] = b"\x55\xaa"
    img[:512] = mbr
    img[settings_at:settings_at + ap.SETTINGS_SIZE] = ap.render_settings()
    if decoy:
        d = P1_START + P1_SIZE + 4096
        img[d:d + 100] = (ap.MARKER + " decoy in the system partition").encode().ljust(100)
    raw = bytes(img)
    if path.endswith(".xz"):
        with lzma.open(path, "wb", preset=0) as fh:
            fh.write(raw)
    else:
        with open(path, "wb") as fh:
            fh.write(raw)
    return raw, settings_at


def test_finds_the_settings_block_only_in_the_boot_partition(tmp_path):
    p = str(tmp_path / "card.img.xz")
    _, at = make_image(p)
    assert core.find_settings_offset(p) == at


def test_write_patches_settings_and_reads_back(tmp_path):
    p = str(tmp_path / "card.img.xz")
    raw, at = make_image(p)
    out = str(tmp_path / "card.bin")
    settings = core.make_settings("pa55word!", "Smiths")
    stages = set()
    res = core.write_image(p, out, settings=settings, progress=lambda s, d, t: stages.add(s))
    got = open(out, "rb").read()
    assert res["verified"] and res["bytes"] == len(raw) and {"write", "verify"} <= stages
    assert got[:at] == raw[:at] and got[at + ap.SETTINGS_SIZE:] == raw[at + ap.SETTINGS_SIZE:]
    vals = ap.parse_settings(got[at:at + ap.SETTINGS_SIZE])
    assert vals["dashboard_name"] == "smiths" and vals["password_hash"].startswith("pbkdf2_sha256$")
    assert b"pa55word!" not in got                                       # never the password itself


def test_patch_across_block_boundaries(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "CHUNK", 4096 * 3 + 512)                  # settings block straddles two reads
    p = str(tmp_path / "card.img")
    raw, at = make_image(p, settings_at=P1_START + 4096 * 3)
    out = str(tmp_path / "card.bin")
    s = core.make_settings(None, "kids")
    core.write_image(p, out, settings=s, offset=at)
    assert open(out, "rb").read()[at:at + ap.SETTINGS_SIZE] == s


def test_wrong_offset_is_refused(tmp_path):
    p = str(tmp_path / "card.img")
    make_image(p)
    with pytest.raises(core.CardError, match="settings block"):
        core.write_image(p, str(tmp_path / "out.bin"), settings=core.make_settings(), offset=P1_START + 512)


def test_bad_readback_is_caught(tmp_path):
    p = str(tmp_path / "card.img")
    make_image(p)

    class Flaky(drives.FileTarget):
        def read_back(self, length, chunk):
            for i, b in enumerate(super().read_back(length, chunk)):
                yield b if i != 2 else b"\0" * len(b)
    with pytest.raises(core.CardError, match="faulty"):
        core.write_image(p, Flaky(str(tmp_path / "out.bin")))


def test_too_small_card(tmp_path):
    p = str(tmp_path / "card.img")
    make_image(p)
    t = drives.FileTarget(str(tmp_path / "out.bin"))
    t.size = 1024 * 1024
    with pytest.raises(core.CardError, match="too small"):
        core.write_image(p, t)


def test_download_checks_the_checksum(tmp_path):
    body = b"x" * 3_000_000

    class Resp(io.BytesIO):
        headers = {"Content-Length": str(len(body))}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    info = {"url": "https://example.invalid/pg.img.xz", "image_download_sha256": hashlib.sha256(body).hexdigest()}
    path = core.download(info, dest_dir=str(tmp_path), opener=lambda *a, **k: Resp(body))
    assert open(path, "rb").read() == body
    # cached: no second download
    assert core.download(info, dest_dir=str(tmp_path), opener=lambda *a, **k: 1 / 0) == path
    info["image_download_sha256"] = "0" * 64
    os.remove(path)
    with pytest.raises(core.CardError, match="damaged"):
        core.download(info, dest_dir=str(tmp_path), opener=lambda *a, **k: Resp(body))
    assert not os.path.exists(path) and not os.path.exists(path + ".part")


def test_change_password_on_a_card(tmp_path):
    from guardian.db import DB
    (tmp_path / ap.SETTINGS_FILE).write_bytes(ap.render_settings({"dashboard_name": "smiths"}))
    assert core.update_card(str(tmp_path), password="new-password") == ["password"]
    raw = (tmp_path / ap.SETTINGS_FILE).read_bytes()
    assert len(raw) == ap.SETTINGS_SIZE and ap.parse_settings(raw)["dashboard_name"] == "smiths"
    db = DB(str(tmp_path / "g.db"))                                     # what the Pi does next time it starts
    ap.apply_settings(str(tmp_path / ap.SETTINGS_FILE), db, str(tmp_path / "l.yaml"))
    assert Auth(db).verify("new-password")
    db.close()
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / ap.SETTINGS_FILE).write_text("hello")
    with pytest.raises(core.CardError):
        core.update_card(str(tmp_path / "other"), password="whatever1")


LSBLK = {"blockdevices": [
    {"name": "nvme0n1", "path": "/dev/nvme0n1", "size": 512110190592, "rm": False, "hotplug": False, "tran": "nvme",
     "type": "disk", "vendor": None, "model": "Samsung SSD", "mountpoints": [None],
     "children": [{"name": "nvme0n1p2", "mountpoints": ["/"]}]},
    {"name": "sdb", "path": "/dev/sdb", "size": 31914983424, "rm": True, "hotplug": True, "tran": "usb",
     "type": "disk", "vendor": "SanDisk ", "model": "Ultra", "mountpoints": [None],
     "children": [{"name": "sdb1", "mountpoints": ["/media/me/bootfs"]}]},
    {"name": "mmcblk0", "path": "/dev/mmcblk0", "size": 15931539456, "rm": False, "hotplug": False, "tran": None,
     "type": "disk", "vendor": None, "model": None, "mountpoints": [None]},
    {"name": "sdc", "path": "/dev/sdc", "size": 1000000000, "rm": True, "hotplug": True, "tran": "usb",
     "type": "disk", "vendor": "Old", "model": "1GB", "mountpoints": [None]},
    {"name": "sdd", "path": "/dev/sdd", "size": 64000000000, "rm": True, "hotplug": True, "tran": "usb",
     "type": "disk", "vendor": "Live", "model": "USB", "mountpoints": [None],
     "children": [{"name": "sdd1", "mountpoints": ["/"]}]},           # booted from USB: that's the system disk
    {"name": "loop0", "type": "loop", "size": 99999999999, "rm": False}]}


def test_linux_drive_list_is_safe():
    ds = drives.parse_lsblk(json.dumps(LSBLK))
    assert [d.id for d in ds] == ["sdb", "mmcblk0"]
    assert ds[0].mounts == ["/media/me/bootfs"] and ds[0].label == "SanDisk Ultra - 32 GB (USB)"
    assert ds[1].label == "Drive - 16 GB (SD card)"


def test_mac_drive_list_is_safe():
    lst = plistlib.dumps({"WholeDisks": ["disk0", "disk4", "disk5"]})
    info = {"disk0": plistlib.dumps({"Internal": True, "TotalSize": 500 * 10**9, "MediaName": "APPLE SSD"}),
            "disk4": plistlib.dumps({"Internal": False, "RemovableMedia": True, "TotalSize": 32 * 10**9,
                                     "MediaName": "SD Card Reader", "BusProtocol": "Secure Digital"}),
            "disk5": plistlib.dumps({"Internal": False, "VirtualOrPhysical": "Virtual", "TotalSize": 10**10})}
    ds = drives.parse_diskutil(lst, info)
    assert [(d.id, d.path) for d in ds] == [("disk4", "/dev/rdisk4")] and "(SD card)" in ds[0].label


def test_windows_drive_list_is_safe():
    data = [{"Number": 0, "FriendlyName": "NVMe", "Size": 512 * 10**9, "BusType": "NVMe", "IsSystem": True, "IsBoot": True},
            {"Number": 2, "FriendlyName": "Generic SD/MMC", "Size": 31 * 10**9, "BusType": "SD", "IsSystem": False},
            {"Number": 3, "FriendlyName": "Kingston", "Size": 64 * 10**9, "BusType": 7, "IsSystem": False},
            {"Number": 4, "FriendlyName": "USB HDD", "Size": 4 * 10**12, "BusType": "USB", "IsSystem": False}]
    ds = drives.parse_windows(json.dumps(data))
    assert [(d.id, d.path) for d in ds] == [("2", r"\\.\PhysicalDrive2"), ("3", r"\\.\PhysicalDrive3")]
    assert drives.parse_windows(json.dumps(data[1]))[0].id == "2"        # one disk: PowerShell gives an object


def test_command_line_write(tmp_path, monkeypatch, capsys):
    from cardmaker.__main__ import main
    img = str(tmp_path / "card.img.xz")
    raw, at = make_image(img)
    out = str(tmp_path / "card.bin")
    d = drives.Drive(id="sdz", path=out, name="Test", size=64 * 10**9)
    monkeypatch.setattr(drives, "list_drives", lambda: [d])
    monkeypatch.setattr(drives, "open_target", lambda drive: drives.FileTarget(drive.path))
    monkeypatch.setattr("sys.stdin", io.StringIO("cli-password\n"))
    assert main(["write", "--drive", "sdz", "--image", img, "--password-stdin", "--name", "kids", "-y"]) == 0
    assert "written and checked" in capsys.readouterr().out
    vals = ap.parse_settings(open(out, "rb").read()[at:at + ap.SETTINGS_SIZE])
    assert vals["dashboard_name"] == "kids"
    assert main(["write", "--drive", "sda", "--image", img, "--no-password", "-y"]) == 1   # not offered: refused
    # the window's administrator helper: progress and result as JSON lines
    sf, pf = tmp_path / "s.bin", tmp_path / "p.jsonl"
    sf.write_bytes(core.make_settings("helper-pass"))
    assert main(["write", "--drive", "sdz", "--image", img, "--settings-file", str(sf),
                 "--progress-file", str(pf), "-y"]) == 0
    lines = [json.loads(x) for x in pf.read_text().splitlines()]
    assert lines[-1]["result"]["verified"] and any(x.get("stage") == "verify" for x in lines[:-1])
