"""Parental Gateway Card Maker.

    python -m cardmaker                      the window (default)
    python -m cardmaker list                 SD cards / USB drives that can be written
    python -m cardmaker write --drive sdb [--image file.img.xz] [--name family]
                                             asks for the dashboard password
    python -m cardmaker set-password [--card /media/me/bootfs]
                                             change the password on an existing card
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

if __package__ in (None, ""):                       # run as a frozen app or a plain script
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    __package__ = "cardmaker"

from cardmaker import core, drives  # noqa: E402


def _ask_password() -> str:
    while True:
        p = getpass.getpass("Dashboard password (8+ characters): ")
        if len(p) < 8:
            print("  Too short.")
            continue
        if getpass.getpass("Again: ") != p:
            print("  They don't match.")
            continue
        return p


class _Progress:
    """Progress to the terminal, or as JSON lines to a file (for the window,
    when the writing runs as an administrator in a separate process)."""

    def __init__(self, path=None):
        self.path, self.last = path, None

    def __call__(self, stage, done, total):
        pct = int(100 * done / total) if total else 0
        if (stage, pct) == self.last:
            return
        self.last = (stage, pct)
        if self.path:
            self.emit({"stage": stage, "done": done, "total": total})
        else:
            label = {"download": "Downloading", "check-download": "Checking download", "prepare": "Preparing",
                     "write": "Writing", "verify": "Checking card"}.get(stage, stage)
            print(f"\r{label}: {pct}%   ", end="", flush=True)

    def emit(self, obj):
        with open(self.path, "a") as fh:
            fh.write(json.dumps(obj) + "\n")


def cmd_list(_args):
    ds = drives.list_drives()
    if not ds:
        print("No SD cards or USB drives found. Insert one and try again.")
    for d in ds:
        print(f"{d.id:10} {d.label}")
    return 0


def cmd_write(args):
    prog = _Progress(args.progress_file)
    try:
        if args.output:
            drive, target = None, drives.FileTarget(args.output)
        else:
            ds = {d.id: d for d in drives.list_drives()}
            if args.drive not in ds:
                raise core.CardError(f"'{args.drive}' isn't an SD card or USB drive here (see: list).")
            drive = ds[args.drive]
            target = drives.open_target(drive)
        if args.settings_file:
            with open(args.settings_file, "rb") as fh:
                settings = fh.read()
            if len(settings) != core.SETTINGS_SIZE or not settings.startswith(core.MARKER.encode()):
                raise core.CardError("bad settings file")
        else:
            pw = None
            if args.password_stdin:
                pw = sys.stdin.readline().rstrip("\n")
            elif not args.no_password:
                pw = _ask_password()
            ssh = open(args.ssh_key_file).read() if args.ssh_key_file else None
            settings = core.make_settings(pw, args.name, ssh)
        info, image = None, args.image
        if not image:
            info = core.fetch_info(args.info_url)
            image = core.download(info, prog)
        elif args.info_file:
            with open(args.info_file) as fh:
                info = json.load(fh)
        if drive and not args.yes and not args.progress_file:
            ok = input(f"\nEverything on {drive.label} ({drive.path}) will be erased. Type 'yes' to go on: ")
            if ok.strip().lower() != "yes":
                print("Stopped - nothing was written.")
                return 1
        res = core.write_image(image, target, settings=settings,
                               offset=(info or {}).get("settings_offset"),
                               size=core.image_size(image, info), progress=prog, verify=not args.no_verify)
        if args.progress_file:
            prog.emit({"result": res})
        else:
            print(f"\nDone: {res['bytes'] / 1e9:.2f} GB written and checked in {res['seconds']:.0f} s.")
            print("Put the card in the Pi, plug in both network cables (either way round) and the power.")
            print("After about two minutes open http://%s.local from any device at home." % (args.name or "family"))
        return 0
    except (core.CardError, OSError) as e:
        if args.progress_file:
            prog.emit({"error": str(e)})
        else:
            print(f"\nError: {e}")
        return 1


def cmd_set_password(args):
    vols = [args.card] if args.card else core.card_volumes()
    if not vols:
        print("No Parental Gateway card found. Put the card in this computer; its 'bootfs' drive should appear.")
        return 1
    if len(vols) > 1:
        print("More than one card found - choose one with --card:", *vols, sep="\n  ")
        return 1
    pw = sys.stdin.readline().rstrip("\n") if args.password_stdin else _ask_password()
    core.update_card(vols[0], password=pw)
    print(f"Saved on {vols[0]}. Eject the card, put it back in the Pi and restart it (unplug the power for 10 s).")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cardmaker", description="Make a Parental Gateway card for a Raspberry Pi.")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list", help="list SD cards and USB drives")
    w = sub.add_parser("write", help="write a card")
    where = w.add_mutually_exclusive_group(required=True)
    where.add_argument("--drive", help="the card, as shown by 'list'")
    where.add_argument("--output", help="write a ready-to-use .img file instead (for other card-writing tools)")
    w.add_argument("--image", help=".img.xz or .img file (default: download the latest)")
    w.add_argument("--info-file", help="the image's .json information file (when using --image)")
    w.add_argument("--info-url", default=core.INFO_URL)
    w.add_argument("--name", default=None, help="dashboard name (default family -> http://family.local)")
    w.add_argument("--ssh-key-file")
    w.add_argument("--password-stdin", action="store_true")
    w.add_argument("--no-password", action="store_true", help="choose it in the dashboard instead")
    w.add_argument("--settings-file", help=argparse.SUPPRESS)
    w.add_argument("--progress-file", help=argparse.SUPPRESS)
    w.add_argument("--no-verify", action="store_true")
    w.add_argument("-y", "--yes", action="store_true")
    s = sub.add_parser("set-password", help="change the dashboard password on an existing card")
    s.add_argument("--card", help="the card's boot drive (found automatically if left out)")
    s.add_argument("--password-stdin", action="store_true")
    args = ap.parse_args(argv)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "write":
        return cmd_write(args)
    if args.cmd == "set-password":
        return cmd_set_password(args)
    from cardmaker.app import run
    return run()


if __name__ == "__main__":
    sys.exit(main())
