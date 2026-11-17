"""Keep what the gateway prints, so problems can be looked at afterwards.

Everything written to stdout/stderr - status lines, warnings, uncaught
exceptions with their tracebacks - still goes to the console (or the Pi's
journal) as before, and is also appended to <data>/logs/<name>.log with a
timestamp and the process ID on each line. Files rotate at 2 MB, keeping 3
old ones, so the logs never fill the SD card. The diagnostics export
(diagnostics.py) bundles them.
"""
from __future__ import annotations

import os
import sys
import threading
import time
import traceback

MAX_BYTES = 2_000_000
KEEP = 3


class _Tee:
    """A text stream that writes to the original stream and to the log file."""

    def __init__(self, original, log: "LogFile", tag: str):
        self._orig, self._log, self._tag = original, log, tag
        self._at_line_start = True

    def write(self, s):
        try:
            if self._orig is not None:
                self._orig.write(s)
        except Exception:
            pass
        if s:
            self._log.write(s, self._tag)
        return len(s)

    def flush(self):
        try:
            if self._orig is not None:
                self._orig.flush()
        except Exception:
            pass

    def __getattr__(self, name):                 # isatty, fileno, encoding, ... from the original
        return getattr(self._orig, name)


class LogFile:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._pending = {"out": "", "err": ""}
        self._writes = 0

    def write(self, text: str, tag: str):
        with self._lock:
            buf = self._pending[tag] + text
            lines = buf.split("\n")
            self._pending[tag] = lines.pop()       # an unfinished line waits for its end
            if not lines:
                return
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            out = "".join(f"{stamp} [{os.getpid()}]{' !' if tag == 'err' else ''} {ln}\n" for ln in lines)
            try:
                with open(self.path, "a", encoding="utf-8", errors="replace") as fh:
                    fh.write(out)
            except OSError:
                return
            self._writes += 1
            if self._writes % 100 == 0:
                self._rotate()

    def _rotate(self):
        try:
            if os.path.getsize(self.path) < MAX_BYTES:
                return
            for i in range(KEEP - 1, 0, -1):
                src = f"{self.path}.{i}"
                if os.path.exists(src):
                    os.replace(src, f"{self.path}.{i + 1}")
            os.replace(self.path, f"{self.path}.1")
        except OSError:
            pass                                     # another process rotated it, or Windows has it open


_active: LogFile | None = None


def capture(data_dir: str, name: str) -> str | None:
    """Start copying this process's output into <data_dir>/logs/<name>.log."""
    global _active
    if _active is not None:
        return _active.path
    logdir = os.path.join(data_dir, "logs")
    try:
        os.makedirs(logdir, exist_ok=True)
    except OSError:
        return None
    _active = LogFile(os.path.join(logdir, f"{name}.log"))
    sys.stdout = _Tee(sys.stdout, _active, "out")
    sys.stderr = _Tee(sys.stderr, _active, "err")

    def thread_hook(args):                       # a background thread died: keep the traceback
        if args.exc_type is SystemExit:
            return
        print(f"[crash] thread {args.thread.name if args.thread else '?'} stopped: "
              f"{args.exc_type.__name__}: {args.exc_value}", file=sys.stderr)
        traceback.print_exception(args.exc_type, args.exc_value, args.exc_traceback, file=sys.stderr)
    threading.excepthook = thread_hook
    print(f"[log] {name} started (pid {os.getpid()}, python {sys.version.split()[0]}, {sys.platform})")
    return _active.path


def log_dir(data_dir: str) -> str:
    return os.path.join(data_dir, "logs")
