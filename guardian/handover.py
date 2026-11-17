"""Pieces that let a new version take over from a running one with no gap.

During an update both processes run for a few seconds:

  * DNS and the dashboard: both bind the same ports with SO_REUSEPORT; the
    kernel shares new queries/connections between them until the old one
    closes its sockets. Nobody's lookups go unanswered.
  * Packet inspection: the new process binds the *other* NFQUEUE number, then
    swaps the firewall over to it in one atomic transaction (gateway/nft.py).
    The old process finishes the packets already queued to it, then exits.
  * Everything that must run once - traffic accounting, the behaviour detector,
    the LAN watch, list downloads, the update check - is guarded by a lock
    (Leader). The new process takes those over the moment the old one exits.
"""
from __future__ import annotations

import os
import socket
import sys
import threading

from dnslib.server import TCPServer as _DnsTCPServer
from dnslib.server import UDPServer as _DnsUDPServer

REUSEPORT = hasattr(socket, "SO_REUSEPORT")


SO_ATTACH_REUSEPORT_CBPF = 51


def _reuseport(sock):
    if REUSEPORT:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)


def steer_to_newest(sock):
    """Linux: send every new datagram/connection on this port to the socket bound
    most recently - ours. The previous version's socket then only holds what's
    already queued, which it answers before closing, so nothing is lost.

    A one-instruction classic-BPF program, 'return 1', attached to the port's
    SO_REUSEPORT group: during a hand-over the group is [previous, ours] and
    index 1 is ours; when the previous socket goes, index 1 is out of range and
    the kernel falls back to its normal choice (the only socket left)."""
    if not (REUSEPORT and sys.platform.startswith("linux")):
        return False
    import ctypes

    class SockFilter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte),
                    ("k", ctypes.c_uint32)]

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]

    prog_insns = (SockFilter * 1)(SockFilter(0x06, 0, 0, 1))          # BPF_RET | BPF_K, k=1
    prog = SockFprog(1, ctypes.cast(prog_insns, ctypes.POINTER(SockFilter)))
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, bytes(prog))
        return True
    except OSError:
        return False


class ReuseUDPServer(_DnsUDPServer):
    def server_bind(self):
        _reuseport(self.socket)
        super().server_bind()
        steer_to_newest(self.socket)


class ReuseTCPServer(_DnsTCPServer):
    def server_bind(self):
        _reuseport(self.socket)
        super().server_bind()

    def server_activate(self):
        super().server_activate()
        steer_to_newest(self.socket)            # TCP: only once listening, or sharing breaks


def web_socket(host: str, port: int) -> socket.socket:
    """A listening socket for the dashboard that the next version can share."""
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    if os.name == "nt":
        # On Windows SO_REUSEADDR would let a second copy silently share the port.
        s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", -5), 1)
    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _reuseport(s)
    s.bind((host, port))
    s.listen(128)
    steer_to_newest(s)
    s.set_inheritable(False)
    return s


class Leader:
    """An exclusive lock on <data>/leader.lock held for the life of the process.
    The first process takes it at once; a process started during an update waits
    and is called back the moment the previous one exits (the OS releases the
    lock with the process, even if it crashes)."""

    def __init__(self, path: str):
        self.path = path
        self.fh = None
        self.is_leader = False

    def try_acquire(self) -> bool:
        self.fh = self.fh or open(self.path, "a+")
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.is_leader = True
        except OSError:
            self.is_leader = False
        return self.is_leader

    def acquire_then(self, callback, poll: float = 0.25):
        """Call callback() as soon as the lock is ours (now, or when the holder exits)."""
        if self.try_acquire():
            callback()
            return

        def wait():
            import time
            while not self.try_acquire():
                time.sleep(poll)
            callback()
        threading.Thread(target=wait, name="leader-wait", daemon=True).start()

    def release(self):
        if self.fh is not None:
            try:
                if os.name != "nt":
                    import fcntl
                    fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            finally:
                self.fh.close()
                self.fh = None
                self.is_leader = False


def signal_ready(fd: int | None, message: str = "ready"):
    """Tell the supervisor this process is serving (it then retires the old one)."""
    if fd is None:
        return
    try:
        os.write(fd, (message + "\n").encode())
        os.close(fd)
    except OSError:
        pass
