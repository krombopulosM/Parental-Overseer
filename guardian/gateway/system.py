"""Small Linux helpers: sysctls, running nft/iptables, killing conntrack flows."""
from __future__ import annotations

import os
import subprocess


def sysctl(path: str, value: str) -> bool:
    try:
        with open(os.path.join("/proc/sys", path), "w") as fh:
            fh.write(value)
        return True
    except OSError:
        return False


def run(cmd: list[str], stdin: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    res = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=60)
    if check and res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} failed: {res.stderr.strip()[:500]}")
    return res


def nft(script: str, check: bool = True):
    return run(["nft", "-f", "-"], stdin=script, check=check)


def kill_flows(src: str | None = None, dst: str | None = None):
    """Drop conntrack state so an already-open connection is re-evaluated
    (and blocked) on its very next packet."""
    args = ["conntrack", "-D"]
    if src:
        args += ["-s", src]
    if dst:
        args += ["-d", dst]
    if src or dst:
        run(args, check=False)
