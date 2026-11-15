"""Replay a packet capture through the gateway's inspector and report what it
would have blocked, and why. Works on Windows, macOS and Linux.

Typical use on your PC: start a Wireshark capture, connect with a VPN app
(or try any other bypass), stop and save the capture, then:

    python tools/replay.py capture.pcapng
    python tools/replay.py capture.pcapng --group consoles --client 192.168.1.23

DNS answers inside the capture are fed to the DNS-consistency check, exactly as
the gateway's own resolver would have recorded them. Blocklists come from the
local cache (run `python run.py --update-lists` once for the full lists).
"""
import argparse
import collections
import ipaddress
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from dnslib import DNSRecord, QTYPE  # noqa: E402

from guardian.alerts import AlertSink  # noqa: E402
from guardian.config import load_config  # noqa: E402
from guardian.dnscache import DnsCache  # noqa: E402
from guardian.identity import Identity  # noqa: E402
from guardian.inspector import ACCEPT, FlowLabels, Inspector  # noqa: E402
from guardian.lists import ListManager  # noqa: E402
from guardian.policy import Policy  # noqa: E402
from guardian.protocols import parse_ip  # noqa: E402


def is_lan(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local
    except ValueError:
        return False


def replay(path, group, client=None, cfg=None, out=print):
    from scapy.all import IP, IPv6, PcapReader

    cfg = cfg or load_config()
    lists = ListManager(cfg)
    lists.load()
    alerts = AlertSink()
    policy = Policy(cfg, None, lists, Identity(cfg), alerts)
    policy.forced_group = group
    dnscache = DnsCache(cfg["enforcement"]["consistency_grace"])
    labels = FlowLabels()
    insp = Inspector(cfg, policy, lists, dnscache, alerts, labels)
    g = cfg["groups"][group]
    limit_web = int(cfg["enforcement"].get("inspect_packets", 10))

    seen = collections.Counter()
    first_block = {}
    flows = {}
    n = 0
    with PcapReader(path) as reader:
        for sp in reader:
            layer = sp.getlayer(IP) or sp.getlayer(IPv6)
            if layer is None:
                continue
            raw = bytes(layer)
            p = parse_ip(raw)
            if p is None or not (p.is_tcp or p.is_udp):
                continue
            # DNS answers -> resolution memory (what the gateway's resolver would know)
            if p.is_udp and p.sport == 53 and p.payload:
                try:
                    rec = DNSRecord.parse(p.payload)
                    names = [str(rec.q.qname).rstrip(".")] + [str(r.rdata).rstrip(".") for r in rec.rr
                                                               if QTYPE[r.rtype] == "CNAME"]
                    ips = [(str(r.rdata), r.ttl) for r in rec.rr if QTYPE[r.rtype] in ("A", "AAAA")]
                    if ips:
                        dnscache.record(p.dst, names, ips)
                except Exception:
                    pass
                continue
            if p.dport == 53:
                continue
            if client and p.src != client:
                continue
            if not client and not (is_lan(p.src) and not is_lan(p.dst)):
                continue
            key = ("tcp" if p.is_tcp else "udp", p.src, p.sport, p.dst, p.dport)
            seen[key] += 1
            # mimic the firewall: only the first packets of a connection reach the inspector
            if p.is_tcp and p.dport in (80, 443):
                limit = limit_web
            elif p.is_udp and g.get("allow_udp"):
                limit = 3
            else:
                limit = 1
            if seen[key] > limit:
                continue
            n += 1
            v = insp.inspect(raw, now=float(sp.time))
            flows.setdefault(key, None)
            if v.action != ACCEPT and key not in first_block:
                first_block[key] = v

    out(f"\nReplayed {n} packets from {len(flows)} connections as group '{group}'\n")
    blocked = [(k, v) for k, v in first_block.items() if v.kind not in ("quic", "port")]
    quiet = [(k, v) for k, v in first_block.items() if v.kind in ("quic", "port")]
    if blocked:
        out("BLOCKED (bypass attempts / blocked sites):")
        for (proto, src, sport, dst, dport), v in blocked:
            out(f"  {proto} {src}:{sport} -> {dst}:{dport:<5}  [{v.kind}] {v.reason}")
    if quiet:
        by = collections.Counter(f"{k[0]}/{k[4]}" for k, _ in quiet)
        out("\nDropped without alert (QUIC / non-web ports): " + ", ".join(f"{p} x{c}" for p, c in by.most_common()))
    allowed = [k for k in flows if k not in first_block]
    out(f"\nALLOWED: {len(allowed)} connections")
    names = collections.Counter((labels.get(k) or {}).get("domain") or f"{k[3]}:{k[4]}" for k in allowed)
    for name, c in names.most_common(25):
        out(f"  {c:4}  {name}")
    return {"blocked": blocked, "allowed": allowed, "alerts": alerts.memory}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--group", default="kids", help="policy group to evaluate as (default: kids)")
    ap.add_argument("--client", help="only replay traffic from this IP (default: every private IP)")
    ap.add_argument("--config", default=os.path.join(HERE, "config.yaml"))
    a = ap.parse_args()
    cfg = load_config(a.config)
    if a.group not in cfg["groups"]:
        sys.exit(f"unknown group {a.group}; choose from {', '.join(cfg['groups'])}")
    replay(a.pcap, a.group, a.client, cfg)


if __name__ == "__main__":
    main()
