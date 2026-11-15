"""Filtering DNS server.

Every lookup is logged with the client IP and timestamp. Blocked lookups get
NXDOMAIN (the device behaves as if the domain doesn't exist); allowed lookups
are forwarded to the upstream resolver and the answer is passed back.
"""
from dnslib import DNSRecord, QTYPE, RCODE
from dnslib.server import DNSServer, BaseResolver


class FilterResolver(BaseResolver):
    def __init__(self, db, policy, upstream_host, upstream_port):
        self.db = db
        self.policy = policy
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")
        try:
            qtype = QTYPE[request.q.qtype]
        except Exception:
            qtype = str(request.q.qtype)
        client_ip = handler.client_address[0]

        self.db.touch_device(client_ip)
        decision = self.policy.decide(client_ip, qname)

        if decision.block:
            self.db.log_query(client_ip, qname, qtype, "blocked", decision.reason)
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        self.db.log_query(client_ip, qname, qtype, "allowed", decision.reason)
        try:
            data = request.send(self.upstream_host, self.upstream_port,
                                tcp=False, timeout=4)
            return DNSRecord.parse(data)
        except Exception:
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def start_dns(db, policy, cfg):
    resolver = FilterResolver(db, policy,
                              cfg["dns"]["upstream_host"], cfg["dns"]["upstream_port"])
    host, port = cfg["dns"]["listen_host"], cfg["dns"]["listen_port"]
    udp = DNSServer(resolver, address=host, port=port, tcp=False)
    tcp = DNSServer(resolver, address=host, port=port, tcp=True)
    udp.start_thread()
    tcp.start_thread()
    print(f"[dns] listening on {host}:{port} (udp+tcp) -> upstream "
          f"{cfg['dns']['upstream_host']}:{cfg['dns']['upstream_port']}")
    return udp, tcp
