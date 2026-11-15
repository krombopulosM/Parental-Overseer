"""The fake internet for the end-to-end test. Runs inside the 'pg-inet'
namespace and serves:

  198.51.100.53:53    upstream DNS (a small fixed zone)
  198.51.100.10       ordinary website: TLS 443 + HTTP 80
  198.51.100.66:443   "VPN server" (listed in the VPN IP list)
  198.51.100.77       a VPS: TLS 443 + UDP echo (51820 WireGuard, 3074 games, 443 QUIC) + TCP 1194
  198.51.100.78:443   server-speaks-first service (SSH/VPN-like)
  198.51.100.79:443   TLS "tunnel" that streams data on request
  198.51.100.80:443   raw TCP echo (what a disguised VPN on 443 looks like)
  9.9.9.9:443         public DoH resolver
  192.168.1.1:80      the ISP router's admin page
"""
import socket
import socketserver
import ssl
import sys
import threading
import time

from dnslib import QTYPE, RR, A
from dnslib.server import BaseResolver, DNSLogger, DNSServer

ZONE = {
    "site.test": "198.51.100.10", "shared-cdn.test": "198.51.100.10", "adult-site.test": "198.51.100.10",
    "cloudflare-ech.com": "198.51.100.10", "vps.test": "198.51.100.77", "relay.test": "198.51.100.77",
    "vpn-server.test": "198.51.100.66", "serverfirst.test": "198.51.100.78",
    "tunnel.test": "198.51.100.79", "raw.test": "198.51.100.80",
}


class Zone(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        name = str(request.q.qname).rstrip(".").lower()
        if name in ZONE and QTYPE[request.q.qtype] == "A":
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ZONE[name]), ttl=300))
        elif name not in ZONE:
            reply.header.rcode = 3
        return reply


class TLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            conn = self.server.ctx.wrap_socket(self.request, server_side=True)
        except Exception:
            return
        try:
            data = conn.recv(100)
            if data.startswith(b"BULK"):
                end = time.time() + 60
                chunk = b"x" * 65536
                while time.time() < end:
                    for _ in range(3):
                        conn.sendall(chunk)
                    time.sleep(0.1)
            else:
                conn.sendall(b"OK\n")
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


class HTTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.recv(4096)
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nOK\n")
        except Exception:
            pass


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = self.request.recv(65536)
            if data:
                self.request.sendall(data)
        except Exception:
            pass


class ServerFirstHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            for _ in range(32):
                self.request.sendall(b"S" * 4096)
                time.sleep(0.05)
            time.sleep(10)
        except Exception:
            pass


class UDPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def tcp(addr, handler, ctx=None):
    s = TCPServer(addr, handler)
    s.ctx = ctx
    threading.Thread(target=s.serve_forever, daemon=True).start()


def main(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    DNSServer(Zone(), address="198.51.100.53", port=53, logger=DNSLogger("-request,-reply")).start_thread()
    for ip in ("198.51.100.10", "198.51.100.66", "198.51.100.77", "198.51.100.79", "9.9.9.9"):
        tcp((ip, 443), TLSHandler, ctx)
    tcp(("198.51.100.10", 80), HTTPHandler)
    tcp(("192.168.1.1", 80), HTTPHandler)
    tcp(("198.51.100.80", 443), EchoHandler)
    tcp(("198.51.100.77", 1194), EchoHandler)
    tcp(("198.51.100.78", 443), ServerFirstHandler)
    for port in (51820, 3074, 443):
        u = socketserver.ThreadingUDPServer(("198.51.100.77", port), UDPEcho)
        threading.Thread(target=u.serve_forever, daemon=True).start()
    print("servers ready", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
