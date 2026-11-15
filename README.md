# Parental Gateway

A home network parental-control system: it logs which domains each device looks
up, filters them per device group, and shows everything in a browser dashboard.
Runs the same on your Windows PC (for development) and on a Raspberry Pi (as the
real gateway).

This is **Phase 1** of the plan — DNS-level filtering and visibility. See
[Roadmap](#roadmap) for what comes next.

## What it does today

- **Filtering DNS resolver** — every device's DNS lookups go through it. Blocked
  names return `NXDOMAIN`; everything else is forwarded upstream (Cloudflare by
  default) and logged.
- **Per-device groups** — devices start in `default` (unfiltered). Move a child's
  device into the `kids` group from the dashboard to apply the kids' blocklists.
- **Category blocklists** — `blocklists/ads.txt`, `blocklists/adult.txt`. Swap in
  maintained lists (StevenBlack, Hagezi) for real coverage.
- **Rules** — block or allow a specific domain for everyone or just the kids
  group. An allow rule overrides a block, so you can whitelist one site inside a
  blocked category.
- **Dashboard** — lookups/blocked counts, per-device activity, top domains, a
  live feed, and all the controls. Auto-refreshes every 3 seconds.

### What it does NOT do (by design)

DNS filtering sees **domains**, not pages — `youtube.com`, never which video.
That's the honest limit of anything that doesn't break encryption. Per-page
history needs device-level tools (Microsoft Family Safety, Family Link, Screen
Time). Byte counts and connection duration come in Phase 2 (passive flow
monitor), which reads the clear-text server name in the TLS handshake — still no
decryption.

## Setup

```bash
cd parental-gateway
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux:    source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Open the dashboard at **http://127.0.0.1:8080**.

By default the resolver listens on port **5353** (so it needs no admin rights
while you develop). The OS can't be pointed at a non-standard DNS port, so test
it directly:

```bash
# blocked for the kids group, allowed otherwise:
nslookup -port=5353 pornhub.com 127.0.0.1
# normal site:
nslookup -port=5353 bbc.co.uk 127.0.0.1
```

Each lookup appears in the dashboard's live feed immediately. To see blocking
take effect, move `127.0.0.1` into the `kids` group in the Devices panel, then
re-run the first lookup — it returns `NXDOMAIN` and shows as blocked.

### Using it to actually filter a machine

Set `dns.listen_port: 53` in `config.yaml` (needs admin on Windows / root on the
Pi, and nothing else can be using port 53), restart, then point a device's DNS
server at this machine's IP. On the Pi this becomes the network's resolver.

## How it will deploy on the Raspberry Pi

The Pi becomes the network's router, so there's no path around it:

```
ISP router (bridge mode) ── Raspberry Pi (this software + routing) ── Wi-Fi AP ── devices
```

Phase 3 adds the routing and lockdown (forcing all DNS through us, blocking DoH,
QUIC and VPN escape routes, device quarantine). Until then this runs fine as a
plain DNS filter on any machine.

## Roadmap

- **Phase 1 (done)** — filtering + logging DNS resolver, web dashboard.
- **Phase 2** — passive flow monitor: SNI + bytes + duration per connection, so
  you get "where, how long, how much data" without decrypting anything.
- **Phase 3** — Pi gateway hardening: nftables routing, forced DNS, egress
  lockdown (block DoH/DoT/QUIC/VPN), new-device quarantine, schedules.

## Note

This is a separate project that currently lives inside the Mini-motorways repo
folder only so it's easy to see and run. It is not part of that game and should
move to its own repository before it goes on the Pi.
