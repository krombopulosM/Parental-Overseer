# Parental Gateway

A home-network filter for a family with kids who will actively try to get
around it. A Raspberry Pi sits between your ISP router and your Wi-Fi, so all
traffic passes through it. It:

- **filters** sites by category (adult, gambling, ads, VPN/proxy/bypass) per device group
- **shows** which device went where, for how long, and how much data moved
- **stops bypasses**: VPNs (including obfuscated ones like ProtonVPN Stealth and
  Mullvad's udp2tcp / Shadowsocks / QUIC modes), encrypted DNS, proxies, Tor,
  iCloud Private Relay, hard-coded IPs, disguised tunnels
- **stops torrents**, including encrypted ones and ones hidden on port 443
- **defends itself** against a skilled kid attacking the gateway: spoofed or
  cloned MAC addresses, ARP spoofing, rogue DHCP servers or IPv6 routers,
  port scans, password guessing, hidden hotspots, manual DNS or IP settings,
  and pulling the plug
- **scores every alert** with how confident it is that the attempt was
  deliberate, and learns from your reviews
- shows a **Health page**: is the protection working, and who tried what, how
  often
- is controlled from a **browser dashboard** with a login

It works at the level of **site names** (`youtube.com`), not individual pages,
and it never breaks encryption: no certificates to install, no HTTPS
downgrade. The site name is visible in every connection's handshake, and the
gateway makes sure it stays visible.

The same code runs on your **Windows PC** (monitor mode, for development) and
on the **Pi** (gateway mode, full enforcement).

---

## How the anti-bypass works

Each layer works independently, so a VPN that slips past one hits the next.

| Layer | What it does | What it stops |
|---|---|---|
| **The Pi is the router** | No other path to the internet | Static IPs, rogue gateways, ARP tricks |
| **Unknown devices are filtered** | Only devices you mark as adults escape the filter | Randomised or spoofed MACs, new devices |
| **DNS is forced through the Pi** | Every port-53 lookup is redirected to the Pi, whatever server it was meant for | "Just use 8.8.8.8" |
| **Encrypted DNS blocked** | DoH/DoT resolvers blocked by name and IP, Firefox canary domain, port 853 | Browser "secure DNS", Android Private DNS |
| **ECH disabled** | HTTPS/SVCB records stripped, so browsers never get Encrypted Client Hello keys | Hiding the site name in the handshake |
| **Web ports only** | Kids get TCP 80/443 and small NTP packets; nothing else leaves | WireGuard, OpenVPN-UDP, IPsec, Tor ORPort, Shadowsocks, QUIC/HTTP3 (browsers fall back to TCP), Mullvad's QUIC obfuscation |
| **Protocol conformance** | Port 443 must open with a real TLS handshake; port 80 must be real HTTP | Mullvad udp2tcp, OpenVPN-over-TCP, Shadowsocks/obfs4/VLESS, SSH-on-443, server-first protocols, HTTP CONNECT proxies |
| **DNS consistency** | A kid's device may only connect to IPs the Pi's DNS gave it | Hard-coded VPN server IPs, VPN apps' built-in resolvers, Proton's "alternative routing", hosts-file entries, Reality-style disguises |
| **Site-name checks** | The TLS name must be present, allowed, and match what DNS returned for that IP | No-SNI clients, domain fronting, `www.microsoft.com` disguises, ECH fronts, blocked sites on shared CDN IPs |
| **VPN / DoH IP lists** | Mullvad relays, Proton servers, Tor relays, Cloudflare WARP, public resolvers (refreshed daily) | Direct connections to known VPN servers |
| **Anti-evasion** | Handshakes split into tiny TCP segments or TLS records are reassembled; handshakes still unfinished after the inspection window are blocked | GoodbyeDPI-style fragmentation tricks |
| **DNS tunnel detection** | Bursts of long random subdomains, NULL/ANY lookups | iodine, dnscat |
| **Behaviour detector** | Scores long-lived, heavy connections from a device that has stopped making DNS lookups | Anything still hiding inside real TLS: Proton Stealth to a new IP, Trojan, Tor WebTunnel, a self-hosted VPN |
| **Fail closed** | If the inspector stops, filtered devices lose web access until it's back | Crashing or killing the service |
| **Tamper protection** | Password-protected dashboard reachable only from adults' devices; kids can't reach the ISP router's admin page | Unblocking themselves |

For example, Mullvad has to get past three separate layers:
1. Its API and relay IPs are blocked.
2. Its WireGuard and QUIC modes need UDP, which kids don't get.
3. Its udp2tcp and Shadowsocks modes aren't real TLS, so they fail the protocol check on 443.

ProtonVPN Stealth *is* real TLS, but it connects to server IPs the Pi's DNS never handed out, and those IPs are on the Proton server list anyway.

## Torrents

| Signal | Catches |
|---|---|
| Torrent sites, public trackers, DHT bootstrap nodes, client websites (DNS + TLS name) | Finding torrents, a fresh client finding peers |
| BitTorrent handshake, even disguised on port 443 or 80 | Peer connections |
| HTTP tracker announces (`/announce?info_hash=`), UDP tracker protocol | Tracker contact |
| DHT and uTP packet headers (unencrypted even when the client "encrypts") | Trackerless/magnet downloads, uTP transfers |
| Contacting 25+ different peers on random ports within a minute | **Fully encrypted** clients with no visible signature |
| BitTorrent local peer discovery broadcasts on the LAN | A client running at all, even if nothing reached the internet |

Kids' devices already get no UDP and only real web traffic on 80/443, so
torrents are blocked several times over. The `consoles` group (UDP allowed) still
has torrent signatures blocked.

## Defences against countermeasures

On the Pi, a passive **LAN watch** listens (never transmits, except to undo ARP
spoofing) for attacks on the gateway itself. Every response follows one rule:
**an automatic defence can restrict, never grant.**

| Countermeasure | What happens |
|---|---|
| Copy a parent's MAC address | The device's **DHCP fingerprint** (the options its OS asks for) doesn't match the parent device's, so that address is treated as filtered until the parent clicks **"It's me"** |
| Two devices sharing one MAC | Fingerprint flips back and forth: flagged as a clone |
| Change MAC to escape the kids group | New MAC with the same fingerprint and hostname keeps the kids' group. Copying an *adult's* fingerprint gets nothing |
| ARP-spoof the gateway (MITM) | Corrective ARP announcements; the attacker is auto-paused |
| Claim another device's IP | The real owner is pinned in the gateway's neighbour table; auto-pause |
| Run a DHCP server or IPv6 router | Flagged; auto-pause |
| Port-scan the Pi / try SSH or the dashboard | Silently dropped and flagged; scans auto-pause |
| Guess the dashboard password | Flagged after 3 tries, locked out for 5 minutes after 5 |
| Set a manual DNS server | Quietly redirected and filtered anyway, and flagged |
| Set a static IP | Flagged (still filtered by MAC) |
| Share the connection to hide devices (hotspot, VM, travel router) | Spotted from the extra router hop in packet TTLs and flagged; everything behind it gets this device's rules |
| Unplug or power off the Pi | Forwarding is off until the firewall loads; kids' web access fails closed while the service is down; the gap is reported on next start |

Auto-pause only ever applies to filtered devices, defaults to 30 minutes, and
can be turned off with `tamper.auto_pause_minutes: 0`.

## Confidence scores

Every alert shows **"N% deliberate"**. Hover over it to see the reasoning and
when it might be innocent. The score combines:

1. **A base rate for that kind of event.** A ClientHello split into 1-byte
   pieces scores 95%. A direct-IP connection (often just an app's cached
   address) scores 50%.
2. **Your reviews.** **Confirmed** and **Not a bypass** recalibrate the base for
   that alert type in your household. "Not a bypass" also undoes the block where
   that's safe: the destination is exempted, or "It's me" restores trust. Site
   blocks are never lifted from an alert; use Rules for that.
3. **The device's behaviour.** Several different techniques from one device in
   a day raises every score. Repeats add a little. A destination you previously
   marked fine lowers it.

### Honest limits

- **Mobile data / a friend's hotspot** skips your network entirely. Pair this
  with the phone's own controls (Screen Time, Google Family Link).
- **Domain, not page.** You'll see `youtube.com` (labelled "YouTube" in the
  dashboard), not which video.
- **A child who learns an adult device's MAC address** could impersonate it.
  Give adults their own Wi-Fi network (SSID/VLAN) and set
  `gateway.trusted_interfaces` so adult status only counts on that network.
- **Traffic between two devices on your Wi-Fi never passes the Pi**, so a
  kid proxying through a sibling's or parent's computer, or poisoning
  another device's ARP cache one-way, is invisible to it. Turn on **client
  isolation** (often called "AP isolation") on the access point.
- **Physical access wins.** If a kid can plug into the ISP router directly, or
  the ISP router's Wi-Fi is still on, the Pi is bypassed. Lock that down.
- The behaviour detector is a heuristic. Every alert explains its score, and
  "This is fine" exempts a destination.

---

## Run it on your PC (monitor mode)

Monitor mode gives you DNS filtering, the full dashboard, and traffic
accounting for the PC itself. Use it to develop and debug.

```bash
cd parental-gateway
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
python run.py --update-lists      # first time: download the blocklists (~330k domains)
python run.py
```

Open **http://127.0.0.1:8080** and choose a password; first-time setup is only
allowed from the machine itself. For traffic accounting on Windows, install
[Npcap](https://npcap.com) and run the terminal as administrator.

Test DNS filtering without touching your system settings:

```
nslookup -port=5353 pornhub.com 127.0.0.1
nslookup -port=5353 protonvpn.com 127.0.0.1
```

Your PC appears as a device in the **quarantine** group (filtered). Move it to
**adults** in the Devices page to see the difference.

### Test the inspector on Windows with a packet capture

Inline blocking needs the Pi, but you can see exactly what the Pi *would* do:

1. Start a Wireshark capture.
2. Connect with a VPN (or try any other bypass).
3. Save the capture, then run:

```bash
python tools/replay.py my-capture.pcapng            # evaluated as the "kids" group
python tools/replay.py my-capture.pcapng --group consoles
```

It runs the same inspector the Pi uses and lists every blocked connection and why.

---

## Deploy on the Raspberry Pi (gateway mode)

**Hardware:** a Raspberry Pi 4 or 5 (2 GB+), a USB 3 gigabit Ethernet adapter
for the second port, and a Wi-Fi access point (or your current router set to
*access point / bridge mode*).

```
ISP router ──eth0── Raspberry Pi ──eth1 (USB adapter)── Wi-Fi access point ── everyone
```

On the Pi (Raspberry Pi OS Bookworm, 64-bit):

```bash
git clone <this repo> && cd parental-gateway
sudo ./deploy/setup-pi.sh
# different interface names?   sudo WAN_IF=eth0 LAN_IF=eth1 ./deploy/setup-pi.sh
```

The script:
- installs everything;
- gives the LAN port `192.168.50.1` and runs DHCP on it;
- creates a `parental-gateway` systemd service;
- asks you for the dashboard password.

The dashboard is at **http://192.168.50.1:8080**.

Then:

1. Set the access point to AP/bridge mode (no DHCP or NAT of its own).
2. **Turn off the ISP router's Wi-Fi and change its admin password.**
3. In **Devices**, move your own devices into **adults**. Put consoles in
   **consoles** (they need UDP for online games). Everything else stays filtered.
4. Optionally add internet-off times under **Rules & schedules**.

Forwarding is off at boot and only switches on once the firewall is loaded,
so there's never an unfiltered window. Machine-specific settings live in
`config.local.yaml`, which the setup script writes and git ignores.

---

## The dashboard

- **Overview:** devices online, lookups, blocks, bypass attempts and data
  today; time per service; latest bypass attempts.
- **Health:**
  - a protection score and checks: firewall running, tamper watch running,
    blocklists fresh, adults assigned, recent tampering, outages;
  - bypass attempts by category over the last 24 hours (chart or table);
  - a card per device with attempts today and this week, techniques used,
    sites blocked, a 7-day trend, its most certain alert, and a status of
    **Clean / Curious / Persistent / Tampering**;
  - your review history.
- **Devices:** set groups, rename devices, see online time / data / blocks,
  pause a device.
- **Device page:** time and data per service (today and last 7 days), live
  connections, lookups, bypass attempts.
- **Activity:** every connection (device, site, destination, duration, ↓/↑
  data, blocked or not) and every lookup.
- **Alerts:** every bypass attempt in plain English, with its confidence and
  *Confirmed* / *Not a bypass* / *Dismiss*.
- **Rules & schedules:** block/allow sites for everyone or a group,
  internet-off times, automatically blocked destinations.
- **System:** component health, blocklist status, inspector counters, password.

"Online time" counts minutes in which a device actually moved data with a
service, so idle background connections don't inflate it.

---

## Groups (config.yaml)

| Group | Filtered | UDP | DNS consistency | Use for |
|---|---|---|---|---|
| `adults` | no | yes | off | parents' devices |
| `kids` | yes | **no** | enforce | phones, tablets, laptops |
| `consoles` | yes | yes (VPN signatures still blocked) | log | game consoles |
| `quarantine` | yes | no | enforce | every new/unknown device (default) |

Categories, lists, detector thresholds and schedules are all in
`config.yaml`, and each setting has a comment.

---

## Tests

```bash
pytest -q                               # 62 unit tests (parsers, inspector, torrents, LAN watch, confidence...)
sudo python3 tests/e2e/run_e2e.py       # Linux only: full end-to-end test of gateway mode
```

The end-to-end test builds a miniature home network out of Linux network
namespaces: two kids' devices, a parent's laptop, a console, the real gateway
(nftables + inspector) and a fake internet with VPN servers, a DoH resolver,
disguised tunnels and an ISP router. It then attempts every bypass above,
plus torrents and real attacks on the gateway (ARP spoofing, rogue DHCP, a
cloned parent MAC, port scans, password guessing, a hidden NAT, a simulated
power cut). **105 checks pass.** It also kills the service and confirms kids'
access fails closed while the parent is unaffected. (The IPv6 router check is
skipped on kernels booted without IPv6.)

## Layout

```
run.py                 entry point (--set-password, --update-lists)
config.yaml            all settings, commented
guardian/
  resolver.py          filtering DNS server + DNS-tunnel detector
  policy.py            groups, rules, categories
  inspector.py         verdict engine (protocol conformance, SNI, DNS consistency, signatures)
  protocols.py         TLS ClientHello / HTTP / VPN signature parsers, JA3/JA4
  dnscache.py          which IPs each device was told about
  flows/               traffic accounting: conntrack (Pi) / packet capture (PC)
  detector.py          behavioural VPN/tunnel detection
  lanwatch.py          passive LAN defences (ARP/DHCP/RA spoofing, MAC cloning, torrent discovery)
  confidence.py        "how deliberate was this?" scoring + review calibration
  gateway/             nftables ruleset, NFQUEUE runner
  lists.py             blocklist + VPN-server list downloads
  webapp.py, static/   dashboard
deploy/                setup-pi.sh, systemd unit
tools/replay.py        run the inspector over a Wireshark capture
tests/                 unit tests + e2e/
```

> This project currently lives inside the Mini-motorways repository folder so
> it's easy to reach from this session. It isn't part of that game; move it to
> its own repository before putting it on the Pi.
