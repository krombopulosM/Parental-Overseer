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
- shows **live what each device is doing**, e.g. *"Likely playing an online
  game with YouTube in the background"*, with a live graph and a daily timeline
- **holds suspicious downloads** for you to approve or deny
- goes **beyond blocklists for adult content**: locked SafeSearch, a family-DNS
  second opinion, site-name heuristics, decoding translator/cache proxies, and
  holding video from unknown sites for review
- has a **Guide** inside the dashboard explaining every feature, how it works,
  and the technology involved (DNS, HTTPS, VPNs, proxies, Tor…)
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

### Every protection is a switch

All of the above are on by default, and every one can be switched off, house-wide
or for a single group (`protections:` in `config.yaml`, or the dashboard's Rules
page and setup wizard):

```yaml
protections:            # house-wide, for every filtered group
  vpn: true             # VPN sites, servers, protocols, learned fingerprints
  tor: true             # Tor website, relays, Tor's handshake
  proxies: true         # proxy sites, Private Relay, CONNECT / SOCKS
  encrypted_dns: true   # DoH / DoT resolvers, Firefox canary
  disguised_tunnels: true
  hidden_names: true    # no-SNI, ECH, QUIC, HTTPS records
  direct_ip: enforce    # enforce | log | off
  dns_tunnels: true
  non_web: block        # block (web only) | games (+UDP) | allow (everything, still checked)
  torrents: true        # protocols; torrent *sites* are a category
  behaviour: true
  network_attacks: true # alerts for probes/scans/hidden routers
groups:
  teens:
    protections: {tor: false, non_web: games}   # overrides; null = use the house-wide value
```

Each switch covers its route at every level (site, servers, protocol,
fingerprint), so switching one off opens exactly that route. The older
per-group keys `allow_udp`, `require_sni` and `dns_consistency` are still read
and converted.

## Adult content protection

A blocklist only knows sites someone has already listed. For children's
devices the gateway adds:

| Layer | What it does |
|---|---|
| **SafeSearch, locked** | Google, Bing, DuckDuckGo and Yandex lookups are answered with their locked "safe" addresses; YouTube with Restricted Mode (strict or moderate). These are the search engines' own mechanisms for schools and families. A connection to an *unlocked* address is refused, because the gateway never handed it out. |
| **Unlockable search engines blocked** | Brave Search, Startpage, Yahoo, Qwant… (editable list) |
| **Family DNS second opinion** | Children's lookups go through Cloudflare for Families (`1.1.1.3`). Anything it flags (adult or malware) is blocked even if no list has it yet. If it can't be reached, lookups fall back to the normal resolver. |
| **Site-name heuristics** | Strong adult terms anywhere in a name are blocked in lookups *and* inside connections. Weaker terms are blocked in strict mode as whole words only (Essex, Middlesex and analytics are safe). |
| **Translator / cache proxies decoded** | `www-example-com.translate.goog` and AMP-cache names carry the real site, so it's decoded and checked against the lists, the heuristics and the family DNS. Ordinary translations keep working. |
| **Web archives and page caches blocked** | archive.ph, the Wayback Machine, 12ft.io… (editable list) |
| **Video from unknown sites held** | Streaming video from a site that isn't a known video service is cut and held on the Reviews page (strict mode). This catches unlisted adult and pirate streaming sites. Approve once and that site is fine for that device. |

`adult.mode` is `strict` (all of the above) or `standard` (no weak-term
blocking; unknown video is only reported). A group can override it with
`adult_protection:`. The honest limits: adult material *inside* allowed
platforms (Reddit, X, Discord, Telegram) is behind encryption, so block the
platform if needed. Mobile data needs device-level controls.

## Targeting VPN and Tor technology, not server lists

Server lists can't keep up: new VPN services, new servers every day, rented
servers, Tor Browser copied in on a USB stick. The main defences don't depend
on knowing the server:

- **Web ports only** for children: VPN protocols and Tor's relay port can't leave the device, whatever the server.
- **Genuine-protocol check** on web ports: disguised tunnels (Shadowsocks, obfs4, fake-TLS "stealth" modes) fail.
- **Only addresses the gateway's DNS handed out:** VPN apps and Tor connect to built-in addresses without DNS, so new or unlisted servers are refused on the first packet.
- **Tor's handshake shape:** made-up `www.<random>.com` names that were never looked up.
- **Learned fingerprints:** once any tunnel is caught (behaviour, hidden site name, disguise, or your "Confirmed"), its software's TLS (JA4) fingerprint is blocked on *every* server. Fingerprints browsers use for normal sites are never learned. They're listed on Rules & schedules, with a Forget button.
- **Unknown destinations:** heavy traffic (15 MB, or 10 min with 3 MB) to a site that isn't popular (Tranco / Umbrella top lists), a known service, used by an adult in the house, or approved is cut and held for review. Hosting platforms (Workers, EC2, Heroku…) never count as known. This is what catches tunnels with real domains and real encryption (CDN-routed VLESS/V2Ray, Tor WebTunnel bridges, self-hosted VPNs).
- **Faster behaviour detection** on unknown destinations: about 1 minute instead of 5.
- **Escalation:** 3+ different techniques from one device in 10 minutes names the tool ("Tor Browser", "a VPN or proxy app") and pauses the device for 15 minutes.

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

## Live activity analysis

In gateway mode every packet already passes through the Pi. The inspector
reads each connection's handshake, and the kernel counts every packet and byte.
Sending every packet through the app as well would add lag to games and calls
without revealing anything new, because the content is encrypted. What *does*
reveal what someone is doing is the **shape** of their traffic:

| Activity | How it looks |
|---|---|
| Gaming | small packets, a steady 10–60 a second **both ways**, low bandwidth, no pauses |
| Video | big downstream bursts with pauses in between, or a known video service |
| Call | steady, roughly symmetrical, medium bandwidth |
| Downloading | one-way, sustained, high bandwidth, no pauses |
| Music / social / browsing | known services, or short small connections to many sites |

Every 2 seconds each connection is classified from its shape (and its service
name when known). The connections are then combined into one sentence per
device: the interactive activity in the foreground, video or music playing
alongside it in the background. For example:

- *"Likely playing Roblox with YouTube in the background"*
- *"Likely watching Netflix (also on Instagram)"*
- *"Likely downloading a file from mega.nz"*

Each sentence comes with a confidence and the reasoning.

- **Live** shows every device at a glance. Each device's page has a graph of
  the last 5 minutes by activity (hover for details) and its connections right
  now.
- **Device pages** show a timeline of today's activity.

## Download guard

Downloads are noticed two ways:
- **HTTPS (almost everything):** a connection turns into a sustained one-way
  transfer. The file is encrypted, so it's judged by **where it comes from and
  who's downloading it**, never its contents.
- **Plain HTTP:** the file name is readable, so a risky file (`.exe`, `.apk`,
  `.zip`, `.dmg`…) is stopped **before the first byte** arrives.

Each download gets a suspicion score, with every point explained:

| Signal | Points |
|---|---|
| A file-sharing, APK or cracked-software site (built-in list + Hagezi anti-piracy) | +55 |
| A torrent site | +60 |
| A risky file type (plain HTTP only) | +40 |
| No site name, just an IP address | +30 |
| Site first seen on your network today | +20 |
| Unencrypted download | +15 |
| Device tried to get around the filter in the last 24 h | +10 |
| Site the gateway doesn't recognise | +10 |
| Known app store / game platform / OS update source | −60 |

At or above 50 (`downloads.suspicious_score`), the connection is cut and that
site is **held for that device** until you decide on the **Downloads** page:

- **Approve:** the site is unblocked for that device and the download can be
  retried. Browsers can usually resume.
- **Deny:** the site stays blocked for that device.

Holds and approvals survive restarts.

The policy can be set globally or per group: `review_suspicious` (default),
`review_all` (every download from an untrusted site), `block_suspicious` (no
review, just stop it) or `off`.

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
allowed from the machine itself. (Devices that use the PC for DNS can also reach
it as `http://family.home.arpa:8080`.) The [setup wizard](#first-time-setup-wizard)
then opens. For traffic accounting on Windows, install
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
# unattended:   sudo WAN_IF=eth0 LAN_IF=eth1 ./deploy/setup-pi.sh
```

The script:
- lists the network interfaces and asks which faces the internet and which
  faces your home, suggesting the likely answers (the one carrying the default
  route is the internet side);
- installs everything;
- gives the LAN port `192.168.50.1` and runs DHCP on it;
- installs into `/opt/parental-gateway` in a versioned layout and creates a
  `parental-gateway` systemd service that runs the supervisor (for
  [updates with no downtime](#updates-no-downtime));
- announces the dashboard's name on the home network (Avahi / mDNS);
- asks you for the dashboard password.

Open the dashboard from any device at home: **http://family.local**

## Updates (no downtime)

The gateway checks for updates every hour; **System → Updates → Check for
updates** checks now. New versions install automatically (or on **Install now**
if you turn automatic installs off). Wi-Fi and filtering are never interrupted:

1. **Download** the new version into `releases/<version>-<commit>`; the running one isn't touched.
2. **Prepare**: reuse the Python environment if the requirements are unchanged,
   otherwise build a new one in the background (pip compiles `netfilterqueue`);
   pre-compile the code.
3. **Self-test** (`run.py --selftest`) against this machine's settings. A failure
   stops the update; nothing else happens.
4. **Hand over**, run by the supervisor (the process the service runs):
   - the new worker starts alongside the old one and shares the DNS and dashboard
     ports (`SO_REUSEPORT`, with a one-line BPF program that steers new traffic to
     the newest socket, so nothing queued on the old one is lost);
   - it binds the *other* packet queue and swaps the firewall to it in one atomic
     nftables transaction, with every device and address list already filled in;
   - the old worker answers what's already queued to it, then exits. The new one
     takes over the once-only jobs (traffic accounting, the behaviour detector,
     LAN watch, list downloads, update checks) through a lock, carries on byte
     counts from where the old one left off, and reloads the DNS answers it had
     handed out (now kept in the database).

If the new version never becomes ready, the old one takes the firewall back and
carries on. If it keeps crashing after taking over, the supervisor goes back to
the previous release by itself. **Go back to version …** does the same on demand.
The supervisor then re-launches itself from the new release, so it's updated too.
Settings that need a restart use the same hand-over.

The end-to-end test runs an update while a child's device and the parent's
laptop make lookups and connections non-stop: none fail. Blocked sites never
resolve and a VPN never gets out during the switch. It also checks that a broken
release is refused by its self-test, and that rollback works.

```yaml
updates:
  enabled: true          # check every hour
  auto_install: true     # false: show the update and wait for "Install now"
  source: https://github.com/you/parental-gateway.git   # an https:// git URL, or a local folder
  branch: main
  subdir: ""             # the program's folder inside the repository ("parental-gateway" while it lives here)
```

`setup-pi.sh` fills `source`, `branch` and `subdir` in from the git checkout it's
run from, so after moving to a dedicated repository, run it once from a clone of
that repository (or change the source in **System → Updates → Where updates come from**).

Installed layout (made by `tools/install.py`):

```
/opt/parental-gateway/
  current -> releases/2.1.0-ab12cd3     what the service runs
  releases/<version>-<commit>/         one folder per version (the newest few are kept)
  venvs/<hash>/                        Python environments, shared while requirements match
  data/                                guardian.db, config.local.yaml, list cache, update cache
```

Re-running `setup-pi.sh` on an installation that's already supervised is itself
a seamless update. An installation from before this layout is migrated once:
its database and settings move to `data/`, and the service is restarted that one
time. The firewall stays up meanwhile, so it fails closed.

## The dashboard address

Nobody needs to find the Pi's IP address. The dashboard answers to a name,
`family` by default (change it in the setup wizard):

| Address | How it's found | Works on |
|---|---|---|
| `family.local` | announced by the Pi with mDNS (Avahi), and answered by the gateway's DNS | iPhone/iPad, Mac, Windows, Linux, most Android |
| `family.home.arpa` | answered by the gateway's DNS - every device at home uses it | everything (the ending reserved for home networks, so browsers open it rather than search) |
| `family.home`, `family.lan`, `192.168.50.1` | aliases / the address | everything |

- Port 80 is redirected to the dashboard, so there's no `:8080` to remember;
  `https://` is refused immediately so browsers fall back to `http://` without waiting.
- **System → Dashboard address** shows the address with a QR code; on a phone,
  *Add to Home Screen* installs it with its own icon.
- The name is answered before any filtering, so a new or paused device can still
  find the dashboard - but only adults' devices can open it, and it needs the password.

Then:

1. Set the access point to AP/bridge mode (no DHCP or NAT of its own).
2. **Turn off the ISP router's Wi-Fi and change its admin password.**
3. Sign in to the dashboard and follow the setup wizard (below).

Forwarding is off at boot and only switches on once the firewall is loaded,
so there's never an unfiltered window. Machine-specific settings live in
`config.local.yaml`, which the setup script and the wizard write (merging,
never overwriting each other) and git ignores. Re-running the script is safe.

## First-time setup wizard

The first sign-in opens a step-by-step wizard (and **System → Run setup again**
reopens it):

| Step | What it sets |
|---|---|
| How it runs | The dashboard's name (`family` → http://family.local). Detects the platform, admin rights, interfaces, firewall, capture support and blocklists, and shows a pass/warn checklist. On a PC: DNS port (53 for real devices, 5353 for testing) and who can open the dashboard. On the Pi: the detected ports plus a house checklist. |
| Protection level | **Strict** (recommended), **Balanced** or **Light** presets. |
| Fine-tune | Adult-content mode, SafeSearch, YouTube Restricted Mode, family DNS, unknown video, downloads, unknown destinations, auto-pause after bypass attempts / network attacks. |
| What to block | Categories for the kids, consoles and new-device groups. |
| Ways around | Each anti-bypass protection on or off: VPNs, Tor, proxies, encrypted DNS, disguised tunnels, hidden site names, direct-to-address connections, DNS tunnels, non-web traffic (web only / games / everything), torrent protocols, behaviour detection, gateway-attack reports. |
| Devices | Names and groups for devices already seen; the device you're using is suggested as an adult's; what happens to new devices. |
| Bedtime | Internet-off window for the children's groups (never adults). |
| Privacy | History retention, recording adults' activity, fail-open vs fail-closed (Pi). |

Most settings apply live. DNS port, dashboard access and fail-open/closed need
a restart, which the service does itself (systemd restarts it on the Pi; on a
PC the process replaces itself) - the page reconnects and you stay signed in.
Network interfaces are deliberately not editable from the web: a wrong choice
would cut the dashboard off, so that stays in `setup-pi.sh`.

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
- **On a phone:** a bottom tab bar (Home, Live, Devices, Alerts, More), device
  cards with one-tap pause, alert actions under the text, 16px inputs (no zooming
  in on iPhone), and *Add to Home Screen* support with an app icon.
- **Devices:** set groups, rename devices, see online time / data / blocks,
  pause a device.
- **Device page:** time and data per service (today and last 7 days), live
  connections, lookups, bypass attempts.
- **Activity:** every connection (device, site, destination, duration, ↓/↑
  data, blocked or not) and every lookup.
- **Alerts:** every bypass attempt in plain English, with its confidence and
  *Confirmed* / *Not a bypass* / *Dismiss*.
- **Reviews:** downloads and videos held for your decision (Approve / Deny).
- **Guide:** the full manual, searchable, with a live summary of your own
  settings. It covers how each protection works and plain-English explainers
  of DNS, HTTPS, VPNs (and how they're used to get round filters), proxies,
  Tor, encrypted DNS, MAC/DHCP/ARP, torrents and what encryption hides.
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
pytest -q                               # 180 unit tests (parsers, inspector, torrents, LAN watch, activity, downloads, adult, setup wizard...)
sudo python3 tests/e2e/run_e2e.py       # Linux only: full end-to-end test of gateway mode
```

The end-to-end test builds a miniature home network out of Linux network
namespaces: two kids' devices, a parent's laptop, a console, the real gateway
(nftables + inspector) and a fake internet with VPN servers, a DoH resolver,
disguised tunnels and an ISP router. It then attempts every bypass above,
plus torrents and real attacks on the gateway (ARP spoofing, rogue DHCP, a
cloned parent MAC, port scans, password guessing, a hidden NAT, a simulated
power cut). It also checks the activity analysis: a console playing a game with
YouTube in the background must be described exactly that way. And it checks the
download guard end to end: a file-sharing download cut mid-transfer, retries
blocked until approved, then allowed; a plain-HTTP `.exe` stopped before it
starts, then denied. The adult-content layers are checked end to end, and so
is the in-app guide. So are VPN and Tor servers that are on no list: an unlisted VPN
caught by behaviour and then blocked by fingerprint on a second brand-new server,
unlisted Tor relays, and a CDN-style tunnel held as an unknown destination.
It also drives the setup wizard: interfaces detected, a category change taking
effect live for the kid, and a real self-restart that must come back as the
same process with the inspector running and no stale fail-open rule.
It switches protections per group on the live gateway (Tor off for the console only, "allow everything" still blocking VPN ports until VPNs are switched off). It also opens the dashboard by name over port 80 (and checks a child can find the name but not open it). It runs the gateway the way the Pi does (installed, under the supervisor) and updates it from a git repository while the network is in use, with zero failed lookups or connections. **218 checks pass.** Finally it kills the service and
confirms kids' access fails closed while the parent is unaffected. (The IPv6 router check is
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
  activity.py          traffic-shape classifier: gaming / video / call / download / ...
  downloads.py         download guard: detect, score, hold for review (downloads + unknown video)
  adult.py             SafeSearch, family DNS, name heuristics, proxy decoding
  reputation.py        known destinations (popularity, familiarity) + learned tunnel fingerprints
  static/docs.html     the in-app Guide
  gateway/             nftables ruleset, NFQUEUE runner
  lists.py             blocklist + VPN-server list downloads
  settings.py          what the setup wizard can change: presets, config.local.yaml, live apply
  supervisor.py        runs the gateway; switches versions with no gap, rolls back, restarts on crash
  updater.py           hourly update check, staging, environments, self-test, history
  handover.py          shared ports, socket steering, the once-only-jobs lock
  selftest.py          `run.py --selftest`: a new version must pass before it goes live
  environment.py       platform / interface / readiness detection for the wizard
  webapp.py, static/   dashboard (static/wizard.js: the setup wizard)
deploy/                setup-pi.sh, systemd unit
tools/replay.py        run the inspector over a Wireshark capture
tools/install.py       install / update into the releases layout (used by setup-pi.sh)
tests/                 unit tests + e2e/
```

> This project currently lives inside the Mini-motorways repository folder so
> it's easy to reach from this session. It isn't part of that game; move it to
> its own repository before putting it on the Pi.
