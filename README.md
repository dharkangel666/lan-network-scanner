# Network Scanner

A local network scanner with a web dashboard. Discover active hosts on your LAN, resolve MAC addresses and vendors, and scan open TCP ports.

## Features

- **ARP discovery** — active ARP scan when raw socket access is available
- **Fallback discovery** — ping sweep plus Linux neighbor table when ARP is unavailable
- **MAC + vendor lookup** — resolves hardware addresses and IEEE OUI vendor names
- **mDNS hostnames** — resolves `.local` names via Avahi when reverse DNS is unavailable
- **OS detection** — combines TTL, open ports, service banners, and vendor hints
- **Connection type** — Wi-Fi vs Ethernet from your local interface, Starlink router data when available, or vendor-based guesses
- **Port scanning** — TCP connect scan with common ports or custom ranges
- **Web dashboard** — browser UI with real-time streaming updates
- **Auto network detection** — reads your default route and interface from `ip route`

## Requirements

- Python 3.11+
- Linux with `ip`, `ping`, and `avahi-daemon` available
- Permission to send ICMP pings (usually works for normal users on Linux)
- Raw socket access for active ARP scans (`sudo` or `cap_net_raw`)

## Setup

```bash
cd ~/Projects/lan-network-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python run.py
```

No `sudo` is required for normal use. Discovery will use ping plus the kernel ARP neighbor table when active ARP scanning is unavailable.

### One-time setup for active ARP (optional)

Active ARP scans need raw socket access. You only need `sudo` once to grant that to the project virtualenv:

```bash
chmod +x scripts/setup-capabilities.sh
sudo ./scripts/setup-capabilities.sh
python run.py
```

The setup script recreates the virtualenv with copied Python binaries if needed, so capabilities are not applied to your system-wide Python.

To undo that change:

```bash
sudo ./scripts/remove-capabilities.sh
```

To force fallback discovery even when ARP is available:

```bash
NETWORK_SCANNER_FORCE_FALLBACK=1 python run.py
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

## Usage

1. Click **Scan Network** to discover active devices on your LAN.
2. Review MAC addresses, vendor names, and connection type for each host.
3. Click **Scan Ports** on any discovered host, or enter a target IP manually.
4. Choose a port preset from the dropdown, or pick **Custom** and enter values like `22,80,443` or `9000-9010`.

## API

- `GET /api/network` — local network info
- `GET /api/scan/discovery` — SSE stream of discovered hosts
- `GET /api/scan/ports?host=IP&ports=common` — SSE stream of open ports

Host objects include:

- `ip`
- `mac`
- `vendor`
- `hostname`
- `os`, `os_detail`
- `connection`, `connection_label`, `connection_source`, `connection_detail`
- `method` (`arp`, `ping`, `ping+arp`, `neighbor`, or `local`)

## Starlink router support

If your LAN uses a Starlink router, run **Network Scanner — Starlink Setup** on your desktop (or the script below). It downloads `grpcurl` automatically if `apt` does not have it, caches the Starlink protocol schema from your dish, then queries the router API for Wi-Fi vs Ethernet per device.

```bash
bash ~/Projects/lan-network-scanner/scripts/install-starlink-support.sh
```

Manual grpcurl only (if needed):

```bash
bash ~/Projects/lan-network-scanner/scripts/install-grpcurl.sh
```

Without Starlink API access, remote devices show a best-guess label based on MAC vendor. Your own PC is detected accurately from its active network interface.

## Notes

- Only scan networks you own or have permission to test.
- Vendor lookup downloads the IEEE OUI database on first scan and caches it in `~/.cache/lan-network-scanner/oui.csv`.
- Hostnames are resolved via reverse DNS first, then mDNS through Avahi. Devices without either will show a blank hostname.
- OS detection is heuristic (TTL, ports, banners, vendor). It is a best guess, not a full fingerprint like nmap -O.
- Connection type for other devices is a best guess unless Starlink router data is available. Hover the Connection column for details.
- Without raw socket access, discovery falls back to ping plus the kernel ARP neighbor table.
- Port scanning uses TCP connect and reports ports that accept connections.
