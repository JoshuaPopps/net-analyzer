# netanalyze

A small, dependency-free home LAN analyzer. Discovers live hosts on your
subnet, identifies them (hostname, MAC, vendor), and checks a curated list
of common service ports — so you can see everything on your network at
a glance.

No dependencies. Python 3.8+. Works on Linux, macOS, and Windows.

## Install

None. It's one file:

```
git clone https://github.com/JoshuaPopps/net-analyzer.git
cd net-analyzer
```

## Usage

```bash
# Scan your local /24 (auto-detected)
python3 netanalyze.py

# Scan a specific subnet, save a markdown report
python3 netanalyze.py --subnet 192.168.1.0/24 --md lan-report.md

# Deep-scan a single host
python3 netanalyze.py --host 192.168.1.10

# Custom port list
python3 netanalyze.py --host 192.168.1.10 --ports 22,80,443,32400
```

## What it checks

- **Discovery:** ping sweep of the subnet, plus the OS ARP/neighbor table
  (catches quiet hosts that ignore ping).
- **Identification:** reverse DNS hostname, MAC address, and vendor from
  the MAC OUI (covers the usual home-lab suspects: Apple, Amazon, Google,
  TP-Link, Raspberry Pi, Espressif, Sonos, Philips Hue, etc.).
- **Ports:** a curated list of ~40 common home-lab ports with friendly
  labels — SSH, SMB, Plex (32400), Ollama (11434/11435), Home Assistant
  (8123), Threadfin (34400), and more.

## Sample output (example data)

```
IP               Hostname   MAC                Vendor     Open ports
192.168.1.10     server     02:00:5e:10:00:0a  Example    22/SSH, 80/HTTP, 445/SMB
192.168.1.25     laptop     02:00:5e:10:00:19  Example    22/SSH, 135/MS-RPC
```

## Notes

- Only scan networks you own. This is built for your own LAN.
- Ping sweep of a /24 takes seconds; the port scan only touches hosts
  that answered.
- The OUI vendor list is a starter set — the full IEEE list is at
  https://standards-oui.ieee.org/oui/oui.txt if you want to extend it.
