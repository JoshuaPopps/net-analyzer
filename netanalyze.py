#!/usr/bin/env python3
"""
netanalyze -- a small, dependency-free home LAN analyzer.

Discovers live hosts on your subnet, identifies them (hostname, MAC, vendor),
and checks a curated list of common service ports.

    python3 netanalyze.py                       # scan your local /24
    python3 netanalyze.py --subnet 192.168.0.0/24
    python3 netanalyze.py --subnet 192.168.0.0/24 --md lan-report.md
    python3 netanalyze.py --host 192.168.0.65    # deep-scan a single host
    python3 netanalyze.py --host 192.168.0.65 --ports 22,80,443,32400

Stdlib only. Python 3.8+. Works on Linux, macOS, and Windows.
Be polite: only scan networks you own.
"""

import argparse
import concurrent.futures as cf
import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import sys

# Port -> friendly label for the report.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB", 548: "AFP", 587: "SMTP-sub",
    1883: "MQTT", 1900: "UPnP", 3000: "HTTP-alt", 3306: "MySQL",
    3389: "RDP", 5000: "HTTP-alt", 5001: "HTTP-alt",
    5353: "mDNS", 5432: "Postgres", 5900: "VNC", 5985: "WinRM",
    8000: "HTTP-alt", 8080: "HTTP-alt", 8081: "HTTP-alt",
    8082: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt",
    9000: "HTTP-alt", 9090: "HTTP-alt",
    9100: "Printer", 9200: "Elastic", 11211: "Memcached",
    11434: "Ollama", 11435: "Ollama", 27017: "MongoDB",
    32400: "Plex", 32469: "Plex-DLNA", 34400: "Threadfin",
    8123: "HomeAssist",
}

# A starter OUI map for the vendors you're most likely to meet on a home LAN.
# Full list: https://standards-oui.ieee.org/oui/oui.txt
OUI_VENDORS = {
    "00:0C:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
    "00:1B:21": "Intel", "00:1E:67": "Intel", "3C:22:FB": "Intel",
    "00:23:12": "Apple", "00:25:00": "Apple", "3C:06:30": "Apple",
    "68:AB:1E": "Apple", "8C:85:90": "Apple", "F0:18:98": "Apple",
    "04:4B:ED": "Amazon", "0C:47:C9": "Amazon", "34:D2:70": "Amazon",
    "40:B4:CD": "Amazon", "68:54:FD": "Amazon", "74:C2:46": "Amazon",
    "A0:02:DC": "Amazon", "FC:A1:83": "Amazon",
    "18:B4:30": "Google/Nest", "54:60:09": "Google", "F4:F5:D8": "Google",
    "00:0E:C6": "ASRock", "00:25:22": "ASRock",
    "50:C7:BF": "TP-Link", "60:E3:27": "TP-Link", "6C:5A:B0": "TP-Link",
    "98:DA:C4": "TP-Link", "A0:F3:C1": "TP-Link", "B0:4E:26": "TP-Link",
    "E8:48:B8": "TP-Link",
    "2C:30:33": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:0D:B9": "PC Engines", "00:0F:B5": "Netgear",
    "20:E5:2A": "Netgear", "28:80:88": "Netgear", "9C:C7:A6": "Netgear",
    "C0:FF:D4": "Netgear",
    "00:1A:2B": "Atheros", "00:03:7F": "Atheros",
    "00:13:10": "Linksys", "00:18:39": "Linksys", "58:EF:68": "Linksys",
    "00:24:36": "Ubiquiti", "04:18:D6": "Ubiquiti", "68:72:51": "Ubiquiti",
    "78:45:58": "Ubiquiti", "80:2A:A8": "Ubiquiti",
    "24:5E:BE": "Espressif", "30:AE:A4": "Espressif",
    "3C:71:BF": "Espressif", "7D:F9:5B": "Espressif",
    "08:3A:F2": "Espressif",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue",
    "18:B4:30": "Google/Nest",
    "2C:AA:8E": "Wyze", "7C:78:7E": "Wyze",
    "44:65:0D": "Amazon", "50:DC:E7": "Amazon",
    "5C:AA:FD": "Sonos", "78:28:CA": "Sonos", "94:9F:3E": "Sonos",
    "00:0B:82": "Grandstream", "00:1F:F3": "Apple",
    "30:65:EC": "Belkin/WeMo", "94:10:3E": "Belkin/WeMo",
    "D0:52:A8": "Xerox", "00:00:74": "Ricoh",
    "3C:D9:2B": "Hewlett Packard", "88:51:FB": "Hewlett Packard",
    "B4:B5:2F": "Hewlett Packard",
    "00:1B:77": "Samsung", "00:12:FB": "Samsung", "5C:49:7D": "Samsung",
    "78:1F:DB": "Samsung", "84:25:DB": "Samsung", "A8:06:00": "Samsung",
    "D0:DF:9A": "Samsung",
    "70:F1:A1": "Dell", "B8:CA:3A": "Dell", "F8:DB:88": "Dell",
    "00:14:22": "Dell",
    "00:25:64": "Giga-byte", "1C:1B:0D": "Giga-byte",
    "04:D9:F5": "Asus", "2C:56:DC": "Asus", "60:45:CB": "Asus",
    "9C:5C:8E": "Asus",
    "00:26:2D": "Hon Hai (Foxconn)",
}


def local_subnet():
    """Guess the local /24 by asking the OS where it would route outward."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no traffic actually sent
        ip = s.getsockname()[0]
    finally:
        s.close()
    net = ipaddress.ip_network(ip + "/24", strict=False)
    return str(net)


def ping_host(ip, timeout=1):
    """True if the host answers a single ping."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif system == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout + 2)
        return r.returncode == 0
    except Exception:
        return False


def arp_table():
    """Map IP -> MAC from the OS neighbor/ARP table."""
    table = {}
    if shutil.which("ip"):
        try:
            out = subprocess.run(["ip", "neigh", "show"], capture_output=True,
                                 text=True, timeout=10).stdout
            for line in out.splitlines():
                m = re.match(r"(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})",
                             line)
                if m:
                    table[m.group(1)] = m.group(2).upper()
        except Exception:
            pass
    if not table and shutil.which("arp"):
        try:
            out = subprocess.run(["arp", "-a"], capture_output=True,
                                 text=True, timeout=10).stdout
            for m in re.finditer(
                    r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F:]{17})",
                    out):
                table[m.group(1)] = m.group(2).upper()
        except Exception:
            pass
    return table


def vendor_of(mac):
    if not mac:
        return ""
    return OUI_VENDORS.get(mac[:8].upper(), "")


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def tcp_open(ip, port, timeout=0.7):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_ports(ip, ports, timeout=0.7, workers=64):
    open_ports = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        fut = {ex.submit(tcp_open, ip, p, timeout): p for p in ports}
        for f in cf.as_completed(fut):
            if f.result():
                open_ports.append(fut[f])
    return sorted(open_ports)


def discover(subnet, ping_timeout=1, workers=64):
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(h) for h in net.hosts()]
    live = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        fut = {ex.submit(ping_host, h, ping_timeout): h for h in hosts}
        for f in cf.as_completed(fut):
            if f.result():
                live.append(fut[f])
    # Fold in anything the ARP table already knows (catches quiet hosts).
    for ip in arp_table():
        try:
            if ipaddress.ip_address(ip) in net and ip not in live:
                live.append(ip)
        except ValueError:
            pass
    return sorted(live, key=lambda ip: tuple(int(x) for x in ip.split(".")))


def analyze_host(ip, macs, ports, port_timeout=0.7):
    mac = macs.get(ip, "")
    return {
        "ip": ip,
        "hostname": reverse_dns(ip),
        "mac": mac,
        "vendor": vendor_of(mac),
        "open": [(p, COMMON_PORTS.get(p, "")) for p in
                 scan_ports(ip, ports, port_timeout)],
    }


def print_table(rows):
    hdr = ("IP", "Hostname", "MAC", "Vendor", "Open ports")
    widths = [15, 24, 17, 16, 40]
    print("  ".join(h.ljust(w) for h, w in zip(hdr, widths)))
    print("-" * sum(widths + [2] * 4))
    for r in rows:
        ports = ", ".join(f"{p}{'/' + l if l else ''}" for p, l in r["open"])
        print("  ".join(x.ljust(w) for x, w in zip(
            [r["ip"], r["hostname"][:24], r["mac"], r["vendor"][:16],
             ports[:40]], widths)))


def write_markdown(path, subnet, rows):
    with open(path, "w") as f:
        f.write(f"# LAN report — {subnet}\n\n")
        f.write("| IP | Hostname | MAC | Vendor | Open ports |\n")
        f.write("|---|---|---|---|---|\n")
        for r in rows:
            ports = ", ".join(
                f"{p}{' (' + l + ')' if l else ''}" for p, l in r["open"])
            f.write(f"| {r['ip']} | {r['hostname']} | {r['mac']} | "
                    f"{r['vendor']} | {ports} |\n")
    print(f"\nReport written to {path}")


def main():
    ap = argparse.ArgumentParser(description="Home LAN analyzer (stdlib only)")
    ap.add_argument("--subnet", default=None,
                    help="e.g. 192.168.0.0/24 (default: your local /24)")
    ap.add_argument("--host", default=None,
                    help="deep-scan a single host instead of sweeping")
    ap.add_argument("--ports", default=None,
                    help="comma-separated ports (default: curated list)")
    ap.add_argument("--md", default=None, help="write markdown report to FILE")
    ap.add_argument("--ping-timeout", type=float, default=1)
    ap.add_argument("--port-timeout", type=float, default=0.7)
    args = ap.parse_args()

    ports = ([int(p) for p in args.ports.split(",") if p.strip().isdigit()]
             if args.ports else sorted(COMMON_PORTS))
    macs = arp_table()

    if args.host:
        rows = [analyze_host(args.host, macs, ports, args.port_timeout)]
        label = args.host
    else:
        subnet = args.subnet or local_subnet()
        label = subnet
        print(f"Sweeping {subnet} ...")
        live = discover(subnet, args.ping_timeout)
        print(f"{len(live)} live host(s). Scanning ports ...")
        rows = []
        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            fut = {ex.submit(analyze_host, ip, macs, ports,
                             args.port_timeout): ip for ip in live}
            for f in cf.as_completed(fut):
                rows.append(f.result())
        rows.sort(key=lambda r: tuple(int(x) for x in r["ip"].split(".")))

    print(f"\n=== {label} ===")
    print_table(rows)
    if args.md:
        write_markdown(args.md, label, rows)


if __name__ == "__main__":
    sys.exit(main())
