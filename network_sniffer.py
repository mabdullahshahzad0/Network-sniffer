#!/usr/bin/env python3
"""
TASK 1: Basic Network Sniffer
------------------------------
A simple educational packet sniffer built with Scapy.

What it does:
  - Captures live network traffic on a chosen interface.
  - Parses each packet to pull out source/destination IPs, protocol,
    ports (for TCP/UDP), and a snippet of the raw payload.
  - Prints the info in a readable, structured way so you can see how
    data actually flows through the network at the packet level.

Requirements:
  pip install scapy

IMPORTANT:
  - Capturing raw packets requires elevated privileges.
    Run with: sudo python3 network_sniffer.py
  - Only capture traffic on networks/interfaces you own or have
    explicit permission to monitor. Sniffing traffic you don't have
    authorization for may be illegal in your jurisdiction.
"""

import argparse
import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf


def format_payload(raw_bytes, max_len=64):
    """Return a printable snippet of the payload (hex + ascii)."""
    if not raw_bytes:
        return None
    snippet = raw_bytes[:max_len]
    hex_part = snippet.hex()
    ascii_part = "".join(
        chr(b) if 32 <= b <= 126 else "." for b in snippet
    )
    suffix = "..." if len(raw_bytes) > max_len else ""
    return f"hex[{hex_part}{suffix}]  ascii[{ascii_part}{suffix}]"


def protocol_name(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def handle_packet(pkt):
    """Callback executed for every captured packet."""
    if not pkt.haslayer(IP):
        return  # skip non-IP traffic (e.g. ARP) for this basic sniffer

    ip_layer = pkt[IP]
    proto = protocol_name(pkt)
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    src = ip_layer.src
    dst = ip_layer.dst
    ttl = ip_layer.ttl
    length = ip_layer.len

    line = f"[{timestamp}] {proto:5s} {src:15s} -> {dst:15s}  len={length} ttl={ttl}"

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = tcp.sprintf("%TCP.flags%")
        line += f"  sport={tcp.sport} dport={tcp.dport} flags={flags}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        line += f"  sport={udp.sport} dport={udp.dport}"
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        line += f"  type={icmp.type} code={icmp.code}"

    print(line)

    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        formatted = format_payload(payload)
        if formatted:
            print(f"    payload: {formatted}")


def main():
    parser = argparse.ArgumentParser(description="Basic Python network sniffer (educational use only).")
    parser.add_argument(
        "-i", "--iface",
        default=None,
        help="Network interface to sniff on (default: scapy's default interface).",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = capture forever until Ctrl+C).",
    )
    parser.add_argument(
        "-f", "--filter",
        default="ip",
        help='BPF filter string, e.g. "tcp port 80" or "udp". Default: "ip".',
    )
    args = parser.parse_args()

    iface = args.iface or conf.iface
    print(f"Starting capture on interface: {iface}")
    print(f"Filter: {args.filter}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=handle_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print("\nPermission denied. Try running this script with sudo/administrator rights.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")


if __name__ == "__main__":
    main()
