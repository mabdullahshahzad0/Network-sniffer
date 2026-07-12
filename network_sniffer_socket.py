#!/usr/bin/env python3
"""
TASK 1 (Alternative Version): Basic Network Sniffer using raw sockets
----------------------------------------------------------------------
This version uses only Python's built-in `socket` module instead of
scapy, so it has zero external dependencies. It works on Linux
(uses AF_PACKET raw sockets). It manually unpacks Ethernet, IP, TCP,
UDP, and ICMP headers using the `struct` module -- a good way to
learn exactly how these protocols are laid out on the wire.

Run with:
  sudo python3 network_sniffer_socket.py

Only capture traffic on networks you own or are authorized to monitor.
"""

import socket
import struct
import textwrap
import datetime


def format_payload(data, max_len=64):
    if not data:
        return None
    snippet = data[:max_len]
    hex_part = snippet.hex()
    ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in snippet)
    suffix = "..." if len(data) > max_len else ""
    return f"hex[{hex_part}{suffix}]  ascii[{ascii_part}{suffix}]"


def unpack_ethernet(raw_data):
    dest, src, proto = struct.unpack("! 6s 6s H", raw_data[:14])
    return proto, raw_data[14:]


def unpack_ipv4(raw_data):
    version_header_len = raw_data[0]
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, dst = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(dst)
    return proto, ttl, src_ip, dst_ip, header_len, raw_data[header_len:]


def unpack_tcp(raw_data):
    src_port, dst_port, seq, ack, offset_flags = struct.unpack("! H H L L H", raw_data[:14])
    offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x3F
    return src_port, dst_port, flags, raw_data[offset:]


def unpack_udp(raw_data):
    src_port, dst_port, length = struct.unpack("! H H 2x", raw_data[:8])
    return src_port, dst_port, raw_data[8:]


def unpack_icmp(raw_data):
    icmp_type, code = struct.unpack("! B B 2x", raw_data[:4])
    return icmp_type, code, raw_data[4:]


def main():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except (PermissionError, AttributeError):
        print("This raw-socket sniffer requires Linux and root privileges.")
        print("Run with: sudo python3 network_sniffer_socket.py")
        return
    except OSError as e:
        print(f"Could not open raw socket: {e}")
        print("Run with: sudo python3 network_sniffer_socket.py")
        return

    print("Sniffing started. Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, _ = conn.recvfrom(65536)
            eth_proto, eth_payload = unpack_ethernet(raw_data)

            if eth_proto != 0x0800:  # only handle IPv4
                continue

            proto, ttl, src_ip, dst_ip, header_len, ip_payload = unpack_ipv4(eth_payload)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")

            if proto == 6:  # TCP
                src_port, dst_port, flags, payload = unpack_tcp(ip_payload)
                print(f"[{timestamp}] TCP   {src_ip:15s} -> {dst_ip:15s} "
                      f"sport={src_port} dport={dst_port} ttl={ttl} flags={flags:#04x}")
            elif proto == 17:  # UDP
                src_port, dst_port, payload = unpack_udp(ip_payload)
                print(f"[{timestamp}] UDP   {src_ip:15s} -> {dst_ip:15s} "
                      f"sport={src_port} dport={dst_port} ttl={ttl}")
            elif proto == 1:  # ICMP
                icmp_type, code, payload = unpack_icmp(ip_payload)
                print(f"[{timestamp}] ICMP  {src_ip:15s} -> {dst_ip:15s} "
                      f"type={icmp_type} code={code} ttl={ttl}")
            else:
                payload = ip_payload
                print(f"[{timestamp}] OTHER {src_ip:15s} -> {dst_ip:15s} proto={proto} ttl={ttl}")

            formatted = format_payload(payload)
            if formatted:
                print(f"    payload: {formatted}")

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
