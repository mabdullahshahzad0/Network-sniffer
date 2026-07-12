# Basic Network Sniffer (Python)

A lightweight network packet sniffer built in Python that captures live network traffic and breaks it down into readable information — source/destination IPs, protocols, ports, and payload data.

Built as a hands-on project to understand how data actually flows through a network at the packet level.

---

## Features

- **Live packet capture** on any network interface
- **Protocol parsing** — TCP, UDP, and ICMP
- **Source & destination IP/port** extraction
- **Payload inspection** (hex + ASCII view)
- **Custom filters** using BPF syntax (e.g. capture only HTTPS traffic)
- Two implementations:
  - `network_sniffer.py` → built with **Scapy** (cross-platform, recommended)
  - `network_sniffer_socket.py` → built with raw **sockets** + `struct` (Linux only, no external dependencies — great for understanding header structures manually)

---
## Requirements
- Python 3.8+
- Windows: Npcap must be installed (Scapy needs it to capture raw packets). Install with the "WinPcap API-compatible mode" option checked.
- Linux/macOS: no extra driver needed, but you must run the script with root privileges (sudo) since raw packet capture requires elevated access.

## Tech Stack

- Python 3
- [Scapy](https://scapy.net/) — packet manipulation library
- `socket` & `struct` (standard library) — for the raw-socket version

---

## How It Works

1. Opens a live capture on a network interface
2. Listens for incoming/outgoing packets
3. For every packet:
   - Extracts the **IP layer** (source IP, destination IP, TTL, length)
   - Detects the **protocol** (TCP / UDP / ICMP) and reads protocol-specific fields (ports, TCP flags)
   - Extracts and displays the **payload** in both hex and ASCII
4. Prints everything in a clean, timestamped format to the console

---

## Getting Started

### Prerequisites
```bash
pip install scapy
```

### Run (Windows/macOS/Linux — Scapy version)
```bash
sudo python3 network_sniffer.py
```
> On Windows, run Command Prompt/PowerShell as **Administrator** and install **Npcap** first (required by Scapy for packet capture).

### Optional arguments
```bash
# Capture only 20 packets
python network_sniffer.py -c 20

# Capture only HTTPS traffic
python network_sniffer.py -f "tcp port 443"

# Choose a specific interface
python network_sniffer.py -i "Ethernet"
```

---

## 📸 Sample Output

```
[12:10:51] TCP   192.168.100.24  -> 35.186.224.33   len=83 ttl=128 sport=33913 dport=443 flags=PA
    payload: hex[1703030026...]  ascii[....&).x#......a.3..V-.L...*..}...]
```
## Legal & ethical note

Only capture traffic on networks you own or have explicit permission to monitor. Sniffing traffic on networks without authorization is illegal in most jurisdictions. This tool is intended for learning on your own lab setup, home network, or with written authorization.

