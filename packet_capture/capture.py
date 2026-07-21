"""
=============================================================
packet_capture/capture.py
=============================================================
Captures live network packets using Scapy,
extracts basic features, and saves them to a CSV file.

Features extracted per packet:
  - timestamp     : time of capture
  - packet_size   : total size in bytes
  - protocol      : TCP / UDP / ICMP / Other
  - src_ip        : source IP address
  - dst_ip        : destination IP address
  - src_port      : source port (TCP/UDP only)
  - dst_port      : destination port (TCP/UDP only)

Output: packet_capture/captured_packets.csv
=============================================================
"""

import csv
import os
import time
from datetime import datetime

# Scapy import - suppress IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, IP, TCP, UDP, ICMP

# --------------------------------------------------------
# Configuration
# --------------------------------------------------------
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "captured_packets.csv")
PACKET_COUNT = 0      # Number of packets to capture (0 = unlimited)
INTERFACE = None        # Set to e.g. "eth0" or None for auto-detect

# CSV headers
FIELDS = ["timestamp", "packet_size", "protocol", "src_ip", "dst_ip", "src_port", "dst_port"]

# --------------------------------------------------------
# Packet processing callback
# --------------------------------------------------------
def process_packet(packet):
    """Extract features from each captured packet and write to CSV."""

    # Only process IP packets
    if not packet.haslayer(IP):
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    packet_size = len(packet)
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = "-"
    dst_port = "-"

    # Determine protocol
    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = "Other"

    row = {
        "timestamp": timestamp,
        "packet_size": packet_size,
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
    }

    # Append to CSV
    file_exists = os.path.isfile(OUTPUT_FILE)
    with open(OUTPUT_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        if not file_exists:
            writer.writeheader()  # Write header only once
        writer.writerow(row)

    print(f"[CAPTURED] {timestamp} | {protocol:5s} | {packet_size:5d} bytes | {src_ip} -> {dst_ip}")


# --------------------------------------------------------
# Main capture function
# --------------------------------------------------------
def start_capture(count=PACKET_COUNT, iface=INTERFACE):
    """Start live packet capture."""
    print("=" * 60)
    print("  IDS Packet Capture Module")
    print("=" * 60)
    print(f"  Output file : {OUTPUT_FILE}")
    print(f"  Packets     : {'Unlimited' if count == 0 else count}")
    print(f"  Interface   : {'Auto' if iface is None else iface}")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)

    try:
        while True:
            sniff(
                prn=process_packet,   # Callback for each packet
                count=count,          # 0 = capture forever
                iface=iface,          # Network interface
                store=False           # Don't store in memory (saves RAM)
            )
            # If a predetermined count > 0 is selected, stop the loop.
            if count > 0:
                break
    except KeyboardInterrupt:
        print("\n[INFO] Capture stopped by user.")
    except PermissionError:
        print("[ERROR] Permission denied. Run with: sudo python3 capture.py")


if __name__ == "__main__":
    start_capture()
