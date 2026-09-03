"""
=============================================================
network_monitor/dns_monitor.py  —  IDS_Snort_Project
=============================================================
DNS Tunneling Detector.

Detection Techniques:
  1. Shannon Entropy       — subdomains with entropy > 3.5 bits/char
     are likely Base64/Hex-encoded payloads (C2 exfiltration).
  2. Abnormal Label Length — DNS labels > 50 chars → suspicious.
  3. Query Flood           — > 30 unique DNS queries per minute
     from same IP → DNS tunnel data transfer rate.
  4. Payload Size Anomaly  — DNS UDP packets > 512 bytes
     (violates the original DNS spec).

Alerts sent to Correlator via UDP 9999 as:
  type=DNS_TUNNEL   severity=HIGH/MEDIUM

Usage:
  python network_monitor/dns_monitor.py
  (Must run as Administrator — raw socket access required)
=============================================================
"""

import os
import sys
import json
import math
import time
import socket
import threading
from datetime import datetime
from collections import defaultdict, deque

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# ── UDP sender ───────────────────────────────────────────
UDP_IP   = "127.0.0.1"
UDP_PORT = 9999
_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# ── Detection thresholds ─────────────────────────────────
ENTROPY_THRESHOLD   = 3.5    # bits/char — above = suspicious
MAX_LABEL_LEN       = 50     # chars — above = suspicious
QUERY_FLOOD_WINDOW  = 60.0   # seconds
QUERY_FLOOD_LIMIT   = 30     # queries per window per IP
DNS_PAYLOAD_LIMIT   = 512    # bytes — over = alert

# ── Per-IP query tracking ─────────────────────────────────
query_times_by_ip: dict[str, deque] = defaultdict(lambda: deque())
alert_cooldown: dict[str, float]    = {}   # ip+type -> last alert time
ALERT_COOLDOWN = 10.0


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LOCAL_IP = get_local_ip()


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _send_alert(alert: dict):
    try:
        _udp_sock.sendto(json.dumps(alert).encode(), (UDP_IP, UDP_PORT))
    except Exception as e:
        print(f"[DNS] UDP send error: {e}")


def _make_alert(src_ip: str, dst_ip: str, severity: str, confidence: float, message: str) -> dict:
    return {
        "id":          int(time.time() * 1000),
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type":        "DNS_TUNNEL",
        "severity":    severity,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "protocol":    "DNS",
        "packet_size": 0,
        "packet_rate": 0,
        "confidence":  confidence,
        "message":     message,
    }


def _can_alert(key: str, now: float) -> bool:
    last = alert_cooldown.get(key, 0)
    if now - last < ALERT_COOLDOWN:
        return False
    alert_cooldown[key] = now
    return True


def process_dns(packet):
    """Scapy callback for DNS packets."""
    try:
        from scapy.all import IP, UDP, DNS, DNSQR

        if not (packet.haslayer(IP) and packet.haslayer(DNS)):
            return

        src_ip  = packet[IP].src
        dst_ip  = packet[IP].dst
        dns_pkt = packet[DNS]
        now     = time.time()
        pkt_size = len(packet)

        # ── Track query rate per source IP ────────────────────
        q = query_times_by_ip[src_ip]
        q.append(now)
        while q and now - q[0] > QUERY_FLOOD_WINDOW:
            q.popleft()
        query_count = len(q)

        # ── 1. DNS Payload Size Anomaly ────────────────────────
        if pkt_size > DNS_PAYLOAD_LIMIT:
            key = f"{src_ip}:size"
            if _can_alert(key, now):
                msg = (f"[!] DNS Payload Size Anomaly from {src_ip}: "
                       f"{pkt_size}B (limit {DNS_PAYLOAD_LIMIT}B) — possible DNS tunnel/amplification")
                print(f"[DNS SIZE] {msg}")
                alert = _make_alert(src_ip, dst_ip, "HIGH", 85.0, msg)
                _send_alert(alert)

        # ── 2. Query Flood ─────────────────────────────────────
        if query_count >= QUERY_FLOOD_LIMIT:
            key = f"{src_ip}:flood"
            if _can_alert(key, now):
                rate = round(query_count / QUERY_FLOOD_WINDOW, 1)
                msg  = (f"[!] DNS Query Flood from {src_ip}: "
                        f"{query_count} queries in {QUERY_FLOOD_WINDOW}s ({rate}/s) "
                        f"— likely DNS tunneling")
                print(f"[DNS FLOOD] {msg}")
                alert = _make_alert(src_ip, dst_ip, "HIGH", 90.0, msg)
                _send_alert(alert)
                return  # Already flagged — no need to check entropy

        # ── 3. Entropy & Label Length (DNS query packets only) ──
        if dns_pkt.qr != 0:   # 0=query, 1=response — only check queries
            return

        qcount = dns_pkt.qdcount
        for i in range(qcount):
            try:
                qname_raw = dns_pkt.qd.qname if hasattr(dns_pkt, 'qd') else b""
                if not qname_raw:
                    break
                # Decode and strip trailing dot
                if isinstance(qname_raw, bytes):
                    qname = qname_raw.decode("utf-8", errors="ignore").rstrip(".")
                else:
                    qname = str(qname_raw).rstrip(".")

                labels = qname.split(".")
                # Check each label (subdomain segment)
                for label in labels[:-2]:  # skip TLD and SLD
                    if not label:
                        continue

                    label_len = len(label)
                    entropy   = shannon_entropy(label)

                    # Long label check
                    if label_len > MAX_LABEL_LEN:
                        key = f"{src_ip}:longlab"
                        if _can_alert(key, now):
                            msg = (f"[!] Suspicious DNS label from {src_ip}: "
                                   f"'{label[:40]}...' ({label_len} chars) in {qname} "
                                   f"— possible DNS exfiltration")
                            print(f"[DNS LABEL] {msg}")
                            alert = _make_alert(src_ip, dst_ip, "MEDIUM", 78.0, msg)
                            _send_alert(alert)

                    # Entropy check
                    if entropy > ENTROPY_THRESHOLD:
                        key = f"{src_ip}:entropy"
                        if _can_alert(key, now):
                            msg = (f"[!] High-Entropy DNS Query from {src_ip}: "
                                   f"subdomain '{label[:30]}' (entropy={entropy:.2f} bits/char) "
                                   f"in {qname} — likely Base64/Hex encoded C2 channel")
                            print(f"[DNS ENTROPY] {msg}")
                            sev  = "HIGH" if entropy > 4.5 else "MEDIUM"
                            conf = round(min(97.0, 65.0 + (entropy - ENTROPY_THRESHOLD) * 10), 1)
                            alert = _make_alert(src_ip, dst_ip, sev, conf, msg)
                            _send_alert(alert)
            except Exception:
                break

    except Exception as e:
        print(f"[DNS] Packet error: {e}")


def start_dns_monitor():
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import sniff

    print("=" * 70)
    print("  DNS Tunneling Monitor — IDS_Snort_Project")
    print("=" * 70)
    print(f"  Filter     : UDP port 53 (DNS)")
    print(f"  Entropy thr: > {ENTROPY_THRESHOLD} bits/char")
    print(f"  Flood thr  : > {QUERY_FLOOD_LIMIT} queries / {QUERY_FLOOD_WINDOW}s")
    print(f"  Label max  : {MAX_LABEL_LEN} chars")
    print(f"  Alerts to  : UDP {UDP_IP}:{UDP_PORT}")
    print("  Press Ctrl+C to stop")
    print("=" * 70)

    try:
        while True:
            sniff(filter="udp port 53", prn=process_dns, store=False)
    except KeyboardInterrupt:
        print("\n[DNS] Stopped by user.")
    except PermissionError:
        print("\n[ERROR] Permission denied — run as Administrator.")
    except Exception as e:
        print(f"\n[DNS] Error: {e}")


if __name__ == "__main__":
    start_dns_monitor()
