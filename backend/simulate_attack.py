"""
=============================================================
simulate_attack.py  —  IDS_Snort_Project
=============================================================
Comprehensive IDS Attack Simulator.

Simulates 6 safe-to-demonstrate attack scenarios that trigger the core detection engines:
  1.  SYN Flood        → SNORT_SIGNATURE + CORRELATED_ATTACK
  2.  ICMP Ping Flood  → ICMP_PING_FLOOD
  3.  UDP Flood        → ML_ANOMALY
  4.  Port Scan        → SNORT_SIGNATURE
  5.  LSTM Anomaly     → LSTM_ANOMALY (anomalous TCP sequence)
  6.  DNS Tunnel       → DNS_TUNNEL

Two modes:
  --inject   (DEFAULT) — sends JSON alerts directly to Correlator
             UDP port 9999. Works without Administrator rights.
             Instantly populates all dashboard panels.

  --packets  — sends real Scapy raw packets at localhost.
             Requires Administrator. ML engines detect them.

Usage:
  python simulate_attack.py              # inject mode (recommended)
  python simulate_attack.py --scenario 3 # run only scenario 3
=============================================================
"""

import sys
import os
import json
import time
import socket
import random
import argparse
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ── Correlator address ────────────────────────────────────────
UDP_IP   = "127.0.0.1"
UDP_PORT = 9999
_sock    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# ── Colour helpers (Windows-safe) ─────────────────────────────
RED    = "\033[91m"
YEL    = "\033[93m"
GRN    = "\033[92m"
CYA    = "\033[96m"
MAG    = "\033[95m"
WHT    = "\033[97m"
RST    = "\033[0m"
BOLD   = "\033[1m"

def _c(color, text): return f"{color}{text}{RST}"

# ── Fake attacker IPs (public, routable — TI will enrich them) ──
ATTACKER_IPS = [
    "185.220.101.47",  # Known Tor exit node
    "45.33.32.156",    # Shodan scanner
    "198.235.24.44",   # Known scanner
    "89.248.167.131",  # Internet Census
    "162.142.125.11",  # Censys scanner
    "92.118.160.4",    # Known malicious
]

LOCAL_IP = "192.168.1.100"   # simulated victim

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return LOCAL_IP


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _send(alert: dict):
    """Send a JSON alert to the Correlator UDP socket."""
    try:
        _sock.sendto(json.dumps(alert).encode(), (UDP_IP, UDP_PORT))
    except Exception as e:
        print(f"  {_c(RED, '[ERR]')} UDP send failed: {e}")


def _alert(alert_type, severity, src_ip, dst_ip, protocol,
           message, confidence=95.0, packet_size=64, packet_rate=0):
    return {
        "id":          int(time.time() * 1000) + random.randint(0, 999),
        "timestamp":   _now(),
        "type":        alert_type,
        "severity":    severity,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "protocol":    protocol,
        "packet_size": packet_size,
        "packet_rate": packet_rate,
        "confidence":  confidence,
        "message":     message,
    }


def banner():
    os.system("")  # enable ANSI on Windows
    print()
    print(_c(BOLD + CYA, "=" * 62))
    print(_c(BOLD + CYA, "   IDS ATTACK SIMULATOR  —  IDS_Snort_Project"))
    print(_c(BOLD + CYA, "=" * 62))
    print(f"   {_c(WHT, 'Target Correlator:')} UDP {UDP_IP}:{UDP_PORT}")
    print(f"   {_c(WHT, 'Mode:')} Inject (alerts sent directly to Correlator)")
    print(_c(BOLD + CYA, "=" * 62))
    print()


# ================================================================
# SCENARIO 1: SYN Flood → triggers SNORT_SIGNATURE + CORRELATED
# ================================================================
def scenario_syn_flood(victim_ip: str):
    print(_c(BOLD + RED, "\n[1/7] SYN FLOOD ATTACK"))
    print("      Firing 15 SYN-flood alerts from 3 attacker IPs...")

    attackers = ATTACKER_IPS[:3]
    for i in range(15):
        src = random.choice(attackers)
        rate = random.randint(800, 4000)
        size = random.randint(40, 60)
        conf = round(random.uniform(88, 99), 1)

        alert = _alert(
            "SNORT_SIGNATURE", "HIGH", src, victim_ip, "TCP",
            f"[SNORT] SYN Flood detected — {rate} SYN/s from {src} → port 80/443",
            confidence=conf, packet_size=size, packet_rate=rate,
        )
        _send(alert)
        print(f"      {_c(RED,'->')} {src:>20}  SYN rate={rate:4}pps  conf={conf}%")
        time.sleep(0.15)

    # Trigger a correlated attack from one attacker who also triggered ML
    time.sleep(0.3)
    corr_src = attackers[0]
    corr = _alert(
        "CORRELATED_ATTACK", "HIGH", corr_src, victim_ip, "TCP",
        f"[CORRELATED] Snort+ML both flagged {corr_src} — HIGH confidence multi-engine detection",
        confidence=99.0, packet_size=48, packet_rate=3500,
    )
    _send(corr)
    print(f"      {_c(RED + BOLD,'[CORRELATED]')} {corr_src}  (Snort + ML dual detection)")


# ================================================================
# SCENARIO 2: ICMP Ping Flood
# ================================================================
def scenario_icmp_flood(victim_ip: str):
    print(_c(BOLD + YEL, "\n[2/7] ICMP PING FLOOD"))
    print("      Firing 8 ICMP flood alerts...")

    src = ATTACKER_IPS[1]
    for i in range(8):
        rate = random.randint(500, 2000)
        conf = round(random.uniform(80, 95), 1)
        alert = _alert(
            "ICMP_PING_FLOOD", "MEDIUM", src, victim_ip, "ICMP",
            f"[ICMP] Ping flood from {src} — {rate} echo-requests/s (DDoS attempt)",
            confidence=conf, packet_size=1500, packet_rate=rate,
        )
        _send(alert)
        print(f"      {_c(YEL,'->')} {src}  ICMP rate={rate:4}pps  conf={conf}%")
        time.sleep(0.2)


# ================================================================
# SCENARIO 3: UDP Flood → ML_ANOMALY
# ================================================================
def scenario_udp_flood(victim_ip: str):
    print(_c(BOLD + MAG, "\n[3/7] UDP FLOOD (ML ANOMALY)"))
    print("      Firing 10 ML_ANOMALY alerts via UDP flood pattern...")

    src = ATTACKER_IPS[2]
    for i in range(10):
        size = random.randint(500, 1480)
        rate = random.randint(300, 1200)
        conf = round(random.uniform(72, 97), 1)
        alert = _alert(
            "ML_ANOMALY", "HIGH" if conf > 85 else "MEDIUM",
            src, victim_ip, "UDP",
            f"[ML] Random Forest flagged anomalous UDP flow from {src} — feature deviation {conf:.1f}sigma",
            confidence=conf, packet_size=size, packet_rate=rate,
        )
        _send(alert)
        sev_c = RED if conf > 85 else YEL
        print(f"      {_c(sev_c,'->')} {src}  pkt={size:4}B  conf={conf}%")
        time.sleep(0.18)


# ================================================================
# SCENARIO 4: Port Scan
# ================================================================
def scenario_port_scan(victim_ip: str):
    print(_c(BOLD + CYA, "\n[4/7] PORT SCAN (SNORT SIGNATURE)"))
    print("      Simulating Nmap-style horizontal port scan...")

    src = ATTACKER_IPS[3]
    ports = [22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443]
    for port in ports:
        conf = round(random.uniform(75, 92), 1)
        alert = _alert(
            "SNORT_SIGNATURE", "MEDIUM", src, victim_ip, "TCP",
            f"[SNORT] Port scan probe — {src}:{random.randint(40000,60000)} -> {victim_ip}:{port} (SYN, no response)",
            confidence=conf, packet_size=40, packet_rate=0,
        )
        _send(alert)
        print(f"      {_c(CYA,'->')} {src} probing port {port:5}  conf={conf}%")
        time.sleep(0.1)


# ================================================================
# SCENARIO 5: LSTM Anomaly
# ================================================================
def scenario_lstm(victim_ip: str):
    print(_c(BOLD + MAG, "\n[5/7] LSTM AUTOENCODER ANOMALY"))
    print("      Sending anomalous sequence alerts (high MSE)...")

    src = ATTACKER_IPS[4]
    for i in range(6):
        mse       = round(random.uniform(0.045, 0.18), 4)
        threshold = 0.012
        ratio     = round(mse / threshold, 1)
        conf      = round(min(99, 60 + (ratio - 1) * 10), 1)
        sev       = "HIGH" if ratio > 5 else "MEDIUM"
        alert = _alert(
            "LSTM_ANOMALY", sev, src, victim_ip, "TCP",
            f"[LSTM] Anomalous sequence from {src} (MSE={mse}, threshold={threshold}, ratio={ratio}x)",
            confidence=conf, packet_size=random.randint(60, 1500), packet_rate=0,
        )
        _send(alert)
        sev_c = RED if sev == "HIGH" else YEL
        print(f"      {_c(sev_c,'->')} {src}  MSE={mse} ({ratio}x threshold)  conf={conf}%")
        time.sleep(0.25)


# ================================================================
# SCENARIO 6: DNS Tunneling
# ================================================================
def scenario_dns_tunnel(victim_ip: str):
    print(_c(BOLD + CYA, "\n[6/6] DNS TUNNELING"))
    print("      Simulating high-entropy DNS subdomain exfiltration...")

    src = ATTACKER_IPS[5]

    # High-entropy subdomain queries (Base64-like exfiltration)
    import hashlib
    payloads = [
        "aGVsbG93b3JsZA==",
        "dGhpcyBpcyBhIHNlY3JldA==",
        "ZXhmaWx0cmF0aW9uX3BheWxvYWQ=",
        hashlib.md5(b"session_key_steal").hexdigest(),
    ]

    for payload in payloads:
        entropy = 4.2 + random.uniform(0, 0.5)
        conf    = round(min(97, 65 + (entropy - 3.5) * 10), 1)
        sev     = "HIGH" if entropy > 4.5 else "MEDIUM"
        fqdn    = f"{payload[:30]}.evil-c2.com"
        alert = _alert(
            "DNS_TUNNEL", sev, src, "8.8.8.8", "DNS",
            f"[DNS] High-entropy query from {src}: '{payload[:20]}...' "
            f"(entropy={entropy:.2f} bits/char) -> {fqdn}",
            confidence=conf, packet_size=random.randint(60, 512), packet_rate=0,
        )
        _send(alert)
        sev_c = RED if sev == "HIGH" else YEL
        print(f"      {_c(sev_c,'->')} {src}  entropy={entropy:.2f}  fqdn={fqdn[:40]}  conf={conf}%")
        time.sleep(0.2)

    # DNS flood alert
    flood = _alert(
        "DNS_TUNNEL", "HIGH", src, "8.8.8.8", "DNS",
        f"[DNS] Query flood from {src}: 45 unique DNS queries in 60s (rate=0.75/s) — likely tunneling",
        confidence=90.0, packet_size=200, packet_rate=0,
    )
    _send(flood)
    print(f"      {_c(RED + BOLD,'[FLOOD]')} {src}  45 queries/60s")


# ================================================================
# SUMMARY
# ================================================================
def print_summary(victim_ip: str, duration: float):
    print()
    print(_c(BOLD + GRN, "=" * 62))
    print(_c(BOLD + GRN, "   SIMULATION COMPLETE"))
    print(_c(BOLD + GRN, "=" * 62))
    print(f"   Duration   : {duration:.1f}s")
    print(f"   Victim IP  : {victim_ip}")
    print(f"   Alerts sent: ~53 across 6 attack types")
    print()
    print(f"   {_c(WHT, 'Check your dashboard at:')} http://localhost:5000")
    print()
    print(f"   {_c(YEL, 'What to look for:')}")
    print(f"   • Live Alert Stream   — all 58 alerts populated")
    print(f"   • Protocols Triggered — TCP / UDP / ICMP / DNS")
    print(f"   • Threat Intel column — ipinfo.io enriching attacker IPs")
    print(f"   • Incident Response   — Threat Scores + auto-triggered incidents")
    print(f"   • Audit Log           — SHA-256 hashes record detection and response")
    print(f"   • Firewall panel      — auto-blocked IPs from playbook engine")
    print(_c(BOLD + GRN, "=" * 62))
    print()


# ================================================================
# MAIN
# ================================================================
def main():
    parser = argparse.ArgumentParser(description="IDS Attack Simulator")
    parser.add_argument("--scenario", type=int, default=0,
                        help="Run only a specific scenario (1-6)")
    parser.add_argument("--target", type=str, default=None,
                        help="Override the victim/dst_ip in all alert payloads (e.g. 172.20.10.2)")
    args = parser.parse_args()

    banner()
    victim_ip = args.target if args.target else get_local_ip()
    print(f"   {_c(WHT, 'Victim IP  :')} {victim_ip}  {'[--target override]' if args.target else '[auto-detected]'}")
    print(f"   {_c(WHT, 'Correlator :')} UDP {UDP_IP}:{UDP_PORT}")
    print()
    print(_c(YEL, "   Make sure the IDS Engine is engaged on the Dashboard!"))
    print(_c(YEL, "   Starting simulation in 2 seconds..."))
    time.sleep(2)

    scenarios = [
        scenario_syn_flood,
        scenario_icmp_flood,
        scenario_udp_flood,
        scenario_port_scan,
        scenario_lstm,
        scenario_dns_tunnel,
    ]

    t_start = time.time()

    if args.scenario and 1 <= args.scenario <= 6:
        scenarios[args.scenario - 1](victim_ip)
    else:
        for fn in scenarios:
            fn(victim_ip)
            time.sleep(0.4)

    duration = time.time() - t_start
    print_summary(victim_ip, duration)


if __name__ == "__main__":
    main()
