"""
=============================================================
victim_agent/agent.py  -  IDS_Snort_Project
=============================================================
Lightweight Victim Agent
Runs on ANY victim PC connected to the same Wi-Fi network.
Detects attacks targeted at THIS machine and forwards
structured alert packets to the HP Monitoring PC's Correlator
over UDP port 9999.

Zero extra dependencies - pure Python standard library only.

SETUP (edit these 2 lines, then run):
  MONITOR_PC_IP = "192.168.1.50"   <- HP Monitoring PC's local IP
  VICTIM_NAME   = "PC-Lab-02"      <- Label shown on dashboard

Run: python agent.py
=============================================================
"""

import socket
import json
import time
import threading
import re
import os
import sys
import http.server
import urllib.parse
from datetime import datetime

# =============================================================
# CONFIGURATION  <-- Edit these for each victim PC
# =============================================================
MONITOR_PC_IP = "172.20.10.3"    # HP Monitoring PC's local IP
MONITOR_PORT  = 9999              # HP Correlator UDP port
VICTIM_NAME   = "PC-Lab-02"      # Label shown on HP dashboard
HTTP_TRAP_PORT = 8888             # Local HTTP honeypot port (optional)
# =============================================================

# ----- Detection thresholds -----
BRUTE_FORCE_THRESHOLD  = 5    # same src IP within TIME_WINDOW = brute force
FLOOD_RATE_THRESHOLD   = 100  # packets/sec from same IP = flood
SQLI_CONFIDENCE        = 97.0
BRUTEFORCE_CONFIDENCE  = 96.0
FLOOD_CONFIDENCE       = 95.0
SCAN_CONFIDENCE        = 93.0

TIME_WINDOW = 2.0  # seconds for rate calculations

# ----- SQL Injection patterns -----
SQLI_PATTERNS = [
    re.compile(r"(\%27|'|--|#)", re.IGNORECASE),
    re.compile(r"\b(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|ALTER|CREATE|EXEC)\b", re.IGNORECASE),
    re.compile(r"\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),
]

# ----- State tracking -----
connection_log = {}   # src_ip -> [timestamps]
lock = threading.Lock()

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


# =============================================================
# Utility helpers
# =============================================================

def get_local_ip():
    """Get this victim machine's local LAN IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


MY_IP = get_local_ip()


def send_alert(alert_type, severity, src_ip, protocol, confidence, message,
               packet_size=256, packet_rate=1):
    """Send structured alert UDP packet to HP Monitoring PC Correlator."""
    alert = {
        "id":          int(time.time() * 1000),
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type":        alert_type,
        "severity":    severity,
        "src_ip":      src_ip,
        "dst_ip":      MY_IP,
        "protocol":    protocol,
        "packet_size": packet_size,
        "packet_rate": packet_rate,
        "confidence":  confidence,
        "message":     message,
        "reported_by": "VICTIM_AGENT",
        "victim_name": VICTIM_NAME,
    }
    try:
        data = json.dumps(alert).encode("utf-8")
        udp_sock.sendto(data, (MONITOR_PC_IP, MONITOR_PORT))
        sev_label = f"[{severity:6}]"
        print(f"  {sev_label} {alert_type:20} src={src_ip:17} -> HP:{MONITOR_PORT}  ({message[:55]})")
    except Exception as e:
        print(f"  [ERROR] Could not send alert to HP: {e}")


def check_sqli(payload, src_ip):
    """Check payload for SQL injection patterns."""
    for pat in SQLI_PATTERNS:
        if pat.search(payload):
            return True
    return False


def record_connection(src_ip):
    """Track connection timestamps for rate-based detection."""
    now = time.time()
    with lock:
        if src_ip not in connection_log:
            connection_log[src_ip] = []
        # Keep only recent connections
        connection_log[src_ip] = [t for t in connection_log[src_ip] if now - t < TIME_WINDOW]
        connection_log[src_ip].append(now)
        count = len(connection_log[src_ip])
    return count


# =============================================================
# HTTP Honeypot Handler
# Exposes a fake HTTP endpoint that detects SQLi + brute force
# =============================================================

class HoneypotHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        # Suppress default server log
        pass

    def handle_request(self):
        src_ip = self.client_address[0]
        path   = self.path
        count  = record_connection(src_ip)

        # Decode query string
        parsed = urllib.parse.urlparse(path)
        query  = urllib.parse.unquote(parsed.query)

        # Read body if POST
        body = ""
        if self.command == "POST":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8", errors="ignore")
            except Exception:
                pass

        full_payload = f"{path} {query} {body}"

        # --- SQL Injection detection ---
        if check_sqli(full_payload, src_ip):
            send_alert(
                alert_type   = "SNORT_SIGNATURE",
                severity     = "HIGH",
                src_ip       = src_ip,
                protocol     = "HTTP",
                confidence   = SQLI_CONFIDENCE,
                message      = f"SQL Injection detected from {src_ip} on {parsed.path}",
                packet_size  = len(full_payload),
                packet_rate  = count,
            )

        # --- Brute Force detection (high connection rate to same endpoint) ---
        elif count >= BRUTE_FORCE_THRESHOLD:
            send_alert(
                alert_type   = "SNORT_SIGNATURE",
                severity     = "HIGH",
                src_ip       = src_ip,
                protocol     = "HTTP",
                confidence   = BRUTEFORCE_CONFIDENCE,
                message      = f"HTTP Brute Force: {count} requests in {TIME_WINDOW}s from {src_ip}",
                packet_size  = len(full_payload),
                packet_rate  = count,
            )

        # Send 200 OK response (honeypot lets attacker think they succeeded)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>OK</body></html>")

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()


def start_http_honeypot():
    """Start the HTTP honeypot on HTTP_TRAP_PORT."""
    try:
        server = http.server.HTTPServer(("0.0.0.0", HTTP_TRAP_PORT), HoneypotHandler)
        print(f"[VICTIM AGENT] HTTP honeypot listening on 0.0.0.0:{HTTP_TRAP_PORT}")
        server.serve_forever()
    except Exception as e:
        print(f"[VICTIM AGENT] HTTP honeypot error: {e}")


# =============================================================
# UDP Flood / Port Scan detector
# Watches a UDP socket for high-rate traffic from same source
# =============================================================

def start_udp_monitor():
    """Monitor UDP traffic on port 9998 for flood/scan patterns."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", 9998))
        sock.settimeout(1.0)
        print(f"[VICTIM AGENT] UDP monitor listening on 0.0.0.0:9998")

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                count  = record_connection(f"udp:{src_ip}")

                if count >= BRUTE_FORCE_THRESHOLD:
                    rate = count / TIME_WINDOW
                    if rate >= FLOOD_RATE_THRESHOLD:
                        sev = "HIGH"
                        atype = "ML_ANOMALY"
                        msg = f"UDP Flood detected from {src_ip} rate={rate:.0f} pkt/s"
                    else:
                        sev = "MEDIUM"
                        atype = "ML_ANOMALY"
                        msg = f"UDP Probe from {src_ip} ({count} pkts in {TIME_WINDOW}s)"

                    send_alert(
                        alert_type   = atype,
                        severity     = sev,
                        src_ip       = src_ip,
                        protocol     = "UDP",
                        confidence   = FLOOD_CONFIDENCE,
                        message      = msg,
                        packet_size  = len(data),
                        packet_rate  = int(rate),
                    )
            except socket.timeout:
                continue
            except Exception:
                continue
    except Exception as e:
        print(f"[VICTIM AGENT] UDP monitor error: {e}")


# =============================================================
# Heartbeat — lets HP dashboard know victim is alive
# =============================================================

def heartbeat_loop():
    """Send a heartbeat to HP every 30 seconds."""
    while True:
        send_alert(
            alert_type   = "HEARTBEAT",
            severity     = "LOW",
            src_ip       = MY_IP,
            protocol     = "UDP",
            confidence   = 100.0,
            message      = f"Victim Agent '{VICTIM_NAME}' online at {MY_IP} - monitoring active",
            packet_size  = 0,
            packet_rate  = 0,
        )
        time.sleep(30)


# =============================================================
# Main
# =============================================================

def main():
    banner = f"""
==============================================================
  IDS Victim Agent  -  Multi-Device Network Monitor
==============================================================
  Victim PC IP    : {MY_IP}
  Victim Name     : {VICTIM_NAME}
  Reporting To    : {MONITOR_PC_IP}:{MONITOR_PORT}  (HP Monitoring PC)
  HTTP Honeypot   : 0.0.0.0:{HTTP_TRAP_PORT}
  UDP Monitor     : 0.0.0.0:9998
==============================================================
  All detected attacks will appear on HP dashboard at:
  http://{MONITOR_PC_IP}:5000
==============================================================
"""
    print(banner)

    # Start all monitoring threads
    threads = [
        threading.Thread(target=start_http_honeypot, daemon=True),
        threading.Thread(target=start_udp_monitor, daemon=True),
        threading.Thread(target=heartbeat_loop, daemon=True),
    ]
    for t in threads:
        t.start()

    print("[VICTIM AGENT] All monitors started. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[VICTIM AGENT] Stopped.")


if __name__ == "__main__":
    main()
