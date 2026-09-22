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
import argparse
import platform
import uuid
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

# =============================================================
# CONFIGURATION  <-- Edit these for each victim PC
# =============================================================
MONITOR_PC_IP = os.environ.get("IDS_SERVER", "127.0.0.1")
MONITOR_PORT  = 9999              # HP Correlator UDP port
VICTIM_NAME   = os.environ.get("IDS_ENDPOINT_NAME", socket.gethostname())
HTTP_TRAP_PORT = 8888             # Local HTTP honeypot port (optional)
AGENT_VERSION  = "2.0"
FILE_AUDIT_STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "file_audit_state.json")
DEFAULT_PROTECTED_POLICY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "protected_paths.json")
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

# ----- Path Traversal / File Theft patterns -----
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c)", re.IGNORECASE),
    re.compile(r"/(etc/passwd|etc/shadow|windows/win.ini|boot.ini)", re.IGNORECASE),
    re.compile(r"\b(passwords?\.txt|secrets?\.json|keys?\.pem|config\.py|credentials|id_rsa)\b", re.IGNORECASE),
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
ENDPOINT_ID = f"{socket.gethostname()}-{uuid.getnode():012x}"


def send_endpoint_status(message_type):
    """Register or heartbeat without creating a security alert."""
    message = {
        "type": message_type,
        "endpoint_id": ENDPOINT_ID,
        "victim_name": VICTIM_NAME,
        "hostname": socket.gethostname(),
        "endpoint_ip": MY_IP,
        "os": f"{platform.system()} {platform.release()}",
        "agent_version": AGENT_VERSION,
    }
    try:
        udp_sock.sendto(json.dumps(message).encode("utf-8"), (MONITOR_PC_IP, MONITOR_PORT))
    except OSError as exc:
        print(f"[VICTIM AGENT] Could not contact IDS server: {exc}")


def send_alert(alert_type, severity, src_ip, protocol, confidence, message,
               packet_size=256, packet_rate=1, metadata=None):
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
        "endpoint_id": ENDPOINT_ID,
        "endpoint_hostname": socket.gethostname(),
    }
    if metadata:
        alert.update(metadata)
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


def check_file_theft(payload):
    """Check payload for directory traversal and unauthorized file theft patterns."""
    for pat in PATH_TRAVERSAL_PATTERNS:
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
# Windows protected-file access monitor (Security Event ID 4663)
# =============================================================

def _event_data(xml_text):
    """Extract Security-event fields from one rendered XML event."""
    root = ET.fromstring(xml_text)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    record_id = root.findtext("e:System/e:EventRecordID", default="0", namespaces=ns)
    fields = {item.attrib.get("Name", ""): item.text or "" for item in root.findall("e:EventData/e:Data", ns)}
    return int(record_id), fields


def _recent_file_events(limit=64):
    """Read recent Windows Security 4663 events without third-party packages."""
    if os.name != "nt":
        return []
    query = "*[System[(EventID=4663)]]"
    try:
        result = subprocess.run(
            ["wevtutil", "qe", "Security", f"/q:{query}", "/f:RenderedXml", "/rd:true", f"/c:{limit}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    events = []
    for chunk in result.stdout.split("</Event>"):
        if "<Event" not in chunk:
            continue
        try:
            events.append(_event_data(chunk + "</Event>"))
        except (ET.ParseError, ValueError):
            continue
    return events


def _load_file_audit_state():
    try:
        with open(FILE_AUDIT_STATE_FILE, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def _save_file_audit_state(state):
    try:
        with open(FILE_AUDIT_STATE_FILE, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
    except OSError:
        pass


def _is_read_access(access_mask):
    """Windows FILE_READ_DATA is bit 0x1; avoid alerting on write-only events."""
    try:
        return bool(int(access_mask, 16) & 0x1)
    except ValueError:
        return False


def load_protected_assets(policy_file, cli_path=None):
    """Load an endpoint-owned protected-asset policy instead of fixed paths."""
    assets = []
    try:
        with open(policy_file, "r", encoding="utf-8") as handle:
            policy = json.load(handle)
        for item in policy.get("protected_assets", []):
            if not item.get("enabled", True) or not item.get("path"):
                continue
            assets.append({
                "name": str(item.get("name") or "Protected asset"),
                "path": os.path.normcase(os.path.abspath(str(item["path"]))),
                "severity": str(item.get("severity", "MEDIUM")).upper(),
                "asset_class": str(item.get("asset_class", "Sensitive data")),
            })
    except FileNotFoundError:
        pass  # A policy is optional; the agent still supports normal monitoring.
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[FILE AUDIT] Could not load policy {policy_file}: {exc}")

    if cli_path:
        assets.append({
            "name": "Command-line protected folder",
            "path": os.path.normcase(os.path.abspath(cli_path)),
            "severity": "MEDIUM",
            "asset_class": "Lab data",
        })

    # Avoid duplicate paths while preserving the first policy label.
    unique = {}
    for asset in assets:
        unique.setdefault(asset["path"], asset)
    return list(unique.values())


def _matching_asset(object_name, assets):
    if not object_name:
        return None
    candidate = os.path.normcase(os.path.abspath(object_name))
    for asset in assets:
        protected = asset["path"]
        if candidate == protected or candidate.startswith(protected + os.sep):
            return asset
    return None


def start_file_access_monitor(assets, poll_seconds=2.0):
    """Report new read accesses to a deliberately protected lab folder.

    Windows must have File System Success auditing and a SACL on each asset path.
    The included setup script applies those settings only when an administrator
    explicitly runs it.
    """
    if os.name != "nt":
        print("[FILE AUDIT] Protected-folder monitoring is available on Windows only.")
        return
    state = _load_file_audit_state()
    state_key = "last_record:protected_assets"
    last_record = int(state.get(state_key, 0))
    initial = _recent_file_events()
    if not last_record:
        # Establish a baseline so historical Windows events are never reported.
        last_record = max((record for record, _ in initial), default=0)
        state[state_key] = last_record
        _save_file_audit_state(state)
    print("[FILE AUDIT] Protected asset policy loaded:")
    for asset in assets:
        print(f"  - {asset['name']} ({asset['asset_class']}): {asset['path']}")
    print("[FILE AUDIT] Waiting for Security Event ID 4663 (run setup_file_audit.ps1 once as Administrator).")

    while True:
        events = _recent_file_events()
        for record_id, data in sorted(events):
            if record_id <= last_record:
                continue
            object_name = data.get("ObjectName", "")
            asset = _matching_asset(object_name, assets)
            if asset:
                if _is_read_access(data.get("AccessMask", "")):
                    actor = data.get("SubjectUserName", "Unknown account")
                    process = data.get("ProcessName", "Unknown process")
                    send_alert(
                        alert_type="FILE_ACCESS", severity=asset["severity"], src_ip="Unknown",
                        protocol="ENDPOINT", confidence=85.0, packet_size=0, packet_rate=1,
                        message=f"Protected asset read: {object_name} by {actor} via {process}",
                        metadata={
                            "protected_asset": asset["name"],
                            "protected_asset_class": asset["asset_class"],
                            "protected_path": asset["path"],
                            "actor": actor,
                            "process_name": process,
                        },
                    )
            last_record = max(last_record, record_id)
        state[state_key] = last_record
        _save_file_audit_state(state)
        time.sleep(max(1.0, poll_seconds))


# =============================================================
# HTTP Honeypot Handler
# Exposes a fake HTTP endpoint that detects SQLi + brute force + file theft
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

        # --- File Theft / Path Traversal detection ---
        if check_file_theft(full_payload):
            send_alert(
                alert_type   = "SNORT_SIGNATURE",
                severity     = "HIGH",
                src_ip       = src_ip,
                protocol     = "HTTP",
                confidence   = 98.0,
                message      = f"File Theft Attempt (Path Traversal) from {src_ip} requesting {parsed.path}",
                packet_size  = len(full_payload),
                packet_rate  = count,
            )

        # --- SQL Injection detection ---
        elif check_sqli(full_payload, src_ip):
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
        send_endpoint_status("ENDPOINT_HEARTBEAT")
        time.sleep(30)


# =============================================================
# Main
# =============================================================

def main():
    global MONITOR_PC_IP, MONITOR_PORT, VICTIM_NAME, HTTP_TRAP_PORT
    parser = argparse.ArgumentParser(description="IDS endpoint agent")
    parser.add_argument("--server", default=MONITOR_PC_IP, help="IDS correlator IP or hostname")
    parser.add_argument("--port", type=int, default=MONITOR_PORT, help="IDS correlator UDP port")
    parser.add_argument("--name", default=VICTIM_NAME, help="Display name shown in the SOC")
    parser.add_argument("--honeypot-port", type=int, default=HTTP_TRAP_PORT)
    parser.add_argument("--policy-file", default=DEFAULT_PROTECTED_POLICY, help="JSON protected-asset policy file")
    parser.add_argument("--watch-path", help="Optional one-off folder added to the protected-asset policy")
    parser.add_argument("--file-audit-poll-seconds", type=float, default=2.0, help="File-audit event polling interval")
    args = parser.parse_args()
    MONITOR_PC_IP, MONITOR_PORT = args.server, args.port
    VICTIM_NAME, HTTP_TRAP_PORT = args.name, args.honeypot_port
    protected_assets = load_protected_assets(args.policy_file, args.watch_path)
    send_endpoint_status("ENDPOINT_REGISTER")
    banner = f"""
==============================================================
  IDS Victim Agent  -  Multi-Device Network Monitor
==============================================================
  Victim PC IP    : {MY_IP}
  Victim Name     : {VICTIM_NAME}
  Reporting To    : {MONITOR_PC_IP}:{MONITOR_PORT}  (HP Monitoring PC)
  HTTP Honeypot   : 0.0.0.0:{HTTP_TRAP_PORT}
  UDP Monitor     : 0.0.0.0:9998
  File Audit      : {len(protected_assets)} policy asset(s)
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
    if protected_assets:
        threads.append(threading.Thread(
            target=start_file_access_monitor,
            args=(protected_assets, args.file_audit_poll_seconds), daemon=True,
        ))
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
