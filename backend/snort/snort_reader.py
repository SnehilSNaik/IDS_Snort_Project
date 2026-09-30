"""
=============================================================
snort/snort_reader.py
=============================================================
Launches the REAL Snort C binary and tails its alert log.
Parses Snort fast-alert output and writes to alerts/alerts.json
in the same format as the ML engine.

Fast-alert format:
  04/13-10:22:01.123456  [**] [1:1000001:1] ICMP Ping Flood Detected [**]
  [Classification: Attempted Denial of Service] [Priority: 2]
  {ICMP} 192.168.1.5 -> 192.168.1.1

Priority → Severity mapping:
  1 = HIGH
  2 = MEDIUM
  3 = LOW
=============================================================
"""

import os
import sys
import re
import json
import ipaddress
import time
import subprocess
import threading
import socket
from datetime import datetime

# ── Add project root to path ──────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)


# ── Paths ─────────────────────────────────────────────────
SNORT_EXE   = r"C:\Snort\bin\snort.exe"
SNORT_CONF  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ids_project.conf")
SNORT_LOG   = r"C:\Snort\log"
ALERT_FILE  = os.path.join(SNORT_LOG, "alert.ids")
ALERTS_JSON = os.path.join(BASE_DIR, "alerts", "alerts.json")

# ── Interface (Wi-Fi on this machine) ─────────────────────
# Run: snort -W    to see all available interfaces + indices
# Change this number to match your Wi-Fi adapter index.
SNORT_INTERFACE_IDX = None   # Will be auto-detected below

# ── Priority → Severity ───────────────────────────────────
PRIORITY_MAP = {
    "1": "HIGH",
    "2": "MEDIUM",
    "3": "LOW",
}

# ── Regex for Snort fast-alert lines ─────────────────────
# Line 1: timestamp + SID + message
ALERT_RE  = re.compile(
    r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)"  # timestamp
    r".*?\[\*\*\] \[(\d+:\d+:\d+)\] (.+?) \[\*\*\]"  # sid + msg
)
# Line with Priority:
PRIO_RE   = re.compile(r"\[Priority:\s*(\d+)\]")
# Line with endpoints: {PROTO} src[:port] -> dst[:port]. Supports IPv4 and IPv6.
IP_RE     = re.compile(r"\{(\w+)\}\s+(\S+)\s*->\s*(\S+)")


def _parse_endpoint_ip(endpoint: str) -> str | None:
    """Extract and normalize an IPv4 or IPv6 address from Snort's endpoint token."""
    endpoint = endpoint.strip().strip(",")
    if endpoint.startswith("[") and "]" in endpoint:
        endpoint = endpoint[1:endpoint.index("]")]
    candidates = [endpoint]
    if ":" in endpoint:
        candidates.append(endpoint.rsplit(":", 1)[0])  # Snort prints the port after the IP.
    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


# ── Alert UDP sender ──────────────────────────────────────
UDP_IP = "127.0.0.1"
UDP_PORT = 9999
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def save_alert(alert_data):
    """Sends the alert to the Correlator via UDP instead of writing to disk."""
    try:
        udp_sock.sendto(json.dumps(alert_data).encode("utf-8"), (UDP_IP, UDP_PORT))
    except Exception as e:
        print(f"[SNORT_READER] Error sending to Correlator: {e}")


# ── Parse a buffered 3-line Snort alert block ─────────────
def parse_alert_block(block: str):
    """
    Snort fast-mode writes multi-line blocks. Try to extract:
      timestamp, sid, message, priority, protocol, src_ip, dst_ip
    Returns a dict or None if parsing fails.
    """
    m_alert = ALERT_RE.search(block)
    if not m_alert:
        return None

    raw_ts  = m_alert.group(1)           # e.g. "04/13-10:22:01.123456"
    sid     = m_alert.group(2)           # e.g. "1:1000001:1"
    message = m_alert.group(3).strip()   # e.g. "ICMP Ping Flood Detected"

    # Parse priority
    m_prio = PRIO_RE.search(block)
    priority = m_prio.group(1) if m_prio else "3"
    severity = PRIORITY_MAP.get(priority, "LOW")

    # Parse IPs and protocol
    m_ip = IP_RE.search(block)
    protocol = m_ip.group(1) if m_ip else "Unknown"
    src_ip   = _parse_endpoint_ip(m_ip.group(2)) if m_ip else None
    dst_ip   = _parse_endpoint_ip(m_ip.group(3)) if m_ip else None
    src_ip   = src_ip or "0.0.0.0"
    dst_ip   = dst_ip or "0.0.0.0"

    # Normalise timestamp
    try:
        current_year = datetime.now().year
        ts = datetime.strptime(f"{current_year}/{raw_ts}", "%Y/%m/%d-%H:%M:%S.%f")
        timestamp = ts.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Confidence: fixed per severity (Snort doesn't give probabilistic scores)
    conf_map = {"HIGH": 95.0, "MEDIUM": 75.0, "LOW": 52.0}

    return {
        "id":          int(time.time() * 1000),
        "timestamp":   timestamp,
        "type":        "SNORT_SIGNATURE",
        "severity":    severity,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "protocol":    protocol,
        "packet_size": 0,         # Not available in fast-alert format
        "packet_rate": 0.0,       # Not available in fast-alert format
        "confidence":  conf_map.get(severity, 52.0),
        "message":     message,
        "snort_sid":   sid,
    }


# ── Tail the Snort alert file ─────────────────────────────
def tail_alert_file():
    r"""
    Blocks and reads new lines from C:\Snort\log\alert.ids as Snort appends them.
    Buffers multi-line alert blocks and fires parse_alert_block() on each.
    """
    print(f"[SNORT_READER] Watching: {ALERT_FILE}")

    # Wait for the alert file to appear (Snort creates it on first alert)
    while not os.path.exists(ALERT_FILE):
        time.sleep(1)

    with open(ALERT_FILE, "r", encoding="utf-8", errors="replace") as fh:
        # Seek to end — we only want NEW alerts
        fh.seek(0, 2)
        buffer = []

        while True:
            line = fh.readline()

            if not line:
                # No new data; flush buffer if we have content + blank line
                if buffer:
                    block = "\n".join(buffer)
                    alert = parse_alert_block(block)
                    if alert:
                        save_alert(alert)
                        sev_icon = {"HIGH": "[!]", "MEDIUM": "[-]", "LOW": "[i]"}.get(
                            alert["severity"], "[?]"
                        )
                        print(
                            f"[! SNORT] {alert['timestamp']} | "
                            f"{sev_icon} {alert['severity']} | "
                            f"{alert['message']} | "
                            f"{alert['src_ip']} -> {alert['dst_ip']}"
                        )
                    buffer = []
                time.sleep(0.1)
                continue

            stripped = line.strip()
            if stripped == "":
                # Blank line = end of one alert block
                if buffer:
                    block = "\n".join(buffer)
                    alert = parse_alert_block(block)
                    if alert:
                        save_alert(alert)
                        sev_icon = {"HIGH": "[!]", "MEDIUM": "[-]", "LOW": "[i]"}.get(
                            alert["severity"], "[?]"
                        )
                        print(
                            f"[! SNORT] {alert['timestamp']} | "
                            f"{sev_icon} {alert['severity']} | "
                            f"{alert['message']} | "
                            f"{alert['src_ip']} -> {alert['dst_ip']}"
                        )
                    buffer = []
            else:
                buffer.append(stripped)


# ── Auto-detect Snort interface index ─────────────────────
def detect_snort_interface():
    """
    Runs `snort -W` and finds the index for Wi-Fi / main active adapter.
    Returns interface index string (e.g. "1") or None.
    """
    try:
        result = subprocess.run(
            [SNORT_EXE, "-W"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
        # Look for Wi-Fi line
        for line in output.splitlines():
            if "Wi-Fi" in line or "Wireless" in line or "Wi-fi" in line:
                # Format: "1. \Device\NPF_{...}   (Wi-Fi)"
                m = re.match(r"^\s*(\d+)\.", line)
                if m:
                    print(f"[SNORT_READER] Auto-detected interface: {line.strip()}")
                    return m.group(1)
        # Fallback: first non-loopback
        for line in output.splitlines():
            m = re.match(r"^\s*(\d+)\.", line)
            if m and "Loopback" not in line and "loopback" not in line:
                print(f"[SNORT_READER] Using interface: {line.strip()}")
                return m.group(1)
    except Exception as e:
        print(f"[SNORT_READER] Interface detection failed: {e}")
    return "4"   # Default fallback to Wi-Fi interface


# ── Launch Snort subprocess ───────────────────────────────
def launch_snort(iface_idx: str):
    """
    Starts Snort 2.9.x in IDS/fast-alert mode.
    Must be run as Administrator.
    """
    os.makedirs(SNORT_LOG, exist_ok=True)

    # Copy rules to C:\Snort\rules\ (Snort reads from there)
    rules_dst = r"C:\Snort\rules\local.rules"
    os.makedirs(os.path.dirname(rules_dst), exist_ok=True)
    rules_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "local.rules")
    try:
        import shutil
        shutil.copy2(rules_src, rules_dst)
        print(f"[SNORT_READER] Copied rules → {rules_dst}")
    except Exception as e:
        print(f"[SNORT_READER] Warning: could not copy rules: {e}")

    # Copy our minimal conf to C:\Snort\etc\
    conf_dst = r"C:\Snort\etc\ids_project.conf"
    os.makedirs(os.path.dirname(conf_dst), exist_ok=True)
    conf_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ids_project.conf")
    try:
        import shutil
        shutil.copy2(conf_src, conf_dst)
        print(f"[SNORT_READER] Copied conf → {conf_dst}")
    except Exception as e:
        print(f"[SNORT_READER] Warning: could not copy conf: {e}")

    cmd = [
        SNORT_EXE,
        "-A", "fast",                  # Fast alert output
        "-q",                          # Quiet mode (no banner)
        "-c", conf_dst,                # Our config
        "-i", iface_idx,               # Interface index
        "-l", SNORT_LOG,               # Log dir
    ]

    print(f"[SNORT_READER] Launching Snort: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    print(f"[SNORT_READER] Snort PID: {proc.pid}")
    return proc


# ── Main ──────────────────────────────────────────────────
def main():
    if not os.path.exists(SNORT_EXE):
        print("=" * 60)
        print("[ERROR] Snort not found at C:\\Snort\\bin\\snort.exe")
        print()
        print("Please install Snort 2.9.20 for Windows:")
        print("  https://www.snort.org/downloads#snort-downloads")
        print("  Choose: Snort_2_9_20_Installer.exe")
        print()
        print("After install, run this script again as Administrator.")
        print("=" * 60)
        sys.exit(1)

    print("=" * 60)
    print("  Snort Reader — IDS_Snort_Project")
    print("  Launching real Snort C binary")
    print("=" * 60)

    iface_idx = detect_snort_interface()
    snort_proc = launch_snort(iface_idx)

    # Start tailing alert file in background
    tail_thread = threading.Thread(target=tail_alert_file, daemon=True)
    tail_thread.start()

    print(f"[SNORT_READER] Monitoring alerts at: {ALERT_FILE}")
    print("[SNORT_READER] Press Ctrl+C to stop")
    print("=" * 60)

    try:
        snort_proc.wait()
    except KeyboardInterrupt:
        print("\n[SNORT_READER] Stopping Snort...")
        snort_proc.terminate()
        snort_proc.wait()
        print("[SNORT_READER] Stopped.")


if __name__ == "__main__":
    main()
