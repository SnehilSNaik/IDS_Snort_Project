"""
=============================================================
simulate_attacks.py  —  IDS_Snort_Project
=============================================================
Realistic attack simulator that sends crafted UDP alert
packets to the correlator (port 9999), simulating a live
attack scenario.

Attack scenarios included:
  1. Port Scan (multiple LOW TCP packets)
  2. DDoS Flood (HIGH rate UDP packets from botnet IPs)
  3. Brute Force SSH (repeated TCP HIGH severity)
  4. SQL Injection attempt (HTTP, MEDIUM severity)
  5. Correlated Attack (both ML + Snort fire for same IP)
  6. Ransomware beacon (ICMP, HIGH severity)
  7. Cryptominer C2 traffic (TCP, MEDIUM)

Run:  python simulate_attacks.py
=============================================================
"""

import socket
import json
import time
import random
import sys

UDP_IP   = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
UDP_PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# -----------------------------------------------
# Attacker profiles
# -----------------------------------------------
ATTACKERS = {
    "port_scanner":    "45.33.32.156",   # Nmap famous IP
    "ddos_node_1":     "185.220.101.47", # Tor exit node
    "ddos_node_2":     "194.165.16.78",
    "ddos_node_3":     "91.108.4.150",
    "brute_force":     "203.0.113.42",   # RFC5737 test range
    "sql_injection":   "198.51.100.77",
    "ransomware":      "10.0.0.99",      # Internal threat
    "cryptominer":     "77.88.55.66",    # Suspicious external
    "correlated_ip":   "172.16.0.250",   # Both engines fire on this
}

VICTIM_IP = "192.168.1.50"

def send_alert(alert: dict):
    data = json.dumps(alert).encode("utf-8")
    sock.sendto(data, (UDP_IP, UDP_PORT))
    sev = alert.get("severity", "LOW")
    print(
        f"  [{sev:6}] "
        f"{alert.get('type','?'):20} "
        f"src={alert.get('src_ip','?'):17} "
        f"proto={alert.get('protocol','?'):5} "
        f"conf={alert.get('confidence',0):.0f}%"
    )

def banner(title):
    print(f"\n{'='*60}")
    print(f"  >>> {title}")
    print(f"{'='*60}")

def pause(secs=0.4):
    time.sleep(secs)

# -----------------------------------------------
# Scenario 1: Port Scan
# -----------------------------------------------
def scenario_port_scan():
    banner("SCENARIO 1: Port Scan (45.33.32.156)")
    ports = [22, 80, 443, 3306, 5432, 8080, 8443, 3389]
    for i, port in enumerate(ports):
        send_alert({
            "id":          int(time.time() * 1000) + i,
            "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
            "type":        "ML_ANOMALY",
            "severity":    "LOW",
            "src_ip":      ATTACKERS["port_scanner"],
            "dst_ip":      VICTIM_IP,
            "dst_port":    port,
            "protocol":    "TCP",
            "packet_size": random.randint(40, 64),
            "packet_rate": random.randint(80, 200),
            "confidence":  round(random.uniform(88, 96), 1),
            "message":     f"Port scan detected from {ATTACKERS['port_scanner']} → port {port}",
        })
        pause(0.2)

# -----------------------------------------------
# Scenario 2: DDoS Botnet Flood
# -----------------------------------------------
def scenario_ddos():
    banner("SCENARIO 2: DDoS Botnet Flood (3 nodes)")
    botnet = [ATTACKERS["ddos_node_1"], ATTACKERS["ddos_node_2"], ATTACKERS["ddos_node_3"]]
    for wave in range(3):
        for i, ip in enumerate(botnet):
            send_alert({
                "id":          int(time.time() * 1000) + i + wave * 10,
                "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
                "type":        "ML_ANOMALY",
                "severity":    "HIGH",
                "src_ip":      ip,
                "dst_ip":      VICTIM_IP,
                "protocol":    "UDP",
                "packet_size": random.randint(512, 1480),
                "packet_rate": random.randint(800, 5000),
                "confidence":  round(random.uniform(95, 99), 1),
                "message":     f"DDoS flood wave {wave+1} from {ip} (rate={random.randint(800,5000)} pps)",
            })
            pause(0.15)
        pause(0.5)

# -----------------------------------------------
# Scenario 3: SSH Brute Force
# -----------------------------------------------
def scenario_brute_force():
    banner("SCENARIO 3: SSH Brute Force (203.0.113.42)")
    for attempt in range(6):
        send_alert({
            "id":          int(time.time() * 1000) + attempt,
            "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
            "type":        "SNORT_SIGNATURE",
            "severity":    "HIGH",
            "src_ip":      ATTACKERS["brute_force"],
            "dst_ip":      VICTIM_IP,
            "dst_port":    22,
            "protocol":    "TCP",
            "packet_size": random.randint(200, 400),
            "packet_rate": random.randint(10, 30),
            "confidence":  round(random.uniform(96, 99), 1),
            "message":     f"SSH brute force attempt #{attempt+1} from {ATTACKERS['brute_force']}",
        })
        pause(0.3)

# -----------------------------------------------
# Scenario 4: SQL Injection
# -----------------------------------------------
def scenario_sql_injection():
    banner("SCENARIO 4: SQL Injection (198.51.100.77)")
    payloads = [
        "' OR 1=1 --",
        "' UNION SELECT * FROM users --",
        "'; DROP TABLE users; --",
        "' AND SLEEP(5) --",
    ]
    for i, payload in enumerate(payloads):
        send_alert({
            "id":          int(time.time() * 1000) + i,
            "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
            "type":        "SNORT_SIGNATURE",
            "severity":    "MEDIUM",
            "src_ip":      ATTACKERS["sql_injection"],
            "dst_ip":      VICTIM_IP,
            "dst_port":    80,
            "protocol":    "TCP",
            "packet_size": random.randint(300, 800),
            "packet_rate": random.randint(5, 20),
            "confidence":  round(random.uniform(91, 97), 1),
            "message":     f"SQL injection attempt: [{payload}] from {ATTACKERS['sql_injection']}",
        })
        pause(0.35)

# -----------------------------------------------
# Scenario 5: Correlated Attack (ML + Snort same IP)
# -----------------------------------------------
def scenario_correlated():
    banner("SCENARIO 5: CORRELATED ATTACK (ML + Snort match!)")
    ip = ATTACKERS["correlated_ip"]
    print("  -> Sending ML_ANOMALY first...")
    send_alert({
        "id":          int(time.time() * 1000),
        "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
        "type":        "ML_ANOMALY",
        "severity":    "HIGH",
        "src_ip":      ip,
        "dst_ip":      VICTIM_IP,
        "protocol":    "TCP",
        "packet_size": 1460,
        "packet_rate": 2500,
        "confidence":  98.5,
        "message":     f"ML: Anomalous HIGH-rate traffic from {ip}",
    })
    pause(0.2)  # Within the 0.5s correlation window
    print("  -> Sending SNORT_SIGNATURE within window -> CORRELATION!")
    send_alert({
        "id":          int(time.time() * 1000) + 1,
        "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
        "type":        "SNORT_SIGNATURE",
        "severity":    "HIGH",
        "src_ip":      ip,
        "dst_ip":      VICTIM_IP,
        "protocol":    "TCP",
        "packet_size": 1460,
        "packet_rate": 2500,
        "confidence":  99.0,
        "message":     f"Snort: Known attack signature match from {ip}",
    })

# -----------------------------------------------
# Scenario 6: Ransomware Beacon
# -----------------------------------------------
def scenario_ransomware():
    banner("SCENARIO 6: Ransomware C2 Beacon (10.0.0.99)")
    for i in range(4):
        send_alert({
            "id":          int(time.time() * 1000) + i,
            "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
            "type":        "ML_ANOMALY",
            "severity":    "HIGH",
            "src_ip":      ATTACKERS["ransomware"],
            "dst_ip":      "185.220.101.99",   # external C2 server
            "protocol":    "ICMP",
            "packet_size": random.randint(64, 128),
            "packet_rate": random.randint(1, 5),
            "confidence":  round(random.uniform(94, 99), 1),
            "message":     f"Ransomware C2 beacon #{i+1} from internal host {ATTACKERS['ransomware']}",
        })
        pause(0.4)

# -----------------------------------------------
# Scenario 7: Cryptominer C2
# -----------------------------------------------
def scenario_cryptominer():
    banner("SCENARIO 7: Cryptominer Traffic (77.88.55.66)")
    for i in range(3):
        send_alert({
            "id":          int(time.time() * 1000) + i,
            "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
            "type":        "ML_ANOMALY",
            "severity":    "MEDIUM",
            "src_ip":      ATTACKERS["cryptominer"],
            "dst_ip":      VICTIM_IP,
            "dst_port":    3333,    # common mining pool port
            "protocol":    "TCP",
            "packet_size": random.randint(256, 512),
            "packet_rate": random.randint(20, 80),
            "confidence":  round(random.uniform(88, 95), 1),
            "message":     f"Cryptominer stratum protocol detected from {ATTACKERS['cryptominer']} → port 3333",
        })
        pause(0.3)

# -----------------------------------------------
# Main
# -----------------------------------------------
if __name__ == "__main__":
    print()
    print("=" * 62)
    print("  IDS Blockchain -- Attack Simulator")
    print("  All attacks committed permanently to blockchain")
    print("=" * 62)
    print()
    print(f"  Sending to correlator at udp://{UDP_IP}:{UDP_PORT}")
    print(f"  Target: {VICTIM_IP}")
    print()

    try:
        scenario_port_scan()
        pause(1)
        scenario_ddos()
        pause(1)
        scenario_brute_force()
        pause(1)
        scenario_sql_injection()
        pause(1)
        scenario_correlated()
        pause(1)
        scenario_ransomware()
        pause(1)
        scenario_cryptominer()

        print()
        print("=" * 62)
        print("  [OK] All 7 attack scenarios simulated successfully!")
        print("  All blocks permanently recorded in blockchain")
        print("  View dashboard --> http://localhost:5000")
        print("=" * 62)
        print()
    except ConnectionRefusedError:
        print("\n[ERROR] Cannot connect to correlator on UDP 9999.")
        print("Make sure the correlator is running first:")
        print("  python correlator/correlator.py")
    finally:
        sock.close()
