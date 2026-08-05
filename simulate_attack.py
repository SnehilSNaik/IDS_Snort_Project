import socket
import json
import time

CORRELATOR_IP   = "127.0.0.1"
CORRELATOR_PORT = 9999
ATTACKER_IP     = "172.20.10.2"
TARGET_IP       = "172.20.10.3"
VICTIM_NAME     = "sonalS_pc"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send(alert):
    sock.sendto(json.dumps(alert).encode(), (CORRELATOR_IP, CORRELATOR_PORT))
    sev = alert["severity"]
    msg = alert["message"][:65]
    print(f"  [{sev:6}] {alert['type']:20}  {msg}")
    time.sleep(0.5)

now = lambda: time.strftime("%Y-%m-%d %H:%M:%S")
ts  = lambda offset=0: int(time.time() * 1000) + offset

print("=" * 65)
print(f"  Simulating attack: {ATTACKER_IP} --> {TARGET_IP}")
print("=" * 65)

# Phase 1: Port Scan
print("\n[Phase 1] Port Scan")
for port in [22, 80, 3306]:
    send({
        "id": ts(port), "timestamp": now(),
        "type": "ML_ANOMALY", "severity": "LOW",
        "src_ip": ATTACKER_IP, "dst_ip": TARGET_IP,
        "dst_port": port, "protocol": "TCP",
        "packet_size": 54, "packet_rate": 140,
        "confidence": 93.0,
        "message": f"Port scan detected from {ATTACKER_IP} -> port {port}",
        "reported_by": "VICTIM_AGENT", "victim_name": VICTIM_NAME,
    })

# Phase 2: SSH Brute Force
print("\n[Phase 2] SSH Brute Force")
send({
    "id": ts(10), "timestamp": now(),
    "type": "SNORT_SIGNATURE", "severity": "HIGH",
    "src_ip": ATTACKER_IP, "dst_ip": TARGET_IP,
    "dst_port": 22, "protocol": "TCP",
    "packet_size": 310, "packet_rate": 25,
    "confidence": 97.5,
    "message": f"SSH brute force attempt from {ATTACKER_IP}",
    "reported_by": "VICTIM_AGENT", "victim_name": VICTIM_NAME,
})

# Phase 3: SQL Injection
print("\n[Phase 3] SQL Injection")
send({
    "id": ts(20), "timestamp": now(),
    "type": "SNORT_SIGNATURE", "severity": "MEDIUM",
    "src_ip": ATTACKER_IP, "dst_ip": TARGET_IP,
    "dst_port": 80, "protocol": "HTTP",
    "packet_size": 512, "packet_rate": 8,
    "confidence": 96.2,
    "message": f"SQL injection attempt: [' OR 1=1 --] from {ATTACKER_IP}",
    "reported_by": "VICTIM_AGENT", "victim_name": VICTIM_NAME,
})

sock.close()
print("\n[DONE] All attack packets sent!")
