"""
=============================================================
ml_model/detect.py  —  IDS_Snort_Project
=============================================================
ML-ONLY anomaly detection engine.

Supports two feature modes (auto-detected from feature_config.pkl):

  1. CIC-IDS-2017 MODE (15 features)
     Trained on real CIC-IDS-2017 dataset. Extracts flow-level
     features from live packets using a per-IP sliding window.

  2. SYNTHETIC MODE (3 features) — Backward Compatible
     Trained on synthetic data. Uses packet_size, protocol_enc,
     packet_rate as before.

Real Snort (C binary) handles signature detection via
snort/snort_reader.py. This module handles only ML-based
anomaly detection for unknown/novel traffic.
=============================================================
"""

import os
import sys
import json
import pickle
import time
import threading
import numpy as np
from datetime import datetime
from collections import deque, defaultdict

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_alert.send_alert import send_email_alert

import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ─── Paths ────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE   = os.path.join(BASE_DIR, "model.pkl")
SCALER_FILE  = os.path.join(BASE_DIR, "scaler.pkl")
FEATURE_CFG  = os.path.join(BASE_DIR, "feature_config.pkl")
ALERTS_FILE  = os.path.join(BASE_DIR, "../alerts/alerts.json")

# ─── Protocol map ─────────────────────────────────────────
PROTO_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "Other": 3}

# ─── Rate tracking (ML anomaly) ──────────────────────────
RATE_WINDOW = 1.0   # seconds: measure pkt/s over last 1 second
packet_times_by_ip = defaultdict(lambda: deque())  # unbounded, pruned by time

# ─── CIC-IDS Flow Window ─────────────────────────────────
# Per-IP sliding window for CIC-IDS-2017 flow feature approximation
FLOW_WINDOW = 10.0   # seconds — typical flow duration
# Stores (timestamp, packet_size, dst_port, syn_flag, psh_flag, ack_flag, tcp_win)
flow_data_by_ip = defaultdict(lambda: deque())

# ─── ICMP Ping Flood tracker (rule-based, per external IP) ─
# Fires a HIGH alert if ≥ ICMP_FLOOD_THRESHOLD pings arrive within ICMP_FLOOD_WINDOW seconds
ICMP_FLOOD_THRESHOLD = 5      # pings to trigger flood alert record
ICMP_FLOOD_WINDOW    = 10.0   # wider window — Windows ping = 1/sec
icmp_times_by_ip     = defaultdict(lambda: deque())   # unbounded – we prune manually
icmp_flood_alerted   = {}     # src_ip -> last alert epoch

# ─── Per-IP ML alert throttle ─────────────────────────────────
ML_ALERT_COOLDOWN = 0.5    # seconds between ML alerts for the same source IP
ml_alerted_by_ip  = {}     # src_ip -> last ML alert epoch

# ─── Per-IP severity state (hysteresis) ──────────────────────────
IP_SEVERITY_DECAY  = 2.0   # seconds before severity level can drop
ip_severity_state  = {}    # src_ip -> {"severity": str, "updated_at": float}
SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

# ─── Diagnostic counter ───────────────────────────────────
_packet_count = 0
_last_diag    = 0


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LOCAL_IP = get_local_ip()


# ─── Load model + feature config ─────────────────────────
def load_model():
    if not os.path.exists(MODEL_FILE) or not os.path.exists(SCALER_FILE):
        print("="*60)
        print("[CRITICAL ERROR] ML model files not found!")
        print(f"Please ensure both model.pkl and scaler.pkl exist in: {BASE_DIR}")
        print("To train the model, run: python ml_model/train_model.py")
        print("="*60)
        time.sleep(10) # Keep window open so user can read error
        sys.exit(1)
    with open(MODEL_FILE, "rb") as f:
        model = pickle.load(f)
    with open(SCALER_FILE, "rb") as f:
        scaler = pickle.load(f)

    # Load feature config (tells us which feature set to use)
    feature_config = {"mode": "synthetic", "features": ["packet_size", "protocol_enc", "packet_rate"], "n_features": 3}
    if os.path.exists(FEATURE_CFG):
        try:
            with open(FEATURE_CFG, "rb") as f:
                feature_config = pickle.load(f)
        except Exception:
            pass

    print(f"[OK] ML model loaded from {MODEL_FILE}")
    print(f"[OK] Feature mode: {feature_config['mode'].upper()} ({feature_config['n_features']} features)")
    if feature_config["mode"] == "cicids2017":
        print(f"[OK] Features: {', '.join(feature_config['features'][:5])}... (+{len(feature_config['features'])-5} more)")
    return model, scaler, feature_config


# ─── Alert UDP sender ─────────────────────────────────────
UDP_IP = "127.0.0.1"
UDP_PORT = 9999
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def save_alert(alert_data):
    """Sends the alert to the Correlator via UDP instead of writing to disk."""
    try:
        udp_sock.sendto(json.dumps(alert_data).encode("utf-8"), (UDP_IP, UDP_PORT))
    except Exception as e:
        print(f"[ML_DETECT] Error sending to Correlator: {e}")

def send_tick(src_ip, severity):
    """Send a lightweight packet tick to the correlator for total packet counting."""
    try:
        udp_sock.sendto(
            json.dumps({"type": "PACKET_TICK", "severity": severity, "src_ip": src_ip}).encode(),
            (UDP_IP, UDP_PORT)
        )
    except Exception:
        pass


def get_severity(src_ip, packet_rate, packet_size, now):
    """
    Rule-based severity using BOTH packet size and rate:

      HIGH   : rate > 20 pkt/s  OR  packet_size > 5000 bytes
               (rapid flood, or large-payload attack)
      MEDIUM : rate > 5  pkt/s  OR  packet_size > 500  bytes
               (moderate scan, or oversized packets)
      LOW    : rate ≤ 5  pkt/s  AND packet_size ≤ 500  bytes
               (slow, small — light probing)

    Hysteresis: severity escalates instantly, but can only
    drop after IP_SEVERITY_DECAY seconds of sustained lower activity.
    """
    # Instantaneous classification
    if packet_rate > 20 or packet_size > 5000:
        instant = "HIGH"
    elif packet_rate > 5 or packet_size > 500:
        instant = "MEDIUM"
    else:
        instant = "LOW"

    # Hysteresis state machine
    state   = ip_severity_state.get(src_ip, {"severity": "LOW", "updated_at": 0})
    current = state["severity"]

    if SEV_ORDER[instant] >= SEV_ORDER[current]:
        ip_severity_state[src_ip] = {"severity": instant, "updated_at": now}
        return instant

    if now - state["updated_at"] > IP_SEVERITY_DECAY:
        ip_severity_state[src_ip] = {"severity": instant, "updated_at": now}
        return instant

    return current  # hold current higher severity


# ─── CIC-IDS-2017 Flow Feature Extraction ────────────────
def extract_cicids_features(src_ip, packet_size, dst_port, syn, psh, ack, tcp_win, now):
    """
    Extracts 15 CIC-IDS-2017-compatible features from a per-IP
    sliding window. These match the features used during training.

    Returns a numpy array of shape (1, 15).
    """
    q = flow_data_by_ip[src_ip]
    q.append((now, packet_size, dst_port, syn, psh, ack, tcp_win))

    # Prune old entries outside the flow window
    while q and now - q[0][0] > FLOW_WINDOW:
        q.popleft()

    # Extract window stats
    timestamps = [e[0] for e in q]
    sizes      = [e[1] for e in q]
    ports      = [e[2] for e in q]
    syns       = [e[3] for e in q]
    pshs       = [e[4] for e in q]
    acks       = [e[5] for e in q]
    wins       = [e[6] for e in q]

    n = len(q)
    duration_ms = (timestamps[-1] - timestamps[0]) * 1e6 if n > 1 else 0  # microseconds (CIC-IDS uses μs)
    duration_s  = duration_ms / 1e6 if duration_ms > 0 else 0.001

    # Inter-arrival times
    iats = []
    for i in range(1, len(timestamps)):
        iats.append((timestamps[i] - timestamps[i-1]) * 1e6)  # microseconds

    # Feature vector (must match CICIDS_FEATURES order in train_model.py):
    # 1.  Destination Port
    # 2.  Flow Duration (microseconds)
    # 3.  Total Fwd Packets
    # 4.  Total Length of Fwd Packets
    # 5.  Fwd Packet Length Max
    # 6.  Fwd Packet Length Mean
    # 7.  Fwd Packet Length Std
    # 8.  Flow Bytes/s
    # 9.  Flow Packets/s
    # 10. Fwd IAT Mean (microseconds)
    # 11. Average Packet Size
    # 12. SYN Flag Count
    # 13. PSH Flag Count
    # 14. ACK Flag Count
    # 15. Init_Win_bytes_forward

    features = np.array([[
        float(dst_port),                                          # Destination Port
        float(duration_ms),                                       # Flow Duration
        float(n),                                                 # Total Fwd Packets
        float(sum(sizes)),                                        # Total Length of Fwd Packets
        float(max(sizes)),                                        # Fwd Packet Length Max
        float(np.mean(sizes)),                                    # Fwd Packet Length Mean
        float(np.std(sizes)) if n > 1 else 0.0,                  # Fwd Packet Length Std
        float(sum(sizes) / duration_s) if duration_s > 0 else 0,  # Flow Bytes/s
        float(n / duration_s) if duration_s > 0 else 0,           # Flow Packets/s
        float(np.mean(iats)) if iats else 0.0,                   # Fwd IAT Mean
        float(np.mean(sizes)),                                    # Average Packet Size
        float(sum(syns)),                                         # SYN Flag Count
        float(sum(pshs)),                                         # PSH Flag Count
        float(sum(acks)),                                         # ACK Flag Count
        float(wins[0]) if wins else 0.0,                          # Init_Win_bytes_forward
    ]])

    return features


# ─── ICMP Ping Flood rule-based detector ─────────────────
def check_icmp_flood(src_ip, dst_ip, packet_size, now):
    """
    Tracks ICMP echo (type 8) packets per source IP.
    Fires a HIGH alert if ≥ ICMP_FLOOD_THRESHOLD pings arrive
    within ICMP_FLOOD_WINDOW seconds.
    Throttled: at most one alert per source IP every 10 seconds.
    Returns True if an alert was fired (so ML engine can skip this packet).
    """
    q = icmp_times_by_ip[src_ip]
    q.append(now)

    # Prune timestamps older than the window
    while q and now - q[0] > ICMP_FLOOD_WINDOW:
        q.popleft()

    count = len(q)

    # ── Severity purely by packet size (user-controllable via -l flag) ──
    # HIGH   : packet_size > 1000  (ping -l 1000 → 1028 bytes)
    # MEDIUM : packet_size > 200   (ping -l 200  → 228 bytes)
    # LOW    : packet_size ≤ 200   (default ping → 74 bytes)
    if packet_size > 1000:
        sev = "HIGH"
    elif packet_size > 200:
        sev = "MEDIUM"
    else:
        sev = "LOW"

    # Tick for EVERY ping — count and severity are both correct
    send_tick(src_ip, sev)

    # Full flood alert record only when enough pings accumulate
    if count < ICMP_FLOOD_THRESHOLD:
        return True  # below flood threshold — no alert record yet, block ML

    # Alert record throttled to 0.5s
    last = icmp_flood_alerted.get(src_ip, 0)
    if now - last < 0.5:
        return True  # tick sent, skip duplicate alert record
    icmp_flood_alerted[src_ip] = now

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ping_rate  = round(count / ICMP_FLOOD_WINDOW, 2)

    # Dynamic confidence: scales with how far above threshold the count is
    # e.g. 5 pings (threshold) = 70%, 10 pings = ~85%, 20+ pings = 98%
    excess_ratio = min((count - ICMP_FLOOD_THRESHOLD) / ICMP_FLOOD_THRESHOLD, 1.0)
    confidence   = round(70.0 + excess_ratio * 28.0, 1)  # 70% → 98%

    alert = {
        "id":          int(now * 1000),
        "timestamp":   timestamp,
        "type":        "ICMP_PING_FLOOD",
        "severity":    "HIGH",
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "protocol":    "ICMP",
        "packet_size": 0,
        "packet_rate": ping_rate,
        "confidence":  confidence,
        "message":     f"[!] ICMP Ping Flood from {src_ip} ({count} pings/{ICMP_FLOOD_WINDOW}s)",
    }

    save_alert(alert)
    threading.Thread(target=send_email_alert, args=(alert,)).start()

    print(
        f"[! ICMP FLOOD] {timestamp} | [HIGH] HIGH | "
        f"ICMP | Rate={ping_rate:.1f} pkt/s | "
        f"{src_ip} -> {dst_ip} | {count} pings in {ICMP_FLOOD_WINDOW}s"
    )
    return True


# ─── Packet callback ──────────────────────────────────────
def make_detector(model, scaler, feature_config):

    feature_mode = feature_config["mode"]

    def detect_packet(packet):
        global _packet_count, _last_diag
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # ── Diagnostic: print packet count every 30 seconds ──
        _packet_count += 1
        now_diag = time.time()
        if now_diag - _last_diag >= 30:
            mode_label = "CIC-IDS" if feature_mode == "cicids2017" else "SYNTH"
            print(f"[ML/{mode_label}] Alive — {_packet_count} IP packets seen so far (local_ip={LOCAL_IP})")
            _last_diag = now_diag

        # ── Filter ALL background noise ─────────────────────
        # 1) Full multicast range 224.0.0.0 – 239.255.255.255
        first_octet = int(dst_ip.split(".")[0])
        if 224 <= first_octet <= 239:
            return
        # 2) Broadcast
        if dst_ip == "255.255.255.255" or dst_ip.endswith(".255"):
            return
        # 3) Loopback / link-local
        if dst_ip.startswith("127.") or dst_ip.startswith("169.254."):
            return

        # ── Filter own non-ICMP traffic ───────────────────
        # Allow ICMP from self (self-pings) but block TCP/UDP from self
        # (browser, OS services, etc. are not attacks)
        if src_ip == LOCAL_IP and not packet.haslayer(ICMP):
            return

        # ── Ignore normal web traffic ─────────────────────
        if packet.haslayer(TCP):
            if packet[TCP].dport in (80, 443) or packet[TCP].sport in (80, 443):
                return
        if packet.haslayer(UDP):
            if packet[UDP].dport in (80, 443, 1900, 5353) or \
               packet[UDP].sport in (80, 443, 1900, 5353):
                return

        # ── Protocol string ───────────────────────────────
        if packet.haslayer(TCP):
            protocol_str = "TCP"
        elif packet.haslayer(UDP):
            protocol_str = "UDP"
        elif packet.haslayer(ICMP):
            protocol_str = "ICMP"
        else:
            protocol_str = "Other"

        packet_size  = len(packet)
        protocol_enc = PROTO_MAP.get(protocol_str, 3)

        # ── ICMP: always handled by rule-based detector, never by ML ──
        now = time.time()
        if packet.haslayer(ICMP):
            if packet[ICMP].type == 8:   # Echo Request only
                # Deduplicate self-pings: when pinging own IP, Scapy sees
                # the same echo request twice. Skip the second one.
                seq_id = packet[ICMP].seq if hasattr(packet[ICMP], 'seq') else 0
                dedup_key = (src_ip, dst_ip, seq_id)
                if hasattr(detect_packet, '_seen_icmp'):
                    if detect_packet._seen_icmp.get(dedup_key, 0) > now - 2:
                        return  # duplicate — skip
                else:
                    detect_packet._seen_icmp = {}
                detect_packet._seen_icmp[dedup_key] = now
                # Prune old entries (keep last 2 seconds only)
                detect_packet._seen_icmp = {
                    k: v for k, v in detect_packet._seen_icmp.items()
                    if v > now - 2
                }
                check_icmp_flood(src_ip, dst_ip, packet_size, now)
            return  # All ICMP exits here — ML skipped

        # ── Feature extraction depends on model mode ──────
        if feature_mode == "cicids2017":
            # ── CIC-IDS-2017 MODE: 15 flow-level features ──
            # Extract TCP flags and window size
            dst_port = 0
            syn_flag = 0
            psh_flag = 0
            ack_flag = 0
            tcp_win  = 0

            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                syn_flag = 1 if flags & 0x02 else 0  # SYN
                psh_flag = 1 if flags & 0x08 else 0  # PSH
                ack_flag = 1 if flags & 0x10 else 0  # ACK
                tcp_win  = packet[TCP].window
            elif packet.haslayer(UDP):
                dst_port = packet[UDP].dport

            features_scaled = scaler.transform(
                extract_cicids_features(src_ip, packet_size, dst_port, syn_flag, psh_flag, ack_flag, tcp_win, now)
            )

            # Also track packet rate for severity calculation
            ip_queue = packet_times_by_ip[src_ip]
            ip_queue.append(now)
            while ip_queue and now - ip_queue[0] > RATE_WINDOW:
                ip_queue.popleft()
            packet_rate = len(ip_queue)

        else:
            # ── SYNTHETIC MODE: 3 basic features ────────────
            ip_queue = packet_times_by_ip[src_ip]
            ip_queue.append(now)
            while ip_queue and now - ip_queue[0] > RATE_WINDOW:
                ip_queue.popleft()
            packet_rate = len(ip_queue)

            features        = np.array([[packet_size, protocol_enc, packet_rate]])
            features_scaled = scaler.transform(features)

        # ── ML prediction ─────────────────────────────────
        prediction      = model.predict(features_scaled)[0]
        confidence_arr  = model.predict_proba(features_scaled)[0]
        raw_conf = float(np.max(confidence_arr)) * 100
        conf_val = round(max(60.0, min(97.0, raw_conf)), 1)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if prediction == 1:  # ML says anomaly — tick + full alert
            # ── Size-based severity (deterministic, user-controllable) ──
            # LOW    = small packets (≤100B)  — SYN packets, probes
            # MEDIUM = medium packets (≤1000B) — ping -l 200, HTTP requests
            # HIGH   = large packets (>1000B)  — ping -l 1000, data floods
            if packet_size > 1000:
                severity = "HIGH"
            elif packet_size > 100:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            send_tick(src_ip, severity)

            # Per-IP cooldown: tick every packet, full alert record every 0.5s
            last_ml = ml_alerted_by_ip.get(src_ip, 0)
            if now - last_ml < ML_ALERT_COOLDOWN:
                return
            ml_alerted_by_ip[src_ip] = now

            mode_tag = "CIC-IDS" if feature_mode == "cicids2017" else "ML"
            alert = {
                "id":          int(time.time() * 1000),
                "timestamp":   timestamp,
                "type":        "ML_ANOMALY",
                "severity":    severity,
                "src_ip":      src_ip,
                "dst_ip":      dst_ip,
                "protocol":    protocol_str,
                "packet_size": packet_size,
                "packet_rate": round(packet_rate, 2),
                "confidence":  round(conf_val, 1),
                "message":     f"Anomalous {protocol_str} traffic from {src_ip} (size={packet_size}B, model={mode_tag})",
            }

            save_alert(alert)
            threading.Thread(target=send_email_alert, args=(alert,)).start()

            sev_icon = {"HIGH": "[!]", "MEDIUM": "[-]", "LOW": "[i]"}.get(severity, "[?]")
            print(
                f"[! {mode_tag}]  {timestamp} | {sev_icon} {severity} | "
                f"{protocol_str} | Size={packet_size}B Rate={packet_rate}/s | "
                f"{src_ip} -> {dst_ip}"
            )



    return detect_packet


# ─── Start detection ──────────────────────────────────────
def start_detection(interface=None):
    model, scaler, feature_config = load_model()
    callback = make_detector(model, scaler, feature_config)

    mode_label = "CIC-IDS-2017" if feature_config["mode"] == "cicids2017" else "Synthetic"

    print("=" * 70)
    print(f"  ML Anomaly Engine — IDS_Snort_Project")
    print(f"  Model: {mode_label} ({feature_config['n_features']} features)")
    print("=" * 70)
    print(f"  Local IP filter : ignoring {LOCAL_IP} and 127.0.0.1")
    print(f"  Alerts file     : {ALERTS_FILE}")
    print("  Press Ctrl+C to stop")
    print("=" * 70)

    try:
        while True:
            sniff(prn=callback, iface=interface, store=False)
    except KeyboardInterrupt:
        print("\n[ML] Stopped by user.")
    except PermissionError:
        print("\n[ERROR] Permission denied — run as Administrator.")


if __name__ == "__main__":
    start_detection()
