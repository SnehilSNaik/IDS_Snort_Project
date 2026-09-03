"""
=============================================================
ml_model/autoencoder.py  —  IDS_Snort_Project
=============================================================
LSTM Autoencoder live inference engine.

Runs alongside detect.py (Random Forest).
Sniffs live packets, builds 20-packet sequences per source IP,
computes reconstruction error via the trained LSTM Autoencoder,
and fires LSTM_ANOMALY alerts to the Correlator (UDP 9999).

Usage:
  python ml_model/autoencoder.py

Prerequisites:
  python ml_model/train_autoencoder.py  (run once first)
=============================================================
"""

import os
import sys
import json
import pickle
import time
import socket
import threading
import numpy as np
from datetime import datetime
from collections import deque, defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(BASE_DIR))

MODEL_PATH     = os.path.join(BASE_DIR, "autoencoder_model.keras")
SCALER_PATH    = os.path.join(BASE_DIR, "autoencoder_scaler.pkl")
THRESHOLD_PATH = os.path.join(BASE_DIR, "autoencoder_threshold.pkl")

SEQ_LEN    = 20
N_FEATURES = 15

# ── UDP sender (Correlator) ───────────────────────────────
UDP_IP   = "127.0.0.1"
UDP_PORT = 9999
_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# ── Per-IP cooldown ───────────────────────────────────────
AE_ALERT_COOLDOWN = 1.0   # seconds between LSTM alerts per IP
ae_alerted_by_ip  = {}    # src_ip -> last alert epoch

# ── Per-IP feature sliding window ─────────────────────────
# Stores tuples: (timestamp, packet_size, dst_port, syn, psh, ack, tcp_win)
flow_data_by_ip = defaultdict(lambda: deque(maxlen=SEQ_LEN + 5))
FLOW_WINDOW = 10.0

PROTO_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "Other": 3}


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


def send_alert(alert: dict):
    try:
        _udp_sock.sendto(json.dumps(alert).encode(), (UDP_IP, UDP_PORT))
    except Exception as e:
        print(f"[AE] UDP send error: {e}")


def load_artefacts():
    """Load Keras model, scaler, and anomaly threshold."""
    if not os.path.exists(MODEL_PATH):
        print(f"[AE][ERROR] autoencoder_model.keras not found at {MODEL_PATH}")
        print("  Run:  python ml_model/train_autoencoder.py  first.")
        sys.exit(1)

    # Suppress TF noise
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
    import logging
    logging.getLogger("tensorflow").setLevel(logging.ERROR)

    import tensorflow as tf
    tf.get_logger().setLevel("ERROR")
    model = tf.keras.models.load_model(MODEL_PATH)

    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    with open(THRESHOLD_PATH, "rb") as f:
        threshold = pickle.load(f)

    print(f"[AE][OK] LSTM Autoencoder loaded from {MODEL_PATH}")
    print(f"[AE][OK] Anomaly MSE threshold = {threshold:.6f}")
    return model, scaler, float(threshold)


def extract_features(src_ip: str, packet_size: int, dst_port: int,
                     syn: int, psh: int, ack: int, tcp_win: int, now: float) -> np.ndarray | None:
    """
    Maintain a per-IP sliding window of recent packets.
    Returns a (1, SEQ_LEN, N_FEATURES) numpy array when the window is full,
    else None.
    """
    q = flow_data_by_ip[src_ip]
    q.append((now, packet_size, dst_port, syn, psh, ack, tcp_win))

    # Prune old entries
    while q and now - q[0][0] > FLOW_WINDOW:
        q.popleft()

    if len(q) < SEQ_LEN:
        return None   # Not enough data yet

    # Use the most recent SEQ_LEN packets
    window = list(q)[-SEQ_LEN:]
    rows = []
    for (ts, pkt_sz, dport, s, p, a, w) in window:
        rows.append([
            float(dport),
            float(ts - window[0][0]) * 1e6,   # Flow Duration (μs)
            float(len(window)),                # Total Fwd Packets (approx)
            float(pkt_sz),
            float(pkt_sz),                    # Max (within single packet context)
            float(pkt_sz),                    # Mean (single packet)
            0.0,                              # Std
            float(pkt_sz / max(ts - window[0][0], 0.001)),  # Bytes/s
            float(len(window) / max(ts - window[0][0], 0.001)),
            0.0,                              # IAT Mean (simplified)
            float(pkt_sz),                    # Avg Packet Size
            float(s),                         # SYN count
            float(p),                         # PSH count
            float(a),                         # ACK count
            float(w),                         # TCP Win
        ])
    return np.array([rows], dtype=np.float32)  # (1, SEQ_LEN, N_FEATURES)


def start_detection():
    import logging as _log
    _log.getLogger("scapy.runtime").setLevel(_log.ERROR)
    from scapy.all import sniff, IP, TCP, UDP, ICMP

    model, scaler, threshold = load_artefacts()

    # Wrap model.predict in a threading lock to be safe
    _lock = threading.Lock()
    _pkt_count = [0]
    _last_diag = [time.time()]

    def detect_packet(packet):
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        now    = time.time()

        # Diagnostics
        _pkt_count[0] += 1
        if now - _last_diag[0] >= 30:
            print(f"[AE] Alive — {_pkt_count[0]} packets seen. Local IP={LOCAL_IP}")
            _last_diag[0] = now

        # Filter noise
        first_oct = int(dst_ip.split(".")[0])
        if 224 <= first_oct <= 239:                   return
        if dst_ip.endswith(".255"):                   return
        if dst_ip.startswith("127.") or dst_ip.startswith("169.254."): return
        if src_ip == LOCAL_IP and not packet.haslayer(ICMP): return

        # Skip common web traffic
        if packet.haslayer(TCP):
            if packet[TCP].dport in (80, 443) or packet[TCP].sport in (80, 443):
                return
        if packet.haslayer(UDP):
            if packet[UDP].dport in (80, 443, 1900, 5353):
                return

        # Extract fields
        dst_port = syn_flag = psh_flag = ack_flag = tcp_win = 0
        if packet.haslayer(TCP):
            dst_port  = packet[TCP].dport
            flags     = packet[TCP].flags
            syn_flag  = 1 if flags & 0x02 else 0
            psh_flag  = 1 if flags & 0x08 else 0
            ack_flag  = 1 if flags & 0x10 else 0
            tcp_win   = packet[TCP].window
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport

        if packet.haslayer(ICMP):
            return   # Let detect.py handle ICMP

        packet_size = len(packet)
        seq_data = extract_features(src_ip, packet_size, dst_port,
                                    syn_flag, psh_flag, ack_flag, tcp_win, now)
        if seq_data is None:
            return  # Building window

        # Scale each time-step's features
        flat = seq_data.reshape(-1, N_FEATURES)
        flat_scaled = scaler.transform(flat)
        seq_scaled = flat_scaled.reshape(1, SEQ_LEN, N_FEATURES)

        # LSTM inference
        with _lock:
            reconstruction = model.predict(seq_scaled, verbose=0)

        mse = float(np.mean(np.power(seq_scaled - reconstruction, 2)))

        if mse <= threshold:
            return   # Normal traffic

        # Anomaly detected!
        last_ae = ae_alerted_by_ip.get(src_ip, 0)
        if now - last_ae < AE_ALERT_COOLDOWN:
            return
        ae_alerted_by_ip[src_ip] = now

        # Severity from how far above threshold we are
        ratio = mse / threshold
        if ratio > 5.0:
            severity = "HIGH"
        elif ratio > 2.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Confidence: normalize reconstruction error to 60-99%
        confidence = round(min(99.0, 60.0 + (ratio - 1.0) * 10.0), 1)

        protocol_str = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"

        alert = {
            "id":            int(now * 1000),
            "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type":          "LSTM_ANOMALY",
            "severity":      severity,
            "src_ip":        src_ip,
            "dst_ip":        dst_ip,
            "protocol":      protocol_str,
            "packet_size":   packet_size,
            "packet_rate":   0,
            "confidence":    confidence,
            "message":       (f"[LSTM] Anomalous sequence from {src_ip} "
                              f"(MSE={mse:.4f}, threshold={threshold:.4f}, ratio={ratio:.1f}x)"),
        }

        send_alert(alert)
        print(
            f"[! LSTM]   {alert['timestamp']} | {severity} | "
            f"{protocol_str} | MSE={mse:.4f} ({ratio:.1f}x) | {src_ip} -> {dst_ip} | {confidence}%"
        )

    print("=" * 70)
    print("  LSTM Autoencoder Anomaly Engine — IDS_Snort_Project")
    print("=" * 70)
    print(f"  Local IP filter : ignoring {LOCAL_IP}")
    print(f"  MSE threshold   : {threshold:.6f}")
    print(f"  Sequence length : {SEQ_LEN} packets")
    print("  Press Ctrl+C to stop")
    print("=" * 70)

    try:
        while True:
            sniff(prn=detect_packet, store=False)
    except KeyboardInterrupt:
        print("\n[AE] Stopped by user.")
    except PermissionError:
        print("\n[ERROR] Permission denied — run as Administrator.")


if __name__ == "__main__":
    start_detection()
