"""
=============================================================
correlator/correlator.py  —  IDS_Snort_Project
=============================================================
Alert Correlator Middleman

Listens on UDP 9999 for alerts from both Snort and ML engines.
If it sees an alert from BOTH engines for the SAME source IP 
within a 2-second window, it deduplicates and merges them 
into a single "CORRELATED_ATTACK" alert with 99% confidence.

Writes the final deduplicated alert feed to alerts/alerts.json
for the dashboard to consume.
=============================================================
"""

import os
import sys
import json
import time
import socket
import threading
from collections import deque
from datetime import datetime

# Windows system beep (stdlib, no pip install needed)
try:
    import winsound as _winsound
    _HAS_WINSOUND = True
except ImportError:
    _HAS_WINSOUND = False   # non-Windows OS — beeps silently skipped

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from email_alert.send_alert import send_email_alert
from blockchain.blockchain import AttackerBlockchain
from telegram_alert.telegram_bot import send_telegram_in_background

# Shared blockchain ledger instance (thread-safe internally)
_blockchain = AttackerBlockchain()

ALERTS_JSON = os.path.join(BASE_DIR, "alerts", "alerts.json")
COUNT_JSON  = os.path.join(BASE_DIR, "alerts", "count.json")
UDP_IP = "0.0.0.0"
UDP_PORT = 9999
CORRELATION_WINDOW = 0.5  # seconds
DEDUP_WINDOW       = 2.0  # seconds — suppress near-identical alerts from same IP+engine+severity

lock = threading.Lock()
alerts_list: deque = deque(maxlen=500)   # O(1) left-eviction when full
ip_cache    = {}
dedup_cache = {}   # (src_ip, engine, severity, protocol) -> last_time
# Per-severity packet tick counters — all four dashboard numbers derive from these
tick_high   = 0
tick_medium = 0
tick_low    = 0


def _sound_alert(alert_type: str) -> None:
    """
    Play a system beep on the monitoring PC using winsound (Windows only).
    Runs in a daemon thread so the UDP listener is never blocked.

    alert_type:
        'correlated' — 3 rapid high-pitched beeps (most critical)
        'high'       — single long beep
        'medium'     — single short soft beep
    """
    if not _HAS_WINSOUND:
        return

    def _beep():
        try:
            if alert_type == 'correlated':
                for freq in (1200, 1000, 800):          # descending urgent triple beep
                    _winsound.Beep(freq, 180)
                    time.sleep(0.05)
            elif alert_type == 'high':
                _winsound.Beep(880, 350)                # single urgent beep
            elif alert_type == 'medium':
                _winsound.Beep(600, 150)                # soft notification beep
        except Exception:
            pass

    threading.Thread(target=_beep, daemon=True).start()


def _flag_watcher():
    """Background thread: watches for clear.flag and clears state when found."""
    flag_path = os.path.join(BASE_DIR, "alerts", "clear.flag")
    while True:
        if os.path.exists(flag_path):
            try:
                os.remove(flag_path)
            except OSError:
                pass
            with lock:
                global tick_high, tick_medium, tick_low
                alerts_list.clear()
                ip_cache.clear()
                dedup_cache.clear()
                tick_high = tick_medium = tick_low = 0
                save_alerts()
            print("[CORRELATOR] Alert list cleared via dashboard.")
        time.sleep(0.5)


def load_alerts():
    global alerts_list
    if os.path.exists(ALERTS_JSON):
        try:
            with open(ALERTS_JSON, "r") as f:
                raw = json.load(f)
            # Strip any stale HEARTBEAT entries persisted before the filter was added
            alerts_list = [a for a in raw if a.get("type") != "HEARTBEAT"]
        except Exception:
            alerts_list = []
    else:
        alerts_list = []


def save_alerts():
    try:
        os.makedirs(os.path.dirname(ALERTS_JSON), exist_ok=True)
        temp = ALERTS_JSON + ".tmp"
        with open(temp, "w") as f:
            json.dump(list(alerts_list), f)    # cast deque → list for JSON serialization
        os.replace(temp, ALERTS_JSON)
    except Exception as e:
        print(f"[CORRELATOR] Warning: could not save alerts: {e}")
    # Also update the tiny count file for fast dashboard stats reads
    save_count()


def save_count():
    """Write a tiny JSON with consistent counts derived directly from active alerts."""
    try:
        high = sum(1 for a in alerts_list if a.get("severity") == "HIGH")
        medium = sum(1 for a in alerts_list if a.get("severity") == "MEDIUM")
        low = sum(1 for a in alerts_list if a.get("severity") == "LOW")
        total = len(alerts_list)

        # Build protocol distribution from current alerts
        protocols = {}
        for a in alerts_list:
            p = a.get("protocol", "Unknown")
            protocols[p] = protocols.get(p, 0) + 1
        counts = {
            "total":  total,
            "high":   high,
            "medium": medium,
            "low":    low,
            "avg_confidence": round(
                sum(a.get("confidence", 0) for a in alerts_list) / max(len(alerts_list), 1), 1
            ),
            "protocols": protocols,
        }
        temp = COUNT_JSON + ".tmp"
        with open(temp, "w") as f:
            json.dump(counts, f)
        os.replace(temp, COUNT_JSON)
    except Exception:
        pass


def process_alert(new_alert):
    global alerts_list, tick_high, tick_medium, tick_low

    # Drop HEARTBEAT pings — they are status signals, not attack alerts
    if new_alert.get("type") == "HEARTBEAT":
        return

    # Handle lightweight packet ticks — just count by severity, no alert record needed
    if new_alert.get("type") == "PACKET_TICK":
        sev = new_alert.get("severity", "LOW")
        with lock:
            if sev == "HIGH":
                tick_high += 1
            elif sev == "MEDIUM":
                tick_medium += 1
            else:
                tick_low += 1
        save_count()   # tiny file write, very fast
        return

    src_ip = new_alert.get("src_ip", "0.0.0.0")
    engine = new_alert.get("type", "UNKNOWN")
    now    = time.time()

    # Auto-assign timestamp if missing — prevents sorting failures in dashboard
    if not new_alert.get("timestamp"):
        new_alert["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with lock:
        cache = ip_cache.get(src_ip, {})
        other_engine = "ML_ANOMALY" if engine == "SNORT_SIGNATURE" else "SNORT_SIGNATURE"
        
        # Deduplication: drop if same engine already fired for this IP within the window
        if engine in cache:
            if now - cache[engine]["time"] < CORRELATION_WINDOW:
                return  # Too soon — drop duplicate

        # Content-based dedup: suppress near-identical alerts
        # (same src_ip + engine + severity + protocol) within DEDUP_WINDOW
        sev   = new_alert.get("severity", "LOW")
        proto = new_alert.get("protocol", "")
        dedup_key = (src_ip, engine, sev, proto)
        last_dedup = dedup_cache.get(dedup_key, 0)
        if now - last_dedup < DEDUP_WINDOW:
            return  # near-identical alert suppressed
        dedup_cache[dedup_key] = now
        
        # 2. Check for correlation within 2 seconds
        if other_engine in cache:
            time_diff = now - cache[other_engine]["time"]
            
            if time_diff <= CORRELATION_WINDOW:
                # MATCH! Merge them.
                orig_alert = cache[other_engine]["ref"]
                
                # We only upgrade if it hasn't already been correlated
                if orig_alert.get("type") != "CORRELATED_ATTACK":
                    orig_alert["type"] = "CORRELATED_ATTACK"
                    orig_alert["severity"] = "HIGH"
                    orig_alert["confidence"] = 99.0
                    orig_alert["message"] = f"[!] CORRELATED ATTACK: Signature + Anomaly match for {src_ip}"
                    
                    # Update cache to point to the merged alert and reset timer
                    ip_cache[src_ip] = {
                        engine: {"time": now, "ref": orig_alert},
                        other_engine: {"time": now, "ref": orig_alert}
                    }
                    
                    save_alerts()
                    print(f"[! CORRELATOR] MATCH FOUND! Merged {src_ip} into CORRELATED_ATTACK (Diff: {time_diff:.2f}s)")

                    _sound_alert('correlated')   # 3 rapid beeps on monitoring PC

                    # Commit correlated attack permanently to blockchain
                    threading.Thread(
                        target=_blockchain.add_block,
                        args=(dict(orig_alert),),
                        daemon=True,
                    ).start()

                    # Trigger email for correlated attack
                    threading.Thread(target=send_email_alert, args=(orig_alert,)).start()

                    # Telegram real-time alert (non-blocking)
                    send_telegram_in_background(orig_alert)
                return

        # 3. No match found within window. Add as separate alert.
        alerts_list.append(new_alert)
        # deque(maxlen=500) auto-evicts oldest entry — no manual size check needed

        ip_cache[src_ip] = cache
        ip_cache[src_ip][engine] = {"time": now, "ref": new_alert}

        # Increment severity counters so dashboard stats stay accurate
        sev = new_alert.get("severity", "LOW")
        if   sev == "HIGH":   tick_high   += 1
        elif sev == "MEDIUM": tick_medium += 1
        else:                 tick_low    += 1

        save_alerts()

        # Server-side beep for HIGH / MEDIUM alerts
        if   sev == "HIGH":   _sound_alert('high')
        elif sev == "MEDIUM": _sound_alert('medium')

        # Commit every new alert permanently to the blockchain ledger
        threading.Thread(
            target=_blockchain.add_block,
            args=(dict(new_alert),),
            daemon=True,
        ).start()

        # Telegram real-time alert for HIGH/MEDIUM (non-blocking, rate-limited per IP)
        send_telegram_in_background(new_alert)


def start_correlator():
    load_alerts()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    # Start background flag-watcher thread
    watcher = threading.Thread(target=_flag_watcher, daemon=True)
    watcher.start()
    
    print("=" * 70)
    print("  Alert Correlator Engine — IDS_Snort_Project")
    print("=" * 70)
    print(f"  Listening on  : UDP {UDP_IP}:{UDP_PORT}")
    print(f"  Time Window   : {CORRELATION_WINDOW} seconds")
    print(f"  Output File   : {ALERTS_JSON}")
    print("  Press Ctrl+C to stop")
    print("=" * 70)

    try:
        while True:
            data, addr = sock.recvfrom(65535)
            try:
                alert = json.loads(data.decode("utf-8"))
                process_alert(alert)
            except json.JSONDecodeError:
                pass
            except Exception as e:
                print(f"[CORRELATOR] Error processing alert: {e}")
    except KeyboardInterrupt:
        print("\n[CORRELATOR] Stopped by user.")
    finally:
        sock.close()


if __name__ == "__main__":
    start_correlator()
