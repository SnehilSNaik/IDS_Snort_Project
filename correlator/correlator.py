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

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from email_alert.send_alert import send_email_alert

ALERTS_JSON = os.path.join(BASE_DIR, "alerts", "alerts.json")
COUNT_JSON  = os.path.join(BASE_DIR, "alerts", "count.json")
UDP_IP = "127.0.0.1"
UDP_PORT = 9999
CORRELATION_WINDOW = 0.5  # seconds

lock = threading.Lock()
alerts_list = []
ip_cache    = {}
# Per-severity packet tick counters — all four dashboard numbers derive from these
tick_high   = 0
tick_medium = 0
tick_low    = 0


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
                tick_high = tick_medium = tick_low = 0
                save_alerts()
            print("[CORRELATOR] Alert list cleared via dashboard.")
        time.sleep(0.5)


def load_alerts():
    global alerts_list
    if os.path.exists(ALERTS_JSON):
        try:
            with open(ALERTS_JSON, "r") as f:
                alerts_list = json.load(f)
        except Exception:
            alerts_list = []
    else:
        alerts_list = []


def save_alerts():
    try:
        os.makedirs(os.path.dirname(ALERTS_JSON), exist_ok=True)
        temp = ALERTS_JSON + ".tmp"
        with open(temp, "w") as f:
            json.dump(alerts_list, f)          # no indent = smaller/faster
        os.replace(temp, ALERTS_JSON)
    except Exception as e:
        print(f"[CORRELATOR] Warning: could not save alerts: {e}")
    # Also update the tiny count file for fast dashboard stats reads
    save_count()


def save_count():
    """Write a tiny JSON with consistent counts — all derived from severity ticks."""
    try:
        total = tick_high + tick_medium + tick_low
        counts = {
            "total":  total,
            "high":   tick_high,
            "medium": tick_medium,
            "low":    tick_low,
            "avg_confidence": round(
                sum(a.get("confidence", 0) for a in alerts_list) / max(len(alerts_list), 1), 1
            ),
        }
        temp = COUNT_JSON + ".tmp"
        with open(temp, "w") as f:
            json.dump(counts, f)
        os.replace(temp, COUNT_JSON)
    except Exception:
        pass


def process_alert(new_alert):
    global alerts_list, tick_high, tick_medium, tick_low

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
    
    with lock:
        cache = ip_cache.get(src_ip, {})
        other_engine = "ML_ANOMALY" if engine == "SNORT_SIGNATURE" else "SNORT_SIGNATURE"
        
        # Deduplication: drop if same engine already fired for this IP within the window
        if engine in cache:
            if now - cache[engine]["time"] < CORRELATION_WINDOW:
                return  # Too soon — drop duplicate
        
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
                    
                    # Trigger email for correlated attack
                    threading.Thread(target=send_email_alert, args=(orig_alert,)).start()
                return

        # 3. No match found within window. Add as separate alert.
        alerts_list.append(new_alert)
        if len(alerts_list) > 500:   # keep list small for fast JSON writes
            alerts_list.pop(0)
            
        ip_cache[src_ip] = cache
        ip_cache[src_ip][engine] = {"time": now, "ref": new_alert}
        
        save_alerts()
        
        # We don't trigger emails here. The detection engines trigger their own emails 
        # when they send the UDP packet if they want to. Actually, we should handle it here 
        # so email logic is centralized, but we'll stick to the existing engine logic.


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
