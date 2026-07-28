"""
=============================================================
start_demo.py  -  IDS_Snort_Project
=============================================================
One-click demo launcher for the HP Monitoring PC.

Automatically:
  1. Detects this machine's local LAN IP
  2. Starts the Correlator (UDP listener on 0.0.0.0:9999)
  3. Starts the Dashboard (web server on 0.0.0.0:5000)
  4. Prints a clear banner with all connection details

Run: python start_demo.py
=============================================================
"""

import os
import sys
import time
import socket
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_local_ip():
    """Auto-detect the machine's local LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def launch(module_name, label):
    """Launch a Python module as a separate subprocess."""
    cmd = [sys.executable, "-m", module_name]
    if os.name == "nt":
        proc = subprocess.Popen(
            cmd,
            cwd=BASE_DIR,
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    else:
        proc = subprocess.Popen(cmd, cwd=BASE_DIR)
    print(f"  [OK] {label} started  (PID {proc.pid})")
    return proc


def main():
    MY_IP = get_local_ip()

    print()
    print("=" * 66)
    print("   IDS Security Command Center  --  Starting Demo")
    print("=" * 66)
    print()

    # Step 1: Start Correlator
    print("  [1/2] Starting Correlator (UDP alert receiver)...")
    correlator_proc = launch("correlator.correlator", "Correlator")
    time.sleep(2)

    # Step 2: Start Dashboard
    print("  [2/2] Starting Dashboard (Web UI)...")
    dashboard_proc = launch("dashboard.app", "Dashboard")
    time.sleep(3)

    # Ready banner
    print()
    print("=" * 66)
    print("   DEMO READY")
    print("=" * 66)
    print()
    print(f"   HP Monitoring PC IP   :  {MY_IP}")
    print()
    print("   --- FOR THE PANEL / AUDIENCE ---")
    print(f"   Dashboard URL          :  http://{MY_IP}:5000")
    print(f"   (Open this on any browser on the same Wi-Fi)")
    print()
    print("   --- FOR EACH VICTIM PC ---")
    print(f"   1. Open victim_agent/agent.py")
    print(f"   2. Set MONITOR_PC_IP = \"{MY_IP}\"")
    print(f"   3. Run: python agent.py")
    print()
    print("   --- FOR THE ATTACKER PC ---")
    print(f"   Attack HP directly:")
    print(f"     python simulate_attacks.py {MY_IP}")
    print()
    print(f"   Attack a Victim PC (replace with victim's IP):")
    print(f"     python simulate_attacks.py 192.168.1.XX")
    print()
    print(f"   HTTP SQL Injection test:")
    print(f"     Open in browser:")
    print(f"     http://{MY_IP}:5000/login?email=admin' OR 1=1--")
    print()
    print("=" * 66)
    print("   Press Ctrl+C to stop all services")
    print("=" * 66)
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  [STOP] Shutting down IDS services...")
        for proc in [correlator_proc, dashboard_proc]:
            try:
                proc.terminate()
            except Exception:
                pass
        print("  [DONE] All services stopped.")


if __name__ == "__main__":
    main()
