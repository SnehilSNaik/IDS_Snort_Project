"""
=============================================================
start_ids.py  —  IDS_Snort_Project Launcher
=============================================================
Starts the Flask Dashboard directly.
All other components (Snort, ML, Correlator) are launched 
via the 'Engage IDS Engine' button in the web dashboard UI.
=============================================================
"""

import os
import sys
import subprocess
import socket

BASE = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_SCRIPT = os.path.join(BASE, "dashboard", "app.py")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"

def banner():
    ip = get_local_ip()
    print("\n" + "=" * 62)
    print("   ___  ____  ____     ____  _  _  __  ____  ____ ")
    print("  (  _)(  _ \/ ___)   / ___)( \/ )/  \(  _ \(_  _)")
    print("   ) _) )   /\___ \   \___ \ )  /(  O ))   /  )(  ")
    print("  (___)(__)  (____/   (____/(__/  \__/(__\_) (__) ")
    print()
    print("   IDS_Snort_Project — Hybrid IDS with REAL Snort C binary")
    print("=" * 62)
    print(f"   [TARGET IP] Tell attacker to target: {ip}")
    print("=" * 62)
    print("   [INFO] Starting Web Dashboard...")
    print("   [INFO] Open your browser to: http://localhost:5000")
    print("=" * 62 + "\n")

def main():
    banner()
    try:
        # Run dashboard directly in this console
        subprocess.run([sys.executable, DASHBOARD_SCRIPT], cwd=BASE)
    except KeyboardInterrupt:
        print("\n  Goodbye.\n")

if __name__ == "__main__":
    main()
