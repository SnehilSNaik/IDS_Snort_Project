"""
=============================================================
start_ids.py  —  IDS_Snort_Project Launcher
=============================================================
Starts the Flask Dashboard directly.
All other components (Snort, ML, Correlator, ARP monitor,
DNS monitor) are launched via the 'Engage IDS Engine'
button in the web dashboard UI.

API keys are loaded automatically from .env in the project
root — no manual environment variable setup needed.
=============================================================
"""

import os
import sys
import subprocess
import socket

BASE             = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_SCRIPT = os.path.join(BASE, "dashboard", "app.py")
ENV_FILE         = os.path.join(BASE, ".env")


# ── Load .env automatically ───────────────────────────────────
def load_env(path: str):
    """
    Simple .env loader — reads KEY=VALUE lines and injects them
    into os.environ if not already set.
    Lines starting with # and blank lines are ignored.
    """
    if not os.path.exists(path):
        return
    loaded = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key   = key.strip()
            value = value.strip()
            if key and value and key not in os.environ:
                os.environ[key] = value
                loaded.append(key)
    if loaded:
        print(f"   [ENV]  Loaded from .env: {', '.join(loaded)}")


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

    # Show which TI sources are active
    ti_sources = []
    if os.environ.get("IPINFO_KEY"):
        ti_sources.append("ipinfo.io [OK]")
    ti_str = "  |  ".join(ti_sources) if ti_sources else "None (TI disabled)"

    print("\n" + "=" * 62)
    print("   ___  ____  ____     ____  _  _  __  ____  ____ ")
    print("  (  _)(  _ \\/ ___)   / ___)( \\/ )/  \\(  _ \\(_  _)")
    print("   ) _) )   /\\___ \\   \\___ \\ )  /(  O ))   /  )(  ")
    print("  (___)(__)  (____/   (____/(__/  \\__/(__\\_) (__) ")
    print()
    print("   IDS_Snort_Project  —  Advanced Hybrid IDS")
    print("=" * 62)
    print(f"   [TARGET IP]  Tell attacker to target: {ip}")
    print(f"   [THREAT INTEL] {ti_str}")
    print("=" * 62)
    print("   [INFO] Starting Web Dashboard...")
    print("   [INFO] Open your browser to: http://localhost:5000")
    print("=" * 62 + "\n")


def main():
    # 1. Load .env (must be BEFORE banner so TI status shows correctly)
    load_env(ENV_FILE)

    # 2. Show banner
    banner()

    # 3. Launch dashboard (all engines start from the UI)
    try:
        subprocess.run(
            [sys.executable, DASHBOARD_SCRIPT],
            cwd=BASE,
            env=os.environ,   # pass loaded .env vars to child process
        )
    except KeyboardInterrupt:
        print("\n  Goodbye.\n")


if __name__ == "__main__":
    main()
