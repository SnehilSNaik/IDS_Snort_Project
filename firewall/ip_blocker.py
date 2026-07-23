"""
=============================================================
firewall/ip_blocker.py  —  IDS_Snort_Project
=============================================================
IP Blocking Manager

Maintains a persistent blocked-IP list in firewall/blocked_ips.json.
Optionally applies Windows Firewall rules via netsh when running
with admin privileges.

Public API:
    blocker = IPBlocker()
    blocker.block_ip(ip, reason, blocked_by)   # add to blocklist
    blocker.unblock_ip(ip)                      # remove from blocklist
    blocker.is_blocked(ip)                      # True / False
    blocker.get_all()                           # list of blocked entries
    blocker.get_stats()                         # summary dict
=============================================================
"""

import json
import os
import subprocess
import threading
from datetime import datetime

BASE_DIR         = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOCKED_IPS_FILE = os.path.join(BASE_DIR, "firewall", "blocked_ips.json")
FIREWALL_RULE_PREFIX = "IDS_BLOCK_"    # prefix for Windows Firewall rule names


class IPBlocker:
    """Thread-safe, persistent IP blocklist with optional OS-level firewall enforcement."""

    def __init__(self):
        self._lock = threading.Lock()
        self._blocked: dict[str, dict] = {}   # ip -> entry dict
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load(self):
        if not os.path.exists(BLOCKED_IPS_FILE):
            self._blocked = {}
            return
        try:
            with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Keyed by IP for O(1) lookup
            self._blocked = {entry["ip"]: entry for entry in data}
            print(f"[FIREWALL] Loaded {len(self._blocked)} blocked IP(s) from disk.")
        except Exception as e:
            print(f"[FIREWALL] Warning: could not load blocked IPs: {e}")
            self._blocked = {}

    def _save(self):
        try:
            os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)
            tmp = BLOCKED_IPS_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(list(self._blocked.values()), f, indent=2)
            os.replace(tmp, BLOCKED_IPS_FILE)
        except Exception as e:
            print(f"[FIREWALL] Warning: could not save blocked IPs: {e}")

    # ------------------------------------------------------------------
    # Windows Firewall integration (best-effort, requires admin)
    # ------------------------------------------------------------------
    @staticmethod
    def _apply_firewall_rule(ip: str) -> bool:
        """Create a Windows Firewall inbound block rule for the given IP."""
        rule_name = f"{FIREWALL_RULE_PREFIX}{ip.replace('.', '_')}"
        try:
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                    "protocol=any",
                    "enable=yes",
                    "profile=any",
                ],
                capture_output=True,
                timeout=5,
            )
            print(f"[FIREWALL] Windows Firewall rule added: block inbound from {ip}")
            return True
        except Exception as e:
            print(f"[FIREWALL] Could not add firewall rule (may need admin): {e}")
            return False

    @staticmethod
    def _remove_firewall_rule(ip: str) -> bool:
        """Remove the Windows Firewall block rule for the given IP."""
        rule_name = f"{FIREWALL_RULE_PREFIX}{ip.replace('.', '_')}"
        try:
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}",
                ],
                capture_output=True,
                timeout=5,
            )
            print(f"[FIREWALL] Windows Firewall rule removed for {ip}")
            return True
        except Exception as e:
            print(f"[FIREWALL] Could not remove firewall rule: {e}")
            return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def block_ip(
        self,
        ip: str,
        reason: str = "Manual block",
        blocked_by: str = "admin",
        severity: str = "UNKNOWN",
        attack_type: str = "UNKNOWN",
    ) -> dict:
        """
        Add an IP to the blocklist and (best-effort) apply a Windows Firewall rule.
        Returns the block entry dict.
        """
        with self._lock:
            if ip in self._blocked:
                # Already blocked — just return existing entry
                return self._blocked[ip]

            entry = {
                "ip":           ip,
                "reason":       reason,
                "blocked_by":   blocked_by,
                "blocked_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity":     severity,
                "attack_type":  attack_type,
                "firewall_rule": False,
            }

            # Try to apply OS-level firewall rule (admin required)
            entry["firewall_rule"] = self._apply_firewall_rule(ip)

            self._blocked[ip] = entry
            self._save()
            print(f"[FIREWALL] Blocked IP: {ip}  reason={reason}  fw_rule={entry['firewall_rule']}")
            return entry

    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP from the blocklist and delete its firewall rule."""
        with self._lock:
            if ip not in self._blocked:
                return False
            self._remove_firewall_rule(ip)
            del self._blocked[ip]
            self._save()
            print(f"[FIREWALL] Unblocked IP: {ip}")
            return True

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked

    def get_entry(self, ip: str) -> dict | None:
        with self._lock:
            return self._blocked.get(ip)

    def get_all(self) -> list[dict]:
        with self._lock:
            return list(self._blocked.values())

    def get_stats(self) -> dict:
        with self._lock:
            total      = len(self._blocked)
            fw_applied = sum(1 for e in self._blocked.values() if e.get("firewall_rule"))
            return {
                "total_blocked":    total,
                "firewall_applied": fw_applied,
                "software_only":    total - fw_applied,
                "blocked_ips":      list(self._blocked.keys()),
            }
