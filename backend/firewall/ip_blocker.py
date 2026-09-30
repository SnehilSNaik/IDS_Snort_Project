"""
=============================================================
firewall/ip_blocker.py  —  IDS_Snort_Project
=============================================================
IP Blocking Manager  (V2: 3-Machine Setup Support)

Maintains a persistent blocked-IP list in firewall/blocked_ips.json.
Optionally applies Windows Firewall rules via netsh locally (admin)
and REMOTELY on a Victim PC via SSH (V2 3-machine mode).

V2 Environment Variables (set in backend/.env):
    VICTIM_PC_IP    = 192.168.1.x     <- Victim PC's LAN IP
    VICTIM_PC_USER  = Administrator   <- SSH login username
    VICTIM_SSH_KEY  = C:\\path\\to\\id_rsa  <- Private key path

Public API:
    blocker = IPBlocker()
    blocker.block_ip(ip, reason, blocked_by)   # add to blocklist
    blocker.unblock_ip(ip)                      # remove from blocklist
    blocker.is_blocked(ip)                      # True / False
    blocker.get_all()                           # list of blocked entries
    blocker.get_stats()                         # summary dict
=============================================================
"""

import ctypes
import json
import ipaddress
import os
import subprocess
import sys
import threading
import time
from datetime import datetime

# ── V2: Remote Victim PC SSH config (loaded from environment) ────────────────
# Set these in backend/.env to enable the 3-machine architecture.
VICTIM_PC_IP   = os.environ.get("VICTIM_PC_IP", "").strip()
VICTIM_PC_USER = os.environ.get("VICTIM_PC_USER", "Administrator").strip()
VICTIM_SSH_KEY = os.environ.get("VICTIM_SSH_KEY", "").strip()
V2_ENABLED = bool(VICTIM_PC_IP)


def _is_admin() -> bool:
    """Return True if the current process has Windows Administrator privileges."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

BASE_DIR         = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOCKED_IPS_FILE = os.path.join(BASE_DIR, "firewall", "blocked_ips.json")
FIREWALL_RULE_PREFIX = "IDS_BLOCK_"    # prefix for Windows Firewall rule names


class IPBlocker:
    """Thread-safe, persistent IP blocklist with optional OS-level firewall enforcement."""

    def __init__(self):
        self._lock = threading.Lock()
        self._blocked: dict[str, dict] = {}   # ip -> entry dict
        self._file_mtime: float = 0.0          # mtime of last successful load
        self._verification = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load(self):
        if not os.path.exists(BLOCKED_IPS_FILE):
            self._blocked = {}
            self._file_mtime = 0.0
            return
        try:
            with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Keyed by IP for O(1) lookup
            self._blocked = {entry["ip"]: entry for entry in data}
            self._file_mtime = os.path.getmtime(BLOCKED_IPS_FILE)
            print(f"[FIREWALL] Loaded {len(self._blocked)} blocked IP(s) from disk.")
        except Exception as e:
            print(f"[FIREWALL] Warning: could not load blocked IPs: {e}")
            self._blocked = {}
            self._file_mtime = 0.0

    def _reload_if_stale(self) -> None:
        """Reload from disk if blocked_ips.json was modified externally.
        Called at the top of every read method so Flask's in-memory
        _blocker instance stays in sync with disk changes made by the
        correlator or other processes.
        """
        if not os.path.exists(BLOCKED_IPS_FILE):
            self._blocked = {}
            self._verification.clear()
            return
        try:
            mtime = os.path.getmtime(BLOCKED_IPS_FILE)
            if mtime != self._file_mtime:
                self._load()
                self._verification.clear()
        except OSError:
            pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)
            tmp = BLOCKED_IPS_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(list(self._blocked.values()), f, indent=2)
            os.replace(tmp, BLOCKED_IPS_FILE)
            self._file_mtime = os.path.getmtime(BLOCKED_IPS_FILE)
        except Exception as e:
            print(f"[FIREWALL] Warning: could not save blocked IPs: {e}")

    # ------------------------------------------------------------------
    # Windows Firewall integration (best-effort, requires admin)
    # ------------------------------------------------------------------
    @staticmethod
    def _rule_name(ip: str) -> str:
        """Sanitise an IP address (IPv4 or IPv6) into a valid Windows Firewall rule name."""
        return f"{FIREWALL_RULE_PREFIX}{ip.replace('.', '_').replace(':', '_')}"

    @staticmethod
    def _apply_firewall_rule(ip: str) -> bool:
        """Create a Windows Firewall inbound block rule for the given IP.
        Applies locally (requires admin) AND remotely on Victim PC via SSH (V2).
        Returns True if at least the local rule was applied successfully.
        """
        local_ok = False
        if not _is_admin():
            print(f"[FIREWALL] Skipping local OS rule for {ip} — not running as Administrator.")
        else:
            rule_name = IPBlocker._rule_name(ip)
            try:
                result = subprocess.run(
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
                    timeout=3,
                    creationflags=_NO_WINDOW,
                )
                if result.returncode != 0:
                    error = (result.stderr or result.stdout or b"").decode("utf-8", errors="replace").strip()
                    print(f"[FIREWALL] Windows Firewall rejected rule for {ip}: {error or 'netsh failed'}")
                else:
                    print(f"[FIREWALL] Local Windows Firewall rule added: block inbound from {ip}")
                    local_ok = True
            except subprocess.TimeoutExpired:
                print(f"[FIREWALL] netsh timed out adding rule for {ip} — run as Administrator.")
            except Exception as e:
                print(f"[FIREWALL] Could not add local firewall rule (may need admin): {e}")

        # ── V2: Remote block on Victim PC via SSH ────────────────────────────
        if V2_ENABLED:
            IPBlocker._apply_remote_firewall_rule(ip)

        return local_ok

    @staticmethod
    def _build_ssh_cmd(remote_cmd: str) -> list:
        """Build the SSH command list for the Victim PC."""
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "ConnectTimeout=5",
               "-o", "BatchMode=yes"]
        if VICTIM_SSH_KEY:
            cmd += ["-i", VICTIM_SSH_KEY]
        cmd += [f"{VICTIM_PC_USER}@{VICTIM_PC_IP}", remote_cmd]
        return cmd

    @staticmethod
    def _apply_remote_firewall_rule(ip: str) -> bool:
        """V2: SSH into Victim PC and apply a netsh firewall block rule for the attacker IP."""
        rule_name = IPBlocker._rule_name(ip)
        netsh_cmd = (
            f'netsh advfirewall firewall add rule '
            f'name="{rule_name}" dir=in action=block '
            f'remoteip={ip} protocol=any enable=yes profile=any'
        )
        try:
            result = subprocess.run(
                IPBlocker._build_ssh_cmd(netsh_cmd),
                capture_output=True, timeout=10, text=True,
            )
            if result.returncode == 0:
                print(f"[FIREWALL V2] ✅ Remote block on Victim PC ({VICTIM_PC_IP}): {ip} blocked")
                return True
            else:
                err = (result.stderr or result.stdout or "").strip()
                print(f"[FIREWALL V2] ❌ Remote block failed on Victim PC ({VICTIM_PC_IP}): {err}")
                return False
        except subprocess.TimeoutExpired:
            print(f"[FIREWALL V2] ⏱ SSH timeout connecting to Victim PC ({VICTIM_PC_IP})")
            return False
        except FileNotFoundError:
            print("[FIREWALL V2] ⚠ 'ssh' not found in PATH — install OpenSSH client on IDS machine")
            return False
        except Exception as e:
            print(f"[FIREWALL V2] Remote block error: {e}")
            return False

    @staticmethod
    def _remove_remote_firewall_rule(ip: str) -> bool:
        """V2: SSH into Victim PC and remove the netsh block rule for the given IP."""
        rule_name = IPBlocker._rule_name(ip)
        netsh_cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        try:
            result = subprocess.run(
                IPBlocker._build_ssh_cmd(netsh_cmd),
                capture_output=True, timeout=10, text=True,
            )
            if result.returncode == 0:
                print(f"[FIREWALL V2] ✅ Remote unblock on Victim PC ({VICTIM_PC_IP}): {ip} unblocked")
                return True
            else:
                err = (result.stderr or result.stdout or "").strip()
                print(f"[FIREWALL V2] ❌ Remote unblock failed ({VICTIM_PC_IP}): {err}")
                return False
        except Exception as e:
            print(f"[FIREWALL V2] Remote unblock error: {e}")
            return False

    @staticmethod
    def _remove_firewall_rule(ip: str) -> bool:
        """Remove the Windows Firewall block rule locally and remotely (V2)."""
        local_ok = False
        if not _is_admin():
            print(f"[FIREWALL] Skipping local OS rule removal for {ip} — not running as Administrator.")
        else:
            rule_name = IPBlocker._rule_name(ip)
            try:
                result = subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}",
                    ],
                    capture_output=True,
                    timeout=3,
                    creationflags=_NO_WINDOW,
                )
                if result.returncode != 0:
                    error = (result.stderr or result.stdout or b"").decode("utf-8", errors="replace").strip()
                    print(f"[FIREWALL] Windows Firewall could not remove rule for {ip}: {error or 'netsh failed'}")
                else:
                    print(f"[FIREWALL] Local Windows Firewall rule removed for {ip}")
                    local_ok = True
            except subprocess.TimeoutExpired:
                print(f"[FIREWALL] netsh timed out removing rule for {ip}.")
            except Exception as e:
                print(f"[FIREWALL] Could not remove local firewall rule: {e}")

        # ── V2: Remote unblock on Victim PC ──────────────────────────────────
        if V2_ENABLED:
            IPBlocker._remove_remote_firewall_rule(ip)

        return local_ok

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    @staticmethod
    def _verify_firewall_rule(ip):
        """Read effective Windows policy, not the saved JSON success flag."""
        ip = str(ipaddress.ip_address(ip))
        return IPBlocker._verify_many([ip]).get(ip, False)

    @staticmethod
    def _verify_many(ips):
        """One policy query for dashboard polling, rather than a process per IP."""
        result_map = {ip: False for ip in ips}
        if os.name != "nt":
            return result_map
        valid = []
        for ip in ips:
            try:
                valid.append(str(ipaddress.ip_address(ip)))
            except ValueError:
                pass
        if not valid:
            return result_map
        literals = ','.join("'" + ip + "'" for ip in valid)
        command = (
            "$ErrorActionPreference='Stop'; $p=New-Object -ComObject HNetCfg.FwPolicy2; "
            "$active=[int]$p.CurrentProfileTypes; $on=($active -ne 0); "
            "foreach($n in @(1,2,4)){if(($active -band $n) -ne 0){$on=$on -and $p.FirewallEnabled($n)}}; "
            "$rows=@(foreach($ip in @(" + literals + ")){try{$r=$p.Rules.Item('IDS_BLOCK_'+$ip.Replace('.','_')); "
            "@{ip=$ip; enabled=[bool]$r.Enabled; action=[int]$r.Action; direction=[int]$r.Direction; "
            "protocol=[int]$r.Protocol; local=$r.LocalAddresses; application=$r.ApplicationName; service=$r.ServiceName; "
            "interfaces=$r.InterfaceTypes; "
            "remote=$r.RemoteAddresses; active=($on -and (($r.Profiles -band $active) -eq $active))}}catch{}}); "
            "ConvertTo-Json -InputObject $rows -Compress"
        )
        try:
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                                    capture_output=True, timeout=4, text=True,
                                    creationflags=_NO_WINDOW)
            if result.returncode:
                return result_map
            for rule in json.loads(result.stdout):
                ip = rule["ip"]
                networks = [ipaddress.ip_network(x.strip(), strict=False) for x in rule["remote"].split(',')]
                exact = any(n.num_addresses == 1 and n.network_address == ipaddress.ip_address(ip) for n in networks)
                result_map[ip] = bool(rule["enabled"] and rule["active"] and rule["action"] == 0
                                      and rule["direction"] == 1 and exact and rule.get("protocol") == 256
                                      and rule.get("local") == "*" and not rule.get("application")
                                      and not rule.get("service") and rule.get("interfaces") == "All")
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
            pass
        return result_map

    def _verified_entry(self, ip, force=False):
        entry = dict(self._blocked[ip])
        cached = self._verification.get(ip)
        if force or not cached or time.monotonic() - cached[0] > 5:
            cached = (time.monotonic(), self._verify_firewall_rule(ip))
            self._verification[ip] = cached
        entry["firewall_rule"] = cached[1]
        entry["block_scope"] = "monitoring_pc"
        entry["rule_status"] = "verified" if cached[1] else "unverified"
        return entry

    def record_reachability(self, ip, target_ip, reachable, note):
        """Operator reports a test from the attacker; never infer this from packets."""
        ip = str(ipaddress.ip_address(ip))
        target_ip = str(ipaddress.ip_address(target_ip))
        with self._lock:
            self._reload_if_stale()
            if ip not in self._blocked:
                raise ValueError("No block entry exists for this source")
            entry = self._blocked[ip]
            entry.setdefault("reachability_checks", {})[target_ip] = {
                "reachable": reachable, "note": note, "method": "operator_reported",
                "checked_at": datetime.now().isoformat(timespec="seconds"),
            }
            self._save()
            return self._verified_entry(ip)

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
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip}") from exc
        with self._lock:
            self._reload_if_stale()
            if ip in self._blocked:
                entry = self._blocked[ip]
                verified = self._verified_entry(ip, force=True)
                if verified.get("firewall_rule"):
                    return verified
                # A previous attempt may have recorded a software-only block.
                # Retry OS enforcement when privileges or firewall availability change.
                entry["firewall_rule"] = self._apply_firewall_rule(ip)
                if entry["firewall_rule"]:
                    entry["blocked_at"] = datetime.now().isoformat(timespec="microseconds")
                    entry.pop("reachability_checks", None)
                self._save()
                return self._verified_entry(ip, force=True)

            entry = {
                "ip":           ip,
                "reason":       reason,
                "blocked_by":   blocked_by,
                "blocked_at":   datetime.now().isoformat(timespec="microseconds"),
                "severity":     severity,
                "attack_type":  attack_type,
                "firewall_rule": False,
                "v2_mode":      V2_ENABLED,
                "victim_pc":    VICTIM_PC_IP if V2_ENABLED else None,
            }

            # Try to apply OS-level firewall rule (admin required)
            # In V2 mode, _apply_firewall_rule also SSHes into Victim PC.
            entry["firewall_rule"] = self._apply_firewall_rule(ip)

            self._blocked[ip] = entry
            self._save()
            v2_tag = f" + remote Victim PC ({VICTIM_PC_IP})" if V2_ENABLED else ""
            print(f"[FIREWALL] Blocked IP: {ip}  reason={reason}  fw_rule={entry['firewall_rule']}{v2_tag}")
            return self._verified_entry(ip, force=True)

    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP from the blocklist and delete its firewall rule (best-effort)."""
        with self._lock:
            self._reload_if_stale()
            if ip not in self._blocked:
                return False
            entry = self._blocked[ip]
            # Best-effort: try to remove the OS firewall rule but never let
            # netsh failure prevent the IP from being removed from the JSON
            # blocklist (e.g. when Flask is not running as Administrator).
            if entry.get("firewall_rule"):
                self._remove_firewall_rule(ip)
            del self._blocked[ip]
            self._verification.pop(ip, None)
            self._save()
            print(f"[FIREWALL] Unblocked IP: {ip}")
            return True

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            self._reload_if_stale()
            return ip in self._blocked

    def get_entry(self, ip: str) -> dict | None:
        with self._lock:
            self._reload_if_stale()
            return self._verified_entry(ip) if ip in self._blocked else None

    def get_all(self) -> list[dict]:
        with self._lock:
            self._reload_if_stale()
            stale = [ip for ip in self._blocked if ip not in self._verification
                     or time.monotonic() - self._verification[ip][0] > 5]
            if len(stale) > 1:
                results = self._verify_many(stale)
                checked_at = time.monotonic()
                self._verification.update({ip: (checked_at, results.get(ip, False)) for ip in stale})
            return [self._verified_entry(ip) for ip in self._blocked]

    def get_stats(self) -> dict:
        with self._lock:
            self._reload_if_stale()
            total      = len(self._blocked)
            verified = [ip for ip in self._blocked if self._verified_entry(ip)["firewall_rule"]]
            fw_applied = len(verified)
            return {
                "total_blocked":    total,
                "firewall_applied": fw_applied,
                "software_only":    total - fw_applied,
                "blocked_ips":      verified,
            }
