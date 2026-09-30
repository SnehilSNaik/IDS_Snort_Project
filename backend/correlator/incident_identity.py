"""Conservative identities: never merge different victims or Snort signatures."""
import ipaddress
import os
import socket
import time

_local_cache = (0, set())


def local_addresses():
    global _local_cache
    now = time.monotonic()
    if now - _local_cache[0] > 30:
        addresses = {"127.0.0.1", "::1"}
        try:
            addresses.update(item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None))
        except OSError:
            pass
        _local_cache = (now, addresses)
    return _local_cache[1]


def victim_key(alert):
    return (str(alert.get("dst_ip", "")), str(alert.get("endpoint_id") or ""))


def incident_key(alert):
    kind = alert.get("type", "UNKNOWN")
    signature = alert.get("snort_sid") or alert.get("signature_id")
    if kind == "SNORT_SIGNATURE" and not signature:
        signature = alert.get("message", "")
    return [str(alert.get("src_ip", "")), *victim_key(alert),
            str(alert.get("protocol", "")).upper(), kind,
            str(signature or alert.get("attack_type") or "")]


def covered_by_block(alert, entry):
    """Return True if the attacker block rule covers the alert's victim.

    V1: victim must be one of this machine's own IP addresses.
    V2: also accept the remote Victim PC IP (VICTIM_PC_IP env var),
        since the block is pushed to that machine via SSH.
    """
    if not entry or not entry.get("firewall_rule"):
        return False
    dst = str(alert.get("dst_ip", ""))
    try:
        dst = str(ipaddress.ip_address(dst))
    except ValueError:
        return False

    # V1: victim is local to this machine
    if dst in local_addresses():
        result = entry.get("reachability_checks", {}).get(dst, {})
        return result.get("reachable") is not True

    # V2: victim is the remote Victim PC managed via SSH
    victim_pc_ip = os.environ.get("VICTIM_PC_IP", "").strip()
    if victim_pc_ip and dst == victim_pc_ip:
        # Block was pushed remotely via SSH — treat as covered
        result = entry.get("reachability_checks", {}).get(dst, {})
        return result.get("reachable") is not True

    return False
