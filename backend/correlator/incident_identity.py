"""Conservative identities: never merge different victims or Snort signatures."""
import ipaddress
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
    """This project's netsh rule is inbound on the monitor only."""
    if not entry or not entry.get("firewall_rule"):
        return False
    dst = str(alert.get("dst_ip", ""))
    try:
        dst = str(ipaddress.ip_address(dst))
    except ValueError:
        return False
    if dst not in local_addresses():
        return False
    result = entry.get("reachability_checks", {}).get(dst, {})
    return result.get("reachable") is not True
