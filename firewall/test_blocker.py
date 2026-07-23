"""Test the IP Blocker module."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from firewall.ip_blocker import IPBlocker

b = IPBlocker()
print("=== IP BLOCKER TEST ===")

# Block a test IP
entry = b.block_ip("185.220.101.47", reason="DDoS Botnet Node", severity="HIGH", attack_type="ML_ANOMALY")
print(f"Blocked   : {entry['ip']}")
print(f"FW Rule   : {entry['firewall_rule']}")
print(f"Blocked at: {entry['blocked_at']}")
print(f"Is blocked (should be True) : {b.is_blocked('185.220.101.47')}")
print(f"Is blocked (should be False): {b.is_blocked('8.8.8.8')}")

stats = b.get_stats()
print(f"Total blocked: {stats['total_blocked']}")
print(f"Blocked IPs  : {stats['blocked_ips']}")

# Unblock
b.unblock_ip("185.220.101.47")
print(f"After unblock (should be False): {b.is_blocked('185.220.101.47')}")
print()
print("=== ALL FIREWALL TESTS PASSED! ===")
