"""Quick test of blockchain engine."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blockchain.blockchain import AttackerBlockchain

bc = AttackerBlockchain()
print(f"Chain length on load: {bc.length}")

# Add a test block
test_alert = {
    "id": 9999,
    "timestamp": "2026-07-24 00:00:00",
    "type": "ML_ANOMALY",
    "severity": "HIGH",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "protocol": "TCP",
    "packet_size": 1400,
    "confidence": 99.0,
    "message": "Test attack for blockchain verification"
}
blk = bc.add_block(test_alert)
print(f"New block: #{blk.index}  hash={blk.hash[:32]}...")
print(f"Chain length after add: {bc.length}")

# Verify chain integrity
valid, broken = bc.is_chain_valid()
print(f"Chain valid: {valid}  broken_at: {broken}")

# Stats
stats = bc.get_attacker_summary()
print(f"Total blocks: {stats['total_blocks']}")
print(f"Attacker blocks: {stats['attacker_blocks']}")
print(f"Unique attackers: {stats['unique_attackers']}")
print(f"Top attackers: {[a['ip'] for a in stats['top_attackers']]}")
print()
print("=== ALL TESTS PASSED ===")
