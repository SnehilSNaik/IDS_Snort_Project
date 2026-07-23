"""
Seed the blockchain with existing alerts from alerts.json.
Run once to backfill historical data.
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blockchain.blockchain import AttackerBlockchain

ALERTS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts", "alerts.json")

bc = AttackerBlockchain()
print(f"Chain length before seeding: {bc.length}")

if not os.path.exists(ALERTS_FILE):
    print("No alerts.json found. Nothing to seed.")
    sys.exit(0)

with open(ALERTS_FILE, "r") as f:
    alerts = json.load(f)

print(f"Found {len(alerts)} alerts to seed...")

seeded = 0
for alert in alerts:
    # Skip if already in chain (check by id)
    existing_ids = {
        b["attacker_data"].get("id")
        for b in bc.get_all_records()
        if b["index"] > 0
    }
    if alert.get("id") in existing_ids:
        print(f"  Skipping duplicate id={alert.get('id')}")
        continue
    blk = bc.add_block(alert)
    print(f"  Committed: Block #{blk.index} - {alert.get('src_ip')} [{alert.get('severity')}]")
    seeded += 1

valid, broken = bc.is_chain_valid()
print(f"\nSeeded {seeded} blocks.")
print(f"Total chain length: {bc.length}")
print(f"Chain valid: {valid}")
print("Done!")
