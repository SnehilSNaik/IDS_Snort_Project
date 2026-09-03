"""Human-readable MITRE ATT&CK context for dashboard alert enrichment.

Mappings are intentionally conservative: an IDS signal indicates suspected
technique activity, not proof that a full adversary procedure occurred.
"""

MAPPINGS = {
    "SNORT_SIGNATURE": {"tactic": "Reconnaissance", "technique_id": "T1595", "technique": "Active Scanning"},
    "ML_ANOMALY": {"tactic": "Command and Control", "technique_id": "T1071", "technique": "Application Layer Protocol"},
    "ICMP_PING_FLOOD": {"tactic": "Impact", "technique_id": "T1498", "technique": "Network Denial of Service"},
    "LSTM_ANOMALY": {"tactic": "Command and Control", "technique_id": "T1071", "technique": "Application Layer Protocol"},
    "DNS_TUNNEL": {"tactic": "Command and Control", "technique_id": "T1071.004", "technique": "DNS"},
    "CORRELATED_ATTACK": {"tactic": "Multiple", "technique_id": "T1595 / T1071", "technique": "Scanning and application-layer anomaly"},
}


def enrich(alert):
    """Attach mapping fields without overwriting a more specific source value."""
    mapping = MAPPINGS.get(alert.get("type"))
    if mapping:
        for key, value in mapping.items():
            alert.setdefault(f"mitre_{key}", value)
    return alert
