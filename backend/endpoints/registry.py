"""Small, dependency-free registry for endpoint agents.

Agents register and send heartbeats through the existing UDP correlator.  The
registry is deliberately separate from alerts so a quiet, healthy device is
still visible in the SOC dashboard.
"""

import json
import os
import threading
from datetime import datetime, timezone
from persistence.event_store import upsert_endpoint

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_FILE = os.path.join(BASE_DIR, "endpoints", "endpoints.json")
_lock = threading.Lock()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _load():
    try:
        with open(REGISTRY_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(records):
    os.makedirs(os.path.dirname(REGISTRY_FILE), exist_ok=True)
    temp = REGISTRY_FILE + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(records, handle, indent=2)
    os.replace(temp, REGISTRY_FILE)


def register(message, sender_ip=""):
    """Create or refresh an endpoint record from an agent message."""
    endpoint_id = str(message.get("endpoint_id") or message.get("hostname") or sender_ip).strip()
    if not endpoint_id:
        return None
    with _lock:
        records = _load()
        existing = records.get(endpoint_id, {})
        records[endpoint_id] = {
            **existing,
            "endpoint_id": endpoint_id,
            "name": message.get("victim_name") or message.get("name") or existing.get("name") or endpoint_id,
            "hostname": message.get("hostname") or existing.get("hostname") or endpoint_id,
            "ip": message.get("endpoint_ip") or sender_ip or existing.get("ip", "Unknown"),
            "os": message.get("os") or existing.get("os", "Unknown"),
            "agent_version": message.get("agent_version") or existing.get("agent_version", "Unknown"),
            "first_seen": existing.get("first_seen", _now()),
            "last_seen": _now(),
            "last_alert_at": existing.get("last_alert_at"),
            "alert_count": existing.get("alert_count", 0),
        }
        _save(records)
        record = dict(records[endpoint_id])
    upsert_endpoint(record)
    return record


def touch_alert(alert):
    """Refresh endpoint health and increment its alert count when it reports."""
    endpoint_id = alert.get("endpoint_id")
    if not endpoint_id:
        # Fallback: match by dst_ip for injected/simulated alerts
        dst_ip = alert.get("dst_ip", "")
        if dst_ip:
            with _lock:
                records = _load()
                for eid, rec in records.items():
                    if rec.get("ip") == dst_ip:
                        endpoint_id = eid
                        break
    if not endpoint_id:
        return
    with _lock:
        exists = endpoint_id in _load()
    if not exists:
        # register() obtains the same lock, so call it before re-entering.
        register({
            "endpoint_id": endpoint_id,
            "victim_name": alert.get("victim_name"),
            "hostname": alert.get("endpoint_hostname"),
            "endpoint_ip": alert.get("dst_ip"),
        })
    with _lock:
        records = _load()
        record = records.get(endpoint_id)
        if not record:
            return
        record = records[endpoint_id]
        record["last_seen"] = _now()
        record["last_alert_at"] = _now()
        record["alert_count"] = int(record.get("alert_count", 0)) + 1
        _save(records)
        updated = dict(record)
    upsert_endpoint(updated)


def get_endpoints(online_seconds=90):
    """Return inventory sorted by name, with a computed online status."""
    from datetime import datetime
    now = datetime.now(timezone.utc)
    items = []
    with _lock:
        for record in _load().values():
            item = dict(record)
            try:
                last_seen = datetime.strptime(item["last_seen"], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
                item["status"] = "online" if (now - last_seen).total_seconds() <= online_seconds else "offline"
            except (KeyError, ValueError):
                item["status"] = "offline"
            items.append(item)
    return sorted(items, key=lambda item: item.get("name", "").lower())
