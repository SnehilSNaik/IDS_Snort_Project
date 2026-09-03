"""Thread-safe SQLite event store with one-time migration from legacy JSON."""

import json
import os
import sqlite3
import threading
import hashlib
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DB_DIR, "ids.db")
ALERTS_JSON = os.path.join(BASE_DIR, "alerts", "alerts.json")
ENDPOINTS_JSON = os.path.join(BASE_DIR, "endpoints", "endpoints.json")
_lock = threading.RLock()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _connect():
    os.makedirs(DB_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def initialize():
    with _lock, _connect() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              alert_id TEXT UNIQUE, timestamp TEXT, src_ip TEXT, dst_ip TEXT,
              alert_type TEXT, severity TEXT, protocol TEXT, confidence REAL,
              endpoint_id TEXT, victim_name TEXT, payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS endpoints (
              endpoint_id TEXT PRIMARY KEY, name TEXT, hostname TEXT, ip TEXT,
              os TEXT, agent_version TEXT, first_seen TEXT, last_seen TEXT,
              last_alert_at TEXT, alert_count INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS timeline_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, src_ip TEXT,
              endpoint_id TEXT, stage TEXT, title TEXT, detail TEXT, severity TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, action TEXT,
              subject TEXT, detail TEXT, previous_hash TEXT, record_hash TEXT UNIQUE
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_src_time ON alerts(src_ip, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_timeline_time ON timeline_events(timestamp DESC);
        """)
        if con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0:
            _migrate_json_alerts(con)
        if con.execute("SELECT COUNT(*) FROM timeline_events").fetchone()[0] == 0:
            _migrate_json_timeline(con)
        if con.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0] == 0:
            _migrate_json_endpoints(con)


def _read_json(path, fallback):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return fallback


def _migrate_json_alerts(con):
    for alert in _read_json(ALERTS_JSON, []):
        record_alert(alert, con=con, timeline=False)


def _migrate_json_timeline(con):
    for alert in _read_json(ALERTS_JSON, []):
        record_alert(alert, con=con, timeline=True)


def _migrate_json_endpoints(con):
    for endpoint in _read_json(ENDPOINTS_JSON, {}).values():
        upsert_endpoint(endpoint, con=con)


def record_alert(alert, con=None, timeline=True):
    """Persist an alert and its primary detection timeline event."""
    initialize() if con is None else None
    alert_id = str(alert.get("id") or f"{alert.get('timestamp')}:{alert.get('src_ip')}:{alert.get('type')}")
    values = (alert_id, alert.get("timestamp") or _now(), alert.get("src_ip", "Unknown"),
              alert.get("dst_ip", "Unknown"), alert.get("type", "UNKNOWN"),
              alert.get("severity", "LOW"), alert.get("protocol", "Unknown"),
              float(alert.get("confidence", 0) or 0), alert.get("endpoint_id"),
              alert.get("victim_name"), json.dumps(alert))
    def write(db):
        db.execute("""INSERT INTO alerts(alert_id,timestamp,src_ip,dst_ip,alert_type,severity,protocol,confidence,endpoint_id,victim_name,payload_json)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(alert_id) DO UPDATE SET payload_json=excluded.payload_json, alert_type=excluded.alert_type, severity=excluded.severity, confidence=excluded.confidence""", values)
        if timeline:
            db.execute("INSERT INTO timeline_events(timestamp,src_ip,endpoint_id,stage,title,detail,severity) VALUES(?,?,?,?,?,?,?)",
                       (values[1], values[2], values[8], "DETECTED", f"{values[4]} detected", alert.get("message", "Detection recorded"), values[5]))
            if any(key in alert for key in ("ti_country", "ti_org", "ti_abuse_score", "ti_confirmed")):
                db.execute("INSERT INTO timeline_events(timestamp,src_ip,endpoint_id,stage,title,detail,severity) VALUES(?,?,?,?,?,?,?)",
                           (_now(), values[2], values[8], "THREAT_INTEL", "Threat intelligence enriched", _ti_detail(alert), values[5]))
    if con is not None:
        write(con)
        record_audit("ALERT_RECORDED", values[2], alert.get("message", "Detection recorded"), con=con)
        return
    with _lock, _connect() as db:
        write(db)
        record_audit("ALERT_RECORDED", values[2], alert.get("message", "Detection recorded"), con=db)


def _ti_detail(alert):
    parts = []
    if alert.get("ti_country"): parts.append(f"Country: {alert['ti_country']}")
    if alert.get("ti_org"): parts.append(f"Network: {alert['ti_org']}")
    if alert.get("ti_abuse_score") is not None: parts.append(f"Abuse score: {alert['ti_abuse_score']}%")
    if alert.get("ti_confirmed"): parts.append("Confirmed by threat intelligence")
    return " · ".join(parts) or "Lookup completed"


def record_stage(src_ip, stage, title, detail, severity="INFO", endpoint_id=None):
    initialize()
    with _lock, _connect() as con:
        con.execute("INSERT INTO timeline_events(timestamp,src_ip,endpoint_id,stage,title,detail,severity) VALUES(?,?,?,?,?,?,?)",
                    (_now(), src_ip, endpoint_id, stage, title, detail, severity))
        if stage == "BLOCKED":
            record_audit("IP_BLOCKED", src_ip, detail, con=con)


def record_audit(action, subject, detail, con=None):
    """Append a tamper-evident audit record using SHA-256 chain hashing."""
    initialize() if con is None else None
    def write(db):
        previous = db.execute("SELECT record_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        previous_hash = previous[0] if previous else "0" * 64
        timestamp = _now()
        payload = json.dumps({"timestamp": timestamp, "action": action, "subject": subject, "detail": detail, "previous_hash": previous_hash}, sort_keys=True)
        record_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        db.execute("INSERT INTO audit_log(timestamp,action,subject,detail,previous_hash,record_hash) VALUES(?,?,?,?,?,?)", (timestamp, action, subject, detail, previous_hash, record_hash))
    if con is not None: write(con); return
    with _lock, _connect() as db: write(db)


def audit_records(limit=100):
    initialize()
    with _lock, _connect() as con:
        return [dict(row) for row in con.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]


def verify_audit():
    initialize()
    with _lock, _connect() as con:
        previous_hash = "0" * 64
        rows = con.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        for row in rows:
            payload = json.dumps({"timestamp": row["timestamp"], "action": row["action"], "subject": row["subject"], "detail": row["detail"], "previous_hash": previous_hash}, sort_keys=True)
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["record_hash"] != expected:
                return False, row["id"]
            previous_hash = row["record_hash"]
        return True, -1


def audit_summary():
    records = audit_records(20)
    valid, broken_at = verify_audit()
    with _lock, _connect() as con:
        total = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    return {"total_records": total, "recent_records": records, "valid": valid, "broken_at": broken_at}


def upsert_endpoint(endpoint, con=None):
    initialize() if con is None else None
    endpoint_id = str(endpoint.get("endpoint_id") or endpoint.get("hostname") or endpoint.get("ip"))
    values = (endpoint_id, endpoint.get("name", endpoint_id), endpoint.get("hostname", endpoint_id), endpoint.get("ip", "Unknown"), endpoint.get("os", "Unknown"), endpoint.get("agent_version", "Unknown"), endpoint.get("first_seen", _now()), endpoint.get("last_seen", _now()), endpoint.get("last_alert_at"), int(endpoint.get("alert_count", 0)))
    sql = """INSERT INTO endpoints(endpoint_id,name,hostname,ip,os,agent_version,first_seen,last_seen,last_alert_at,alert_count)
             VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(endpoint_id) DO UPDATE SET name=excluded.name,hostname=excluded.hostname,ip=excluded.ip,os=excluded.os,agent_version=excluded.agent_version,last_seen=excluded.last_seen"""
    if con is not None: con.execute(sql, values); return
    with _lock, _connect() as db: db.execute(sql, values)


def endpoints():
    initialize()
    with _lock, _connect() as con:
        return [dict(row) for row in con.execute("SELECT * FROM endpoints ORDER BY name")]


def timeline(limit=120, src_ip=None):
    initialize()
    with _lock, _connect() as con:
        if src_ip:
            rows = con.execute("SELECT * FROM timeline_events WHERE src_ip=? ORDER BY id DESC LIMIT ?", (src_ip, limit)).fetchall()
        else:
            rows = con.execute("SELECT * FROM timeline_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]


def clear_alert_history():
    initialize()
    with _lock, _connect() as con:
        con.execute("DELETE FROM alerts"); con.execute("DELETE FROM timeline_events")
        con.execute("DELETE FROM audit_log")


initialize()
