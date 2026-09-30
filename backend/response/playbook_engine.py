"""
=============================================================
response/playbook_engine.py  —  IDS_Snort_Project
=============================================================
Automated Incident Response Playbook Engine.

Evaluates every incoming alert against a set of JSON-defined
playbook rules (response/playbooks.json).

On match, executes one or more automated actions:
  • block_ip       — calls IPBlocker.block_ip() + netsh firewall
  • telegram_alert — sends Telegram notification
  • email_alert    — sends throttled email
  • incident_log   — appends to response/incident_log.json

Per-IP Threat Score System:
  • HIGH alert    → +3 points
  • MEDIUM alert  → +1 point
  • LOW alert     → +0 (not scored)
  • Score ≥ quarantine_threshold (default 10) → PB-006 fires →
    IP is auto-blocked

Scores are persisted in response/threat_scores.json.

Public API:
  engine = PlaybookEngine()
  engine.evaluate(alert)   — call from correlator after saving alert
=============================================================
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from collections import defaultdict, deque

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

PLAYBOOKS_FILE    = os.path.join(os.path.dirname(__file__), "playbooks.json")
THREAT_SCORE_FILE = os.path.join(os.path.dirname(__file__), "threat_scores.json")
INCIDENT_LOG_FILE = os.path.join(os.path.dirname(__file__), "incident_log.json")

# Score increments per severity
SCORE_MAP = {"HIGH": 3, "MEDIUM": 1, "LOW": 0}

# ── Repeat-trigger tracker (for PB-007) ──────────────────
# ip -> deque of (timestamp, alert_type, severity)
_repeat_tracker: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
_repeat_lock = threading.Lock()


class PlaybookEngine:
    """
    Thread-safe playbook evaluator.
    Designed to be instantiated once and reused across all alerts.
    """

    def __init__(self):
        self._lock            = threading.Lock()
        self._playbooks: list = self._load_playbooks()
        self._scores: dict    = self._load_scores()
        self._incident_count  = 0

        # Lazy imports — avoid circular dependency at module load
        self._blocker   = None
        self._telegram  = None
        self._email     = None

        self._init_dependencies()

        print(f"[PLAYBOOK] Engine started — {len(self._playbooks)} rules loaded.")

    # ── Startup ───────────────────────────────────────────
    def _init_dependencies(self):
        try:
            from firewall.ip_blocker import IPBlocker
            self._blocker = IPBlocker()
        except Exception as e:
            print(f"[PLAYBOOK] IP Blocker unavailable: {e}")

        try:
            from telegram_alert.telegram_bot import send_telegram_in_background
            self._telegram = send_telegram_in_background
        except Exception as e:
            print(f"[PLAYBOOK] Telegram unavailable: {e}")

        try:
            from email_alert.send_alert import send_email_alert
            self._email = send_email_alert
        except Exception as e:
            print(f"[PLAYBOOK] Email unavailable: {e}")


    # ── Persistence ───────────────────────────────────────
    def _load_playbooks(self) -> list:
        try:
            with open(PLAYBOOKS_FILE, "r") as f:
                return [pb for pb in json.load(f) if pb.get("enabled", True)]
        except Exception as e:
            print(f"[PLAYBOOK] Could not load playbooks.json: {e}")
            return []

    def _load_scores(self) -> dict:
        if os.path.exists(THREAT_SCORE_FILE):
            try:
                with open(THREAT_SCORE_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_scores(self):
        try:
            tmp = THREAT_SCORE_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._scores, f, indent=2)
            os.replace(tmp, THREAT_SCORE_FILE)
        except Exception as e:
            print(f"[PLAYBOOK] Score save error: {e}")

    def _append_incident(self, incident: dict):
        incidents = []
        if os.path.exists(INCIDENT_LOG_FILE):
            try:
                with open(INCIDENT_LOG_FILE, "r") as f:
                    incidents = json.load(f)
            except Exception:
                incidents = []
        incidents.append(incident)
        # Keep last 500 incidents
        if len(incidents) > 500:
            incidents = incidents[-500:]
        try:
            tmp = INCIDENT_LOG_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(incidents, f, indent=2)
            os.replace(tmp, INCIDENT_LOG_FILE)
        except Exception as e:
            print(f"[PLAYBOOK] Incident log save error: {e}")

    # ── Score update ──────────────────────────────────────
    def _update_score(self, ip: str, severity: str) -> int:
        """Add score for the alert and return the new total."""
        increment = SCORE_MAP.get(severity, 0)
        if increment == 0:
            return self._scores.get(ip, {}).get("score", 0)

        with self._lock:
            entry = self._scores.get(ip, {"score": 0, "ip": ip, "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "alerts": 0})
            entry["score"]     += increment
            entry["alerts"]    += 1
            entry["last_seen"]  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            entry["severity"]   = severity
            self._scores[ip]    = entry
            self._save_scores()
            return entry["score"]

    def get_threat_scores(self) -> dict:
        """Returns a copy of all current IP threat scores."""
        with self._lock:
            return dict(self._scores)

    # ── Action executors ──────────────────────────────────
    def _action_block_ip(self, ip: str, reason: str, alert: dict):
        if not self._blocker:
            return
        try:
            entry = self._blocker.get_entry(ip)
            if not entry or not entry.get("firewall_rule"):
                entry = self._blocker.block_ip(
                    ip,
                    reason=reason,
                    blocked_by="PlaybookEngine",
                    severity=alert.get("severity", "HIGH"),
                    attack_type=alert.get("type", "UNKNOWN"),
                )
                state = "Windows Firewall enforced" if entry.get("firewall_rule") else "software-only; Windows Firewall did not confirm"
                print(f"[PLAYBOOK][AUTO-BLOCK] {ip} — {reason} ({state})")
        except Exception as e:
            print(f"[PLAYBOOK] Block error for {ip}: {e}")

    def _action_telegram(self, alert: dict):
        if self._telegram:
            try:
                self._telegram(alert)
            except Exception:
                pass

    def _action_email(self, alert: dict):
        if self._email:
            try:
                threading.Thread(target=self._email, args=(alert,), daemon=True).start()
            except Exception:
                pass

    def _action_incident_log(self, playbook: dict, alert: dict, reason: str):
        self._incident_count += 1
        incident = {
            "incident_id":    self._incident_count,
            "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "playbook_id":    playbook.get("id", "?"),
            "playbook_name":  playbook.get("name", "?"),
            "trigger_type":   alert.get("type"),
            "src_ip":         alert.get("src_ip"),
            "severity":       alert.get("severity"),
            "confidence":     alert.get("confidence"),
            "actions_taken":  playbook.get("actions", []),
            "reason":         reason,
            "alert_message":  alert.get("message", ""),
        }
        self._append_incident(incident)
        print(f"[PLAYBOOK][INCIDENT #{self._incident_count}] {playbook['id']} — {reason}")

    # ── Playbook matching ─────────────────────────────────
    def _matches(self, pb: dict, alert: dict, score: int) -> tuple[bool, str]:
        """Returns (matched, reason_string)."""
        alert_type  = alert.get("type", "")
        severity    = alert.get("severity", "")
        confidence  = float(alert.get("confidence", 0))
        abuse_score = int(alert.get("ti_abuse_score", 0))
        src_ip      = alert.get("src_ip", "")
        now         = time.time()

        pb_type     = pb.get("trigger_type", "")
        pb_sev      = pb.get("trigger_severity", "ANY")
        pb_conf_min = float(pb.get("trigger_confidence_min", 0))

        # ── Threat score quarantine rule ──────────────────
        if pb_type == "THREAT_SCORE_EXCEEDED":
            threshold = pb.get("quarantine_threshold", 10)
            if score >= threshold:
                return True, f"Threat score {score} >= quarantine threshold {threshold}"
            return False, ""

        # Type match
        if pb_type != "ANY" and pb_type != alert_type:
            return False, ""

        # Severity match
        if pb_sev != "ANY" and pb_sev != severity:
            return False, ""

        # Confidence match
        if confidence < pb_conf_min:
            return False, ""

        # TI abuse score match (optional)
        if "trigger_ti_abuse_min" in pb:
            if abuse_score < pb["trigger_ti_abuse_min"]:
                return False, ""

        # Repeat-trigger match (e.g. PB-007: 3 HIGH Snort alerts in 60s)
        if "trigger_repeat_count" in pb:
            repeat_count  = pb["trigger_repeat_count"]
            repeat_window = pb.get("trigger_repeat_window", 60)
            with _repeat_lock:
                q = _repeat_tracker[src_ip]
                relevant = [ts for (ts, t, s) in q
                            if now - ts <= repeat_window
                            and t == alert_type
                            and s == severity]
                if len(relevant) < repeat_count:
                    return False, ""

        reason = (f"{pb['id']} ({pb['name']}): "
                  f"{alert_type}/{severity}/{confidence}% "
                  f"from {src_ip}")
        return True, reason

    # ── Main evaluation entry point ───────────────────────
    def evaluate(self, alert: dict):
        """
        Evaluate all playbook rules against this alert.
        Called from the correlator after each new alert is saved.
        """
        src_ip   = alert.get("src_ip", "0.0.0.0")
        severity = alert.get("severity", "LOW")
        now      = time.time()

        # Record for repeat-trigger tracking
        with _repeat_lock:
            _repeat_tracker[src_ip].append((now, alert.get("type", ""), severity))

        # Update threat score
        score = self._update_score(src_ip, severity)

        # Evaluate each enabled playbook in a background thread
        triggered_actions = []
        for pb in self._playbooks:
            matched, reason = self._matches(pb, alert, score)
            if not matched:
                continue

            actions = pb.get("actions", [])
            triggered_actions.extend(actions)

            # Execute actions in a daemon thread (never block correlator)
            pb_copy    = dict(pb)
            alert_copy = dict(alert)

            def _run_actions(pb=pb_copy, al=alert_copy, r=reason):
                for action in pb.get("actions", []):
                    if action == "block_ip":
                        self._action_block_ip(al.get("src_ip", ""), r, al)
                    elif action == "telegram_alert":
                        self._action_telegram(al)
                    elif action == "email_alert":
                        self._action_email(al)
                    elif action == "incident_log":
                        self._action_incident_log(pb, al, r)

            threading.Thread(target=_run_actions, daemon=True).start()

        return triggered_actions


# ── Module-level singleton ────────────────────────────────
_engine: PlaybookEngine | None = None
_engine_lock = threading.Lock()


def get_engine() -> PlaybookEngine:
    """Get or create the singleton PlaybookEngine."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = PlaybookEngine()
    return _engine
