"""
=============================================================
dashboard/app.py
=============================================================
Flask web dashboard for the IDS project.

Routes:
  GET  /              → Public landing page (home)
  GET  /login         → Login page
  POST /login         → Authenticate user
  GET  /signup        → Signup page
  POST /signup        → Register new user
  POST /logout        → Log out current user
  GET  /dashboard     → Main IDS dashboard (login required)
  GET  /api/alerts    → JSON API: returns all alerts
  POST /api/clear     → Clear all alerts
  GET  /api/stats     → Summary statistics
  POST /api/start_engine → Start capture + detect processes
  POST /api/test_email   → Send test email

Run: python3 dashboard/app.py
Then open: http://localhost:5000
=============================================================
"""

import os
import sys
import json
import time
import re
import socket
import subprocess
from functools import wraps
from flask import (
    Flask, render_template, jsonify, request,
    session, redirect, url_for, flash
)
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------------------------------------------
# App setup
# --------------------------------------------------------
app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get("IDS_SECRET_KEY", "ids-secret-key-change-in-prod-2024")

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    return response

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# start_ids.py launches this module from backend/dashboard; expose backend's
# sibling packages (persistence, firewall, endpoints, etc.) reliably.
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# IP Blocker — lazy import
try:
    from firewall.ip_blocker import IPBlocker as _IB
    _blocker = _IB()
except Exception as _fw_err:
    _blocker = None
    print(f"[DASHBOARD] IP Blocker unavailable: {_fw_err}")

try:
    from endpoints.registry import get_endpoints as _get_endpoints
except Exception as _endpoint_err:
    _get_endpoints = None
    print(f"[DASHBOARD] Endpoint registry unavailable: {_endpoint_err}")

from persistence.event_store import timeline as _timeline, endpoints as _sqlite_endpoints, clear_alert_history as _clear_history, record_stage as _record_stage, audit_records as _audit_records, verify_audit as _verify_audit, audit_summary as _audit_summary
from mitre.mapping import enrich as _enrich_mitre
from correlator.incident_identity import covered_by_block, local_addresses


ALERTS_FILE  = os.path.join(BASE_DIR, "alerts", "alerts.json")
COUNT_FILE   = os.path.join(BASE_DIR, "alerts", "count.json")
ML_METRICS_FILE = os.path.join(BASE_DIR, "ml_model", "metrics.json")
USERS_FILE   = os.path.join(os.path.dirname(__file__), "users.json")

# Global list to track running background engines
active_processes = []


# --------------------------------------------------------
# WAF Middleware: Inspection & IP Block Enforcement
# Intercepts requests from Mobile Apps, Browsers, & APIs
# --------------------------------------------------------
SQLI_PATTERNS = [
    r"(\%27|\'|\-\-|\%23|#)",
    r"\b(SELECT|INSERT|DELETE|UPDATE|DROP|UNION|ALTER|CREATE|EXEC)\b",
    r"\bOR\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+",
]

@app.before_request
def inspect_incoming_traffic():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    # 1. Enforce Firewall Blocklist
    if _blocker and _blocker.is_blocked(client_ip):
        return jsonify({
            "status": "error",
            "message": f"ACCESS DENIED: IP {client_ip} has been blocked by IDS Firewall.",
            "blocked": True
        }), 403

    # Skip internal static files
    if request.path.startswith("/static"):
        return

    # 2. Inspect for SQL Injection payloads in URL, headers, or body
    raw_query    = request.query_string.decode("utf-8", errors="ignore")

    # Skip body inspection on auth form POSTs to prevent false positives
    # on password fields that may contain SQL-like keywords
    auth_post = request.method == "POST" and request.path in ("/login", "/signup")
    raw_body     = "" if auth_post else (request.get_data(as_text=True) or "")
    full_payload = f"{request.path}?{raw_query} {raw_body}"

    found_sqli = False
    for pat in SQLI_PATTERNS:
        if re.search(pat, full_payload, re.IGNORECASE):
            found_sqli = True
            break

    if found_sqli:
        print(f"[WAF DETECT] SQL Injection attempt from {client_ip} -> {request.path}")
        # Send alert packet to UDP correlator
        try:
            alert_pkt = {
                "id":          int(time.time() * 1000),
                "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type":        "SNORT_SIGNATURE",
                "severity":    "HIGH",
                "src_ip":      client_ip,
                "dst_ip":      request.host.split(":")[0],
                "protocol":    "HTTP",
                "packet_size": len(full_payload),
                "packet_rate": 1,
                "confidence":  98.0,
                "message":     f"SQL Injection detected from {client_ip} on {request.path}",
            }
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(json.dumps(alert_pkt).encode("utf-8"), ("127.0.0.1", 9999))
            s.close()
        except Exception as _err:
            print(f"[WAF DETECT] Correlator alert send error: {_err}")


# --------------------------------------------------------
# User store helpers
# --------------------------------------------------------
def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def find_user(email):
    return next((u for u in load_users() if u["email"].lower() == email.lower()), None)


# --------------------------------------------------------
# Auth decorator
# --------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_email" not in session:
            # Return JSON 401 for API routes so the React frontend
            # receives a proper error instead of an HTML redirect.
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "Authentication required", "authenticated": False}), 401
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


# --------------------------------------------------------
# Helper: load alerts from JSON
# --------------------------------------------------------
def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    for _ in range(5):
        try:
            with open(ALERTS_FILE, "r") as f:
                data = json.load(f)
            # Strip heartbeat pings — they are not attack alerts
            attack_alerts = [_enrich_mitre(a) for a in data if a.get("type") != "HEARTBEAT"]
            return sorted(attack_alerts, key=lambda x: x.get("timestamp", ""), reverse=True)
        except (json.JSONDecodeError, ValueError):
            return []
        except OSError:
            time.sleep(0.05)
    return []


# --------------------------------------------------------
# Helper: compute stats
# --------------------------------------------------------
def compute_stats(alerts):
    # Try reading pre-computed counts from correlator's count.json first
    if os.path.exists(COUNT_FILE):
        try:
            with open(COUNT_FILE, "r") as f:
                cached = json.load(f)
            # Recompute protocols and avg_confidence from live alert list
            protocols = {}
            for a in alerts:
                p = a.get("protocol", "Unknown")
                protocols[p] = protocols.get(p, 0) + 1
            avg_confidence = (
                round(sum(a.get("confidence", 0) for a in alerts) / max(len(alerts), 1), 1)
                if alerts else 0
            )
            return {
                "total":          cached.get("total", len(alerts)),
                "high":           cached.get("high", 0),
                "medium":         cached.get("medium", 0),
                "low":            cached.get("low", 0),
                "protocols":      protocols,
                "avg_confidence": avg_confidence,
            }
        except Exception:
            pass

    # Fallback: compute from alert list directly
    total  = len(alerts)
    high   = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
    low    = sum(1 for a in alerts if a.get("severity") == "LOW")

    protocols = {}
    for a in alerts:
        p = a.get("protocol", "Unknown")
        protocols[p] = protocols.get(p, 0) + 1

    avg_confidence = (
        round(sum(a.get("confidence", 0) for a in alerts) / total, 1)
        if total > 0 else 0
    )

    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "protocols": protocols,
        "avg_confidence": avg_confidence,
    }


# --------------------------------------------------------
# PUBLIC ROUTES
# --------------------------------------------------------

@app.route("/")
def home():
    """Public landing page."""
    if "user_email" in session:
        return redirect(url_for("dashboard"))
    # The React UI is the public entry point; keeping this redirect also
    # avoids relying on an unbundled legacy landing-page template.
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            error = "Please fill in all fields."
        else:
            user = find_user(email)
            if user is None:
                error = "No account found with that email."
            elif not check_password_hash(user["password"], password):
                error = "Incorrect password. Please try again."
            else:
                session["user_email"]    = user["email"]
                session["user_username"] = user["username"]
                next_url = request.args.get("next") or url_for("dashboard")
                return redirect(next_url)

    return render_template("login.html", error=error)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_email" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        if not username or not email or not password or not confirm:
            error = "Please fill in all fields."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "Passwords do not match."
        elif find_user(email):
            error = "An account with that email already exists."
        else:
            users = load_users()
            users.append({
                "username": username,
                "email": email,
                "password": generate_password_hash(password),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
            save_users(users)
            return redirect(url_for("login") + "?registered=1")

    return render_template("signup.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


# --------------------------------------------------------
# PROTECTED DASHBOARD
# --------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    """Serve the current React UI; the old Flask dashboard has been retired."""
    # A production build is served directly by Flask. During development, send
    # the browser to Vite so no stale Flask template can ever be demonstrated.
    dist_html = os.path.join(BASE_DIR, "dashboard", "static", "dist", "index.html")
    if os.path.exists(dist_html):
        with open(dist_html, "r", encoding="utf-8") as f:
            return f.read()

    frontend_url = os.environ.get(
        "IDS_FRONTEND_URL",
        f"{request.scheme}://{request.host.split(':')[0]}:5173",
    )
    return redirect(frontend_url)


@app.route("/assets/<path:path>")
def send_dist_assets(path):
    from flask import send_from_directory
    dist_assets = os.path.join(BASE_DIR, "dashboard", "static", "dist", "assets")
    return send_from_directory(dist_assets, path)



# --------------------------------------------------------
# API ROUTES  (no session auth — React SPA uses its own UI-level auth)
# --------------------------------------------------------

@app.route("/api/alerts")
def api_alerts():
    alerts = load_alerts()
    entries = {e["ip"]: e for e in _blocker.get_all()} if _blocker else {}
    for alert in alerts:
        entry = entries.get(alert.get("src_ip"))
        alert["block_status"] = "not_blocked"
        if entry:
            result = entry.get("reachability_checks", {}).get(alert.get("dst_ip"), {})
            if result.get("reachable") is True:
                alert["block_status"] = "ineffective"
            elif covered_by_block(alert, entry):
                alert["block_status"] = "blocked_on_monitor"
            else:
                alert["block_status"] = "monitor_only" if entry.get("firewall_rule") else "unverified"
    return jsonify({"count": len(alerts), "alerts": alerts})


@app.route("/api/stats")
def api_stats():
    """Fast stats: read pre-computed count.json written by correlator."""
    # Fast path: read tiny count.json maintained by correlator
    if os.path.exists(COUNT_FILE):
        try:
            with open(COUNT_FILE, "r") as f:
                stats = json.load(f)
            # Ensure all expected keys exist
            for k in ("total", "high", "medium", "low", "avg_confidence"):
                stats.setdefault(k, 0)
            return jsonify(stats)
        except (json.JSONDecodeError, OSError):
            pass
    # Fallback: compute from alerts (slower, used only on first load)
    alerts = load_alerts()
    stats  = compute_stats(alerts)
    return jsonify(stats)


@app.route("/api/ml/metrics")
def api_ml_metrics():
    """Return held-out evaluation metrics from the latest training run."""
    try:
        with open(ML_METRICS_FILE, "r", encoding="utf-8") as handle:
            return jsonify(json.load(handle))
    except (OSError, json.JSONDecodeError):
        return jsonify({"status": "not_trained", "message": "Run ml_model/train_model.py to generate held-out evaluation metrics."})


@app.route("/api/endpoints")
def api_endpoints():
    """Return endpoint-agent inventory with computed online/offline state."""
    if _get_endpoints is None:
        return jsonify({"status": "error", "message": "Endpoint registry unavailable"}), 503
    endpoints = _sqlite_endpoints() or _get_endpoints()
    from datetime import timezone
    now_utc = datetime.now(timezone.utc)
    for endpoint in endpoints:
        try:
            seen = datetime.strptime(endpoint["last_seen"], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
            endpoint["status"] = "online" if (now_utc - seen).total_seconds() <= 90 else "offline"
        except (KeyError, ValueError):
            endpoint["status"] = "offline"
    return jsonify({
        "status": "ok",
        "total": len(endpoints),
        "online": sum(item.get("status") == "online" for item in endpoints),
        "endpoints": endpoints,
    })


@app.route("/api/timeline")
def api_timeline():
    """Unified detection-to-response audit timeline, newest event first."""
    limit = min(max(request.args.get("limit", 80, type=int), 1), 300)
    return jsonify({"status": "ok", "events": _timeline(limit, request.args.get("ip"))})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
    with open(ALERTS_FILE, "w") as f:
        json.dump([], f)

    flag_path = os.path.join(os.path.dirname(ALERTS_FILE), "clear.flag")
    with open(flag_path, "w") as f:
        f.write("1")
    _clear_history()

    return jsonify({"status": "ok", "message": "All alerts cleared."})


@app.route("/api/reset_all_data", methods=["POST"])
def api_reset_all_data():
    """Reset live alerts, response data, TI cache, and the local audit log for a clean demonstration run."""
    try:
        # 1. Clear live alerts
        os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
        with open(ALERTS_FILE, "w") as f:
            json.dump([], f)

        flag_path = os.path.join(os.path.dirname(ALERTS_FILE), "clear.flag")
        with open(flag_path, "w") as f:
            f.write("1")

        # 2. Reset threat scores
        if os.path.exists(THREAT_SCORE_FILE):
            with open(THREAT_SCORE_FILE, "w") as f:
                json.dump({}, f)

        # 3. Reset incident log
        if os.path.exists(INCIDENT_LOG_FILE):
            with open(INCIDENT_LOG_FILE, "w") as f:
                json.dump([], f)

        # 4. Reset Threat Intel cache
        ti_cache = os.path.join(BASE_DIR, "threat_intel", "ti_cache.json")
        if os.path.exists(ti_cache):
            with open(ti_cache, "w") as f:
                json.dump({}, f)

        _clear_history()

        return jsonify({"status": "ok", "message": "All demo attack data, threat scores, incident logs, and audit records have been reset."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# --------------------------------------------------------
# Helper: spawn a script in a new console window
# --------------------------------------------------------
def _launch(script_path):
    cmd    = [sys.executable, script_path]
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_CONSOLE
    proc = subprocess.Popen(cmd, cwd=BASE_DIR, **kwargs)
    active_processes.append(proc)
    return proc

def _stop_all_processes():
    global active_processes
    for proc in active_processes:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    active_processes.clear()


@app.route("/api/start_engine", methods=["POST"])
def api_start_engine():
    try:
        # First ensure any old zombie processes are killed
        _stop_all_processes()

        # 1. Start Correlator first
        _launch(os.path.join(BASE_DIR, "correlator", "correlator.py"))
        time.sleep(1)

        # 2. Start ML Random Forest anomaly engine
        _launch(os.path.join(BASE_DIR, "ml_model", "detect.py"))

        # 3. Start LSTM Autoencoder engine (if model trained)
        ae_model = os.path.join(BASE_DIR, "ml_model", "autoencoder_model.keras")
        if os.path.exists(ae_model):
            _launch(os.path.join(BASE_DIR, "ml_model", "autoencoder.py"))
            lstm_msg = " + LSTM Autoencoder"
        else:
            lstm_msg = " (LSTM not trained — run train_autoencoder.py)"

        # 4. Start DNS Tunnel monitor
        _launch(os.path.join(BASE_DIR, "network_monitor", "dns_monitor.py"))

        # 5. Start real Snort (if installed)
        snort_reader = os.path.join(BASE_DIR, "snort", "snort_reader.py")
        snort_exe    = r"C:\Snort\bin\snort.exe"
        if os.path.exists(snort_exe) and os.path.exists(snort_reader):
            _launch(snort_reader)
            snort_msg = " + Real Snort"
        else:
            snort_msg = " (Snort not installed — ML only)"

        msg = f"IDS Engine started (RF ML{lstm_msg} + DNS Monitor{snort_msg})."
        return jsonify({"status": "ok", "message": msg})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/stop_engine", methods=["POST"])
def api_stop_engine():
    try:
        _stop_all_processes()
        return jsonify({"status": "ok", "message": "IDS Engine stopped."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/test_email", methods=["POST"])
def api_test_email():
    try:
        _launch(os.path.join(BASE_DIR, "email_alert", "send_alert.py"))
        return jsonify({"status": "ok", "message": "Test email dispatched."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# --------------------------------------------------------
# HASH-CHAINED AUDIT API ROUTES
# --------------------------------------------------------

@app.route("/api/audit")
def api_audit():
    return jsonify({"status": "ok", "records": _audit_records()})


@app.route("/api/audit/verify")
def api_audit_verify():
    valid, broken_at = _verify_audit()
    return jsonify({
        "status": "ok", "valid": valid, "broken_at": broken_at,
        "message": "Audit integrity verified" if valid else f"Audit record {broken_at} failed verification",
    })


@app.route("/api/audit/stats")
def api_audit_stats():
    return jsonify({"status": "ok", **_audit_summary()})


# --------------------------------------------------------
# FIREWALL / IP BLOCK API ROUTES
# --------------------------------------------------------

@app.route("/api/firewall/blocked")
def api_blocked_list():
    """Return all currently blocked IPs."""
    if _blocker is None:
        return jsonify({"status": "error", "message": "Blocker not available"}), 503
    try:
        entries = _blocker.get_all()
        verified = [e["ip"] for e in entries if e.get("firewall_rule")]
        return jsonify({"status": "ok", "blocked": entries, "blocked_ips": verified,
                        "total_blocked": len(entries), "firewall_applied": len(verified),
                        "software_only": len(entries) - len(verified)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/firewall/block/<path:ip>", methods=["POST"])
def api_block_ip(ip):
    """Block an attacker IP (adds to blocklist + applies Windows Firewall rule)."""
    if _blocker is None:
        return jsonify({"status": "error", "message": "Blocker not available"}), 503
    try:
        data        = request.get_json(silent=True) or {}
        reason      = data.get("reason", "Blocked from IDS dashboard")
        blocked_by  = session.get("user_username", "admin")
        severity    = data.get("severity", "UNKNOWN")
        attack_type = data.get("attack_type", "UNKNOWN")

        existing = _blocker.get_entry(ip)
        if existing and existing.get("firewall_rule"):
            return jsonify({"status": "ok", "message": f"{ip} is already blocked.", "already_blocked": True})

        entry = _blocker.block_ip(ip, reason=reason, blocked_by=blocked_by,
                                   severity=severity, attack_type=attack_type)
        stage = "BLOCKED" if entry.get("firewall_rule") else "BLOCK_REQUESTED"
        title = "Windows Firewall blocked source IP" if entry.get("firewall_rule") else "Software-only block recorded"
        _record_stage(ip, stage, title, reason, severity)

        fw_msg = " + Windows Firewall rule applied" if entry.get("firewall_rule") else " (software-only — run as admin for OS firewall)"
        return jsonify({
            "status":  "ok",
            "message": (f"Inbound block verified on monitoring PC for {ip}." if entry.get("firewall_rule")
                        else f"Block requested for {ip}; OS enforcement is unverified. Run as administrator and retry."),
            "entry":   entry,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/firewall/unblock/<path:ip>", methods=["DELETE"])
def api_unblock_ip(ip):
    """Unblock a previously blocked IP."""
    if _blocker is None:
        return jsonify({"status": "error", "message": "Blocker not available"}), 503
    try:
        ok = _blocker.unblock_ip(ip)
        if not ok:
            return jsonify({"status": "error", "message": f"{ip} was not in the blocklist."}), 404
        return jsonify({"status": "ok", "message": f"IP {ip} has been UNBLOCKED."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/firewall/check/<path:ip>")
def api_check_ip(ip):
    """Check if a given IP is currently blocked."""
    if _blocker is None:
        return jsonify({"status": "error", "message": "Blocker not available"}), 503
    entry = _blocker.get_entry(ip)
    return jsonify({"status": "ok", "ip": ip, "blocked": bool(entry and entry.get("firewall_rule")),
                    "application_blocklisted": bool(entry), "scope": "monitoring_pc", "entry": entry})


@app.route("/api/firewall/reachability/<path:ip>", methods=["POST"])
def api_record_reachability(ip):
    data = request.get_json(silent=True) or {}
    if _blocker is None:
        return jsonify({"status": "error", "message": "Blocker unavailable"}), 503
    if type(data.get("reachable")) is not bool or data.get("target_ip") not in local_addresses():
        return jsonify({"status": "error", "message": "Choose a monitoring-PC IP and a test result."}), 400
    note = str(data.get("note", "")).strip()
    if not note or len(note) > 500:
        return jsonify({"status": "error", "message": "Describe the tested service (up to 500 characters)."}), 400
    try:
        entry = _blocker.record_reachability(ip, data["target_ip"], data["reachable"], note)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    failed = data["reachable"]
    _record_stage(ip, "BLOCK_INEFFECTIVE" if failed else "BLOCK_TEST_RECORDED",
                  "Operator reported service reachable" if failed else "Operator reported service unreachable",
                  f"Target {data['target_ip']}: {note}", "HIGH" if failed else "INFO")
    return jsonify({"status": "ok", "entry": entry})


# --------------------------------------------------------
# INCIDENT RESPONSE API ROUTES
# --------------------------------------------------------

RESPONSE_DIR        = os.path.join(BASE_DIR, "response")
INCIDENT_LOG_FILE   = os.path.join(RESPONSE_DIR, "incident_log.json")
THREAT_SCORE_FILE   = os.path.join(RESPONSE_DIR, "threat_scores.json")
PLAYBOOKS_FILE      = os.path.join(RESPONSE_DIR, "playbooks.json")


@app.route("/api/response/incidents")
def api_incidents():
    """Return all incident log entries, newest first."""
    try:
        if not os.path.exists(INCIDENT_LOG_FILE):
            return jsonify({"status": "ok", "total": 0, "incidents": []})
        with open(INCIDENT_LOG_FILE, "r") as f:
            data = json.load(f)
        # Sort newest first
        data_sorted = sorted(data, key=lambda x: x.get("timestamp", ""), reverse=True)
        return jsonify({"status": "ok", "total": len(data_sorted), "incidents": data_sorted})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/response/threat_scores")
def api_threat_scores():
    """Return per-IP threat scores, sorted highest first."""
    try:
        if not os.path.exists(THREAT_SCORE_FILE):
            return jsonify({"status": "ok", "total": 0, "scores": []})
        with open(THREAT_SCORE_FILE, "r") as f:
            data = json.load(f)
        scores_list = sorted(data.values(), key=lambda x: x.get("score", 0), reverse=True)
        return jsonify({"status": "ok", "total": len(scores_list), "scores": scores_list})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/response/playbooks")
def api_playbooks():
    """Return active playbook rules."""
    try:
        if not os.path.exists(PLAYBOOKS_FILE):
            return jsonify({"status": "ok", "total": 0, "playbooks": []})
        with open(PLAYBOOKS_FILE, "r") as f:
            data = json.load(f)
        return jsonify({"status": "ok", "total": len(data), "playbooks": data})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# --------------------------------------------------------
# Run
# --------------------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("  IDS Dashboard running at http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)
