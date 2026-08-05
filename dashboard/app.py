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

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Blockchain ledger — lazy import so app boots even before correlator runs
try:
    sys.path.insert(0, BASE_DIR)
    from blockchain.blockchain import AttackerBlockchain as _BC
    _blockchain = _BC()
except Exception as _bc_err:
    _blockchain = None
    print(f"[DASHBOARD] Blockchain unavailable: {_bc_err}")

# IP Blocker — lazy import
try:
    from firewall.ip_blocker import IPBlocker as _IB
    _blocker = _IB()
except Exception as _fw_err:
    _blocker = None
    print(f"[DASHBOARD] IP Blocker unavailable: {_fw_err}")


ALERTS_FILE  = os.path.join(BASE_DIR, "alerts", "alerts.json")
COUNT_FILE   = os.path.join(BASE_DIR, "alerts", "count.json")
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
            attack_alerts = [a for a in data if a.get("type") != "HEARTBEAT"]
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
    return render_template("home.html")


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
    alerts = load_alerts()
    stats  = compute_stats(alerts)
    now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    username = session.get("user_username", "User")
    return render_template("index.html", alerts=alerts, stats=stats,
                           last_updated=now, username=username)


# --------------------------------------------------------
# API ROUTES  (all login-required)
# --------------------------------------------------------

@app.route("/api/alerts")
@login_required
def api_alerts():
    alerts = load_alerts()
    return jsonify({"count": len(alerts), "alerts": alerts})


@app.route("/api/stats")
@login_required
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


@app.route("/api/clear", methods=["POST"])
@login_required
def api_clear():
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
    with open(ALERTS_FILE, "w") as f:
        json.dump([], f)

    flag_path = os.path.join(os.path.dirname(ALERTS_FILE), "clear.flag")
    with open(flag_path, "w") as f:
        f.write("1")

    return jsonify({"status": "ok", "message": "All alerts cleared."})


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
@login_required
def api_start_engine():
    try:
        # First ensure any old zombie processes are killed
        _stop_all_processes()
        
        # Start Correlator first
        _launch(os.path.join(BASE_DIR, "correlator", "correlator.py"))
        time.sleep(1)
        
        # Start ML anomaly engine
        _launch(os.path.join(BASE_DIR, "ml_model", "detect.py"))
        
        # Start real Snort (if installed)
        snort_reader = os.path.join(BASE_DIR, "snort", "snort_reader.py")
        snort_exe    = r"C:\Snort\bin\snort.exe"
        if os.path.exists(snort_exe) and os.path.exists(snort_reader):
            _launch(snort_reader)
            msg = "IDS Engine started (ML + Real Snort)."
        else:
            msg = "IDS Engine started (ML only — Snort not installed)."
        return jsonify({"status": "ok", "message": msg})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/stop_engine", methods=["POST"])
@login_required
def api_stop_engine():
    try:
        _stop_all_processes()
        return jsonify({"status": "ok", "message": "IDS Engine stopped."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/test_email", methods=["POST"])
@login_required
def api_test_email():
    try:
        _launch(os.path.join(BASE_DIR, "email_alert", "send_alert.py"))
        return jsonify({"status": "ok", "message": "Test email dispatched."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# --------------------------------------------------------
# BLOCKCHAIN API ROUTES  (all login-required)
# --------------------------------------------------------

@app.route("/api/blockchain")
@login_required
def api_blockchain():
    """Return all blocks in the chain."""
    if _blockchain is None:
        return jsonify({"status": "error", "message": "Blockchain not available"}), 503
    try:
        records = _blockchain.get_all_records()
        return jsonify({"status": "ok", "total_blocks": len(records), "blocks": records})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/blockchain/verify")
@login_required
def api_blockchain_verify():
    """Verify full chain integrity."""
    if _blockchain is None:
        return jsonify({"status": "error", "message": "Blockchain not available"}), 503
    try:
        valid, broken_at = _blockchain.is_chain_valid()
        return jsonify({
            "status":     "ok",
            "valid":      valid,
            "broken_at":  broken_at,
            "message":    "Chain integrity verified ✅" if valid else f"⚠️ Chain TAMPERED at block #{broken_at}",
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/blockchain/attacker/<path:ip>")
@login_required
def api_blockchain_attacker(ip):
    """Return all blocks for a specific attacker IP."""
    if _blockchain is None:
        return jsonify({"status": "error", "message": "Blockchain not available"}), 503
    try:
        records = _blockchain.get_attacker_records(ip)
        return jsonify({"status": "ok", "ip": ip, "count": len(records), "blocks": records})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/blockchain/stats")
@login_required
def api_blockchain_stats():
    """Aggregated attacker stats from the blockchain."""
    if _blockchain is None:
        return jsonify({"status": "error", "message": "Blockchain not available"}), 503
    try:
        summary = _blockchain.get_attacker_summary()
        valid, broken_at = _blockchain.is_chain_valid()
        summary["chain_valid"]  = valid
        summary["broken_at"]   = broken_at
        return jsonify({"status": "ok", **summary})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# --------------------------------------------------------
# FIREWALL / IP BLOCK API ROUTES  (all login-required)
# --------------------------------------------------------

@app.route("/api/firewall/blocked")
@login_required
def api_blocked_list():
    """Return all currently blocked IPs."""
    if _blocker is None:
        return jsonify({"status": "error", "message": "Blocker not available"}), 503
    try:
        stats = _blocker.get_stats()
        return jsonify({"status": "ok", "blocked": _blocker.get_all(), **stats})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/firewall/block/<path:ip>", methods=["POST"])
@login_required
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

        if _blocker.is_blocked(ip):
            return jsonify({"status": "ok", "message": f"{ip} is already blocked.", "already_blocked": True})

        entry = _blocker.block_ip(ip, reason=reason, blocked_by=blocked_by,
                                   severity=severity, attack_type=attack_type)

        # Also commit the block event to the blockchain ledger
        if _blockchain:
            _blockchain.add_block({
                "type":       "IP_BLOCKED",
                "severity":   "HIGH",
                "src_ip":     ip,
                "dst_ip":     "0.0.0.0",
                "protocol":   "ANY",
                "confidence": 100.0,
                "blocked_by": blocked_by,
                "reason":     reason,
                "message":    f"IP {ip} manually BLOCKED by {blocked_by}: {reason}",
            })

        fw_msg = " + Windows Firewall rule applied" if entry.get("firewall_rule") else " (software-only — run as admin for OS firewall)"
        return jsonify({
            "status":  "ok",
            "message": f"IP {ip} has been BLOCKED.{fw_msg}",
            "entry":   entry,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/firewall/unblock/<path:ip>", methods=["DELETE"])
@login_required
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
@login_required
def api_check_ip(ip):
    """Check if a given IP is currently blocked."""
    if _blocker is None:
        return jsonify({"status": "error", "message": "Blocker not available"}), 503
    blocked = _blocker.is_blocked(ip)
    entry   = _blocker.get_entry(ip) if blocked else None
    return jsonify({"status": "ok", "ip": ip, "blocked": blocked, "entry": entry})


# --------------------------------------------------------
# Run
# --------------------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("  IDS Dashboard running at http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)
