"""
=============================================================
telegram_alert/telegram_bot.py  -  IDS_Snort_Project
=============================================================
Real-Time Telegram Notifications for IDS Alerts.

Sends instant Telegram messages when HIGH or MEDIUM severity
attacks are detected on any device (HP direct or victim agent).

SETUP (one-time, 2 minutes):
  1. Open Telegram and search for @BotFather
  2. Send /newbot  -> follow prompts -> copy the Token
  3. Open your bot, send /start
  4. Visit: https://api.telegram.org/bot<TOKEN>/getUpdates
     Copy your "chat":{"id": XXXXXXXX}
  5. Paste both below and save.
=============================================================
"""

import urllib.request
import urllib.parse
import json
import threading
import time
import os

# =============================================================
# CONFIGURATION  <-- Fill these in
# =============================================================
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8449036981:AAEwm7HMItL3xMRJ9BeJ0I8-FElDQIFm-UE")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID",   "7137557113")
# =============================================================

# Only alert on these severities (set to ["HIGH"] to reduce noise)
ALERT_SEVERITIES = {"HIGH", "MEDIUM"}

# Rate-limit: don't send more than 1 message per IP per N seconds
COOLDOWN_SECONDS = 15
_last_sent = {}   # src_ip -> last epoch time sent
_lock = threading.Lock()

TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"


def _is_configured():
    return (
        TELEGRAM_BOT_TOKEN not in ("", "YOUR_BOT_TOKEN_HERE") and
        TELEGRAM_CHAT_ID   not in ("", "YOUR_CHAT_ID_HERE")
    )


def _build_message(alert: dict) -> str:
    sev      = alert.get("severity", "?")
    src_ip   = alert.get("src_ip", "?")
    dst_ip   = alert.get("dst_ip", "?")
    proto    = alert.get("protocol", "?")
    msg      = alert.get("message", "")
    ts       = alert.get("timestamp", "")
    conf     = alert.get("confidence", 0)
    rby      = alert.get("reported_by", "DIRECT")
    vname    = alert.get("victim_name", "")
    atype    = alert.get("alert_type", alert.get("type", "ALERT"))

    # Severity emoji
    sev_icon = {"HIGH": "🚨", "MEDIUM": "⚠️", "LOW": "🔵"}.get(sev, "❓")

    # Source icon
    src_icon = "📡" if rby == "VICTIM_AGENT" else ("🛡️" if rby == "WAF" else "🖥️")
    src_label = f"Victim Agent ({vname})" if vname else rby

    lines = [
        f"{sev_icon} <b>IDS ALERT — {sev}</b>",
        f"",
        f"🎯 <b>Attack Type:</b> <code>{atype}</code>",
        f"🌐 <b>Attacker IP:</b> <code>{src_ip}</code>",
        f"🖥 <b>Victim IP:</b>   <code>{dst_ip}</code>",
        f"📶 <b>Protocol:</b>    <code>{proto}</code>",
        f"📊 <b>Confidence:</b>  {conf}%",
        f"{src_icon} <b>Detected by:</b> {src_label}",
        f"🕐 <b>Time:</b>       {ts}",
        f"",
        f"💬 <i>{msg}</i>",
        f"",
        f"🔗 Dashboard: http://localhost:5000",
    ]
    return "\n".join(lines)


def send_telegram_alert(alert: dict) -> bool:
    """
    Send a Telegram message for this alert.
    Returns True if sent, False if skipped (cooldown/unconfigured) or failed.
    """
    if not _is_configured():
        return False

    severity = alert.get("severity", "")
    if severity not in ALERT_SEVERITIES:
        return False

    # Skip HEARTBEAT alerts
    if alert.get("type") == "HEARTBEAT":
        return False

    src_ip = alert.get("src_ip", "")

    # Rate limiting per source IP
    now = time.time()
    with _lock:
        last = _last_sent.get(src_ip, 0)
        if now - last < COOLDOWN_SECONDS:
            return False
        _last_sent[src_ip] = now

    text = _build_message(alert)

    payload = json.dumps({
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       text,
        "parse_mode": "HTML",
    }).encode("utf-8")

    req = urllib.request.Request(
        TELEGRAM_API,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            resp = json.loads(r.read())
            if resp.get("ok"):
                print(f"[TELEGRAM] Alert sent for {src_ip} ({severity})")
                return True
            else:
                print(f"[TELEGRAM] API error: {resp}")
                return False
    except Exception as e:
        print(f"[TELEGRAM] Send failed: {e}")
        return False


def send_telegram_in_background(alert: dict):
    """Non-blocking: fire-and-forget Telegram alert on a daemon thread."""
    t = threading.Thread(target=send_telegram_alert, args=(alert,), daemon=True)
    t.start()


def test_connection() -> bool:
    """Send a test message to verify bot token + chat ID work."""
    if not _is_configured():
        print("[TELEGRAM] Not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.")
        return False

    test_alert = {
        "severity":   "HIGH",
        "src_ip":     "1.2.3.4",
        "dst_ip":     "192.168.1.50",
        "protocol":   "TCP",
        "confidence": 99.0,
        "type":       "TEST",
        "timestamp":  time.strftime("%Y-%m-%d %H:%M:%S"),
        "message":    "IDS Telegram integration test - system is working!",
        "reported_by": "DIRECT",
    }
    print("[TELEGRAM] Sending test message...")
    ok = send_telegram_alert(test_alert)
    if ok:
        print("[TELEGRAM] Test message sent! Check your Telegram.")
    return ok


if __name__ == "__main__":
    test_connection()
