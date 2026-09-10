"""
=============================================================
threat_intel/threat_intel.py  —  IDS_Snort_Project
=============================================================
Threat Intelligence Enrichment Engine.

IP enrichment uses one clear primary provider: ipinfo.io for country, city,
network/ASN and hostname context. It provides context; it is not a maliciousness verdict.

Design:
  • Non-blocking : runs lookups in a background daemon thread
  • TTL cache    : results cached for 1 hour per IP (ti_cache.json)
  • Graceful     : any missing API key is silently skipped

Public API:
  enrich_alert_async(alert_dict, alerts_list, lock, save_fn)
    — enriches alert in background, updates the alert dict in-place,
      then calls save_fn() to persist the change
=============================================================
"""

import os
import sys
import json
import time
import threading
import urllib.request
import urllib.error
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from threat_intel.config import (
    IPINFO_KEY, IPINFO_IP_URL,
    TI_CACHE_TTL, TI_CACHE_FILE,
    IPINFO_MIN_INTERVAL,
    SUSPICIOUS_ORG_KEYWORDS,
)

# ── Private/reserved IPs — never send these to external APIs ─
_PRIVATE_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.", "169.254.", "::1", "fc", "fd",
)

# ── Rate-limit state (module-level, shared across all calls) ──
_last_ipinfo_call  = [0.0]
_ipinfo_lock = threading.Lock()

# ── Disk cache ────────────────────────────────────────────────
_cache: dict = {}
_cache_lock   = threading.Lock()
_cache_loaded = [False]


# ─────────────────────────────────────────────────────────────
# Cache helpers
# ─────────────────────────────────────────────────────────────
def _load_cache():
    global _cache
    if _cache_loaded[0]:
        return
    if os.path.exists(TI_CACHE_FILE):
        try:
            with open(TI_CACHE_FILE, "r") as f:
                _cache = json.load(f)
        except Exception:
            _cache = {}
    _cache_loaded[0] = True


def _save_cache():
    try:
        tmp = TI_CACHE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_cache, f, indent=2)
        os.replace(tmp, TI_CACHE_FILE)
    except Exception as e:
        print(f"[TI] Cache save error: {e}")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _get_cached(ip: str) -> dict | None:
    with _cache_lock:
        _load_cache()
        entry = _cache.get(ip)
        if entry and time.time() - entry.get("cached_at", 0) < TI_CACHE_TTL:
            return entry
    return None


def _set_cache(ip: str, data: dict):
    with _cache_lock:
        data["cached_at"] = time.time()
        _cache[ip] = data
        _save_cache()


# ─────────────────────────────────────────────────────────────
# ipinfo.io  (PRIMARY — works with Google/GitHub sign-in)
# ─────────────────────────────────────────────────────────────
def _lookup_ipinfo(ip: str) -> dict:
    """
    Query ipinfo.io for IP geolocation, ASN, and org data.
    Works with or without an API key (token raises limit from 1k to 50k/month).
    """
    with _ipinfo_lock:
        wait = IPINFO_MIN_INTERVAL - (time.time() - _last_ipinfo_call[0])
        if wait > 0:
            time.sleep(wait)
        _last_ipinfo_call[0] = time.time()

    try:
        # Works without a key too (1000 req/day free)
        url = IPINFO_IP_URL.format(ip=ip)
        if IPINFO_KEY:
            url += f"?token={IPINFO_KEY}"

        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())

        # Parse org / ASN field (format: "AS12345 Cloudflare, Inc.")
        org_raw = data.get("org", "")
        asn = ""
        org = org_raw
        if org_raw.startswith("AS"):
            parts = org_raw.split(" ", 1)
            asn = parts[0] if parts else ""
            org = parts[1] if len(parts) > 1 else org_raw

        country  = data.get("country", "??")
        city     = data.get("city", "")
        region   = data.get("region", "")
        hostname = data.get("hostname", "")
        bogon    = data.get("bogon", False)

        # Heuristic: check if org looks like a suspicious hosting provider
        org_lower = org.lower()
        suspicious_org = any(kw in org_lower for kw in SUSPICIOUS_ORG_KEYWORDS)

        location_str = ", ".join(filter(None, [city, region, country]))

        result = {
            "ti_country":       country,
            "ti_city":          city,
            "ti_region":        region,
            "ti_location":      location_str,
            "ti_org":           org,
            "ti_asn":           asn,
            "ti_hostname":      hostname,
            "ti_bogon":         bogon,
            "ti_suspicious_org": suspicious_org,
            "ti_source":        "ipinfo.io",
        }

        return result

    except urllib.error.HTTPError as e:
        if e.code == 429:
            print(f"[TI] ipinfo.io rate limit hit for {ip}")
        elif e.code == 403:
            print(f"[TI] ipinfo.io: invalid token for {ip}")
        return {}
    except Exception as e:
        print(f"[TI] ipinfo.io error for {ip}: {e}")
        return {}


# ─────────────────────────────────────────────────────────────
# Main enrichment function (runs in background thread)
# ─────────────────────────────────────────────────────────────
def _do_enrich(alert: dict, alerts_list, lock, save_fn):
    src_ip = alert.get("src_ip", "")
    if not src_ip or _is_private(src_ip):
        return   # Never query TI for private/local IPs

    # Check TTL cache first
    cached = _get_cached(src_ip)
    if cached:
        ti_data = {k: v for k, v in cached.items() if k != "cached_at"}
    else:
        ti_data = _lookup_ipinfo(src_ip)

        if not ti_data:
            return   # All sources returned nothing

        _set_cache(src_ip, ti_data)

    # ── Determine confirmed-malicious flag ────────────────────
    bogon       = ti_data.get("ti_bogon", False)
    ti_confirmed = bool(bogon)
    ti_data["ti_confirmed"]   = ti_confirmed
    ti_data["ti_enriched_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Context does not alter severity; only a reserved/bogon address is elevated.
    if ti_confirmed and alert.get("severity") != "HIGH":
        ti_data["ti_escalated"] = True
        alert["severity"]  = "HIGH"
        alert["confidence"] = round(
            min(99.0, max(float(alert.get("confidence", 70)), 75.0)), 1
        )

    # ── Update alert in-place (thread-safe) ──────────────────
    with lock:
        alert.update(ti_data)
        save_fn()

    country = ti_data.get("ti_country", "??")
    org     = ti_data.get("ti_org", "")
    print(
        f"[TI] {src_ip:>15}  "
        f"Country={country:3}  "
        f"Org={org[:30]:<30}  "
        f"Context={'reserved' if bogon else 'network metadata'}"
    )


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────
def enrich_alert_async(alert: dict, alerts_list, lock, save_fn):
    """
    Kick off TI enrichment for an alert in a daemon thread.
    Returns immediately — caller is never blocked.
    """
    t = threading.Thread(
        target=_do_enrich,
        args=(alert, alerts_list, lock, save_fn),
        daemon=True,
    )
    t.start()
