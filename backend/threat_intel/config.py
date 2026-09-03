"""
=============================================================
threat_intel/config.py  —  IDS_Snort_Project
=============================================================
API key configuration for Threat Intelligence lookups.

How to get free API keys (no email verification headaches):
─────────────────────────────────────────────────────────────
  ★ ipinfo.io (RECOMMENDED — sign in with Google/GitHub, instant):
      1. Go to https://ipinfo.io/signup
      2. Click "Continue with Google" — no email verification needed
      3. Copy your token from https://ipinfo.io/account/home
      4. set IPINFO_KEY=your_token_here
      Free tier: 50,000 requests/month

─────────────────────────────────────────────────────────────
"""

import os

# ── ipinfo.io (PRIMARY — recommended, works without email verify) ──
IPINFO_KEY      = os.environ.get("IPINFO_KEY", "")
IPINFO_IP_URL   = "https://ipinfo.io/{ip}/json"

# ── Cache ─────────────────────────────────────────────────
TI_CACHE_TTL  = 3600   # seconds (1 hour per IP)
TI_CACHE_FILE = os.path.join(os.path.dirname(__file__), "ti_cache.json")

# ── Rate limiting ─────────────────────────────────────────
IPINFO_MIN_INTERVAL     = 0.05   # 50ms — very generous free tier
# ── Context labels (never an automatic maliciousness verdict) ──
SUSPICIOUS_ORG_KEYWORDS = [
    "tor-exit", "tor exit", "vpn", "proxy", "hosting",
    "bulletproof", "bullet-proof", "scan", "crawler",
]
