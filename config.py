# =============================================================================
# PhishShield — Configuration
# Replace placeholder values with your real API keys before deployment.
# NEVER commit real keys to version control.
# =============================================================================

import os

# ─── VirusTotal ────────────────────────────────────────────────────────────────
# Free key: https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "")
VIRUSTOTAL_URL_SCAN   = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{id}"

# ─── Google Safe Browsing (optional fallback) ──────────────────────────────────
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "YOUR_GOOGLE_API_KEY_HERE")
GOOGLE_SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    "?key={key}"
)

# ─── Application ──────────────────────────────────────────────────────────────
DEBUG          = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
PORT           = int(os.environ.get("PORT", 5000))
HOST           = os.environ.get("HOST", "0.0.0.0")
SECRET_KEY     = os.environ.get("SECRET_KEY", "phishshield-dev-key-change-in-prod")

# ─── Timeouts (seconds) ───────────────────────────────────────────────────────
SSL_TIMEOUT    = 5
WHOIS_TIMEOUT  = 8
API_TIMEOUT    = 10

# ─── Scoring thresholds ───────────────────────────────────────────────────────
SAFE_MAX       = 30
SUSPICIOUS_MAX = 60
# Above SUSPICIOUS_MAX → PHISHING

# ─── Domain age threshold ─────────────────────────────────────────────────────
YOUNG_DOMAIN_DAYS = 180   # domains younger than this are flagged
