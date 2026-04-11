# =============================================================================
# PhishShield — WHOIS Domain Lookup Module
# Checks domain age and registration metadata. Returns risk score (0–20).
# =============================================================================

import datetime
from urllib.parse import urlparse
from typing import Dict, Any
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


def whois_lookup(url: str) -> Dict[str, Any]:
    """
    Perform a WHOIS lookup for the domain in `url`.

    Returns:
        dict with keys:
          - score      (int 0–20)
          - flags      (list[str])
          - details    (dict)
    """
    flags: list[str] = []
    score = 0
    details: Dict[str, Any] = {}

    if not WHOIS_AVAILABLE:
        return {
            "score": 5,
            "flags": ["python-whois library not installed — WHOIS skipped (+5)"],
            "details": {"error": "library_missing"},
        }

    # ── Extract domain ────────────────────────────────────────────────────────
    try:
        parsed   = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
        hostname = parsed.hostname or parsed.netloc.split(":")[0]
        # Use registrable domain (last two labels) for WHOIS
        parts    = hostname.split(".")
        domain   = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    except Exception as exc:
        return {"score": 10, "flags": [f"Cannot parse domain: {exc}"], "details": {}}

    details["queried_domain"] = domain

    # ── Run WHOIS ─────────────────────────────────────────────────────────────
    try:
        w = python_whois.whois(domain)
    except Exception as exc:
        # WHOIS failure is non-fatal; assign moderate score
        return {
            "score": 8,
            "flags": [f"WHOIS lookup failed for '{domain}': {type(exc).__name__} (+8)"],
            "details": {"error": str(exc), "queried_domain": domain},
        }

    # ── Extract creation date ─────────────────────────────────────────────────
    creation_date = w.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    expiry_date = w.expiration_date
    if isinstance(expiry_date, list):
        expiry_date = expiry_date[0]

    registrar       = getattr(w, "registrar", None) or "Unknown"
    registrant_name = getattr(w, "name", None) or "Unknown / Redacted"
    country         = getattr(w, "country", None) or "Unknown"
    dnssec          = getattr(w, "dnssec", None) or "Unknown"

    details["registrar"]        = str(registrar)
    details["registrant"]       = str(registrant_name)
    details["country"]          = str(country)
    details["dnssec"]           = str(dnssec)

    # ── Rule 1: Domain age ────────────────────────────────────────────────────
    if creation_date and isinstance(creation_date, datetime.datetime):
        now       = datetime.datetime.utcnow()
        age_days  = (now - creation_date).days
        details["creation_date"] = creation_date.isoformat()
        details["domain_age_days"] = age_days

        if age_days < 0:
            # Likely a data error; treat as unknown
            flags.append("Domain creation date in the future — data anomaly")
        elif age_days < 30:
            score += 20
            flags.append(f"Domain is only {age_days} days old — extremely new (+20)")
        elif age_days < config.YOUNG_DOMAIN_DAYS:
            score += 12
            flags.append(f"Domain is {age_days} days old (< 6 months) (+12)")
        elif age_days < 365:
            score += 6
            flags.append(f"Domain is {age_days} days old (< 1 year) (+6)")
        else:
            flags.append(f"Domain established {age_days} days ago — mature ✓")
    else:
        score += 8
        flags.append("Domain creation date unavailable (+8)")

    # ── Rule 2: Expiry within 1 year from now ────────────────────────────────
    if expiry_date and isinstance(expiry_date, datetime.datetime):
        days_to_expiry = (expiry_date - datetime.datetime.utcnow()).days
        details["expiry_date"]         = expiry_date.isoformat()
        details["days_to_expiry"]      = days_to_expiry
        if days_to_expiry < 0:
            score += 5
            flags.append(f"Domain registration EXPIRED {abs(days_to_expiry)} days ago (+5)")
        elif days_to_expiry < 30:
            score += 3
            flags.append(f"Domain expires in {days_to_expiry} days (+3)")
        else:
            flags.append(f"Domain expires in {days_to_expiry} days ✓")

    # ── Rule 3: WHOIS privacy / redacted ─────────────────────────────────────
    redacted_keywords = ["redacted", "privacy", "protected", "masked", "withheld"]
    registrant_lower  = str(registrant_name).lower()
    if any(k in registrant_lower for k in redacted_keywords) or registrant_name == "Unknown / Redacted":
        score += 2
        flags.append("Registrant details hidden / privacy-protected (+2)")
    else:
        details["registrant"] = registrant_name

    # ── Rule 4: DNSSEC ────────────────────────────────────────────────────────
    if str(dnssec).lower() in ("unsigned", "no", "none", "false", "unknown"):
        score += 1
        flags.append("DNSSEC not enabled on domain (+1)")
    else:
        flags.append("DNSSEC enabled ✓")

    return {"score": min(score, 20), "flags": flags, "details": details}
