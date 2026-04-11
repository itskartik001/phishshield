# =============================================================================
# PhishShield — URL Analysis Module
# Extracts heuristic features from a URL and returns a risk score (0–25).
# =============================================================================

import re
import math
from urllib.parse import urlparse
from typing import Dict, Any


# Suspicious TLDs historically abused in phishing campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".club",
    ".work", ".date", ".download", ".racing", ".win", ".stream",
    ".bid", ".loan", ".review", ".trade", ".accountant", ".science",
}

# Common brand names targeted by typosquatters
TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "bankofamerica",
    "chase", "wellsfargo", "citibank", "dropbox", "adobe", "ebay",
    "signin", "login", "secure", "account", "verify", "update",
    "confirm", "wallet", "support", "helpdesk",
]


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Analyse a URL for phishing-indicative heuristics.

    Returns:
        dict with keys:
          - score        (int 0–25)
          - flags        (list[str])  human-readable reasons for each flag
          - details      (dict)       raw extracted features
    """
    flags: list[str] = []
    score = 0

    # ── Parse ──────────────────────────────────────────────────────────────────
    try:
        parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    except Exception:
        return {"score": 25, "flags": ["URL could not be parsed"], "details": {}}

    scheme    = parsed.scheme.lower()
    netloc    = parsed.netloc.lower()
    path      = parsed.path
    full_path = parsed.path + (("?" + parsed.query) if parsed.query else "")
    raw_host  = netloc.split(":")[0]            # strip port

    details: Dict[str, Any] = {
        "scheme":      scheme,
        "host":        raw_host,
        "path_length": len(full_path),
        "url_length":  len(url),
    }

    # ── Rule 1: HTTP (no TLS) ──────────────────────────────────────────────────
    if scheme == "http":
        score += 3
        flags.append("Uses HTTP instead of HTTPS (+3)")

    # ── Rule 2: URL length ─────────────────────────────────────────────────────
    if len(url) > 100:
        score += 5
        flags.append(f"Very long URL ({len(url)} chars) (+5)")
    elif len(url) > 75:
        score += 3
        flags.append(f"Long URL ({len(url)} chars) (+3)")
    details["url_length"] = len(url)

    # ── Rule 3: IP address used as host ───────────────────────────────────────
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$|"          # IPv4
        r"^\[?[0-9a-fA-F:]+\]?$"              # IPv6
    )
    if ip_pattern.match(raw_host):
        score += 7
        flags.append("IP address used as domain (+7)")
        details["is_ip"] = True
    else:
        details["is_ip"] = False

    # ── Rule 4: '@' symbol in URL ─────────────────────────────────────────────
    if "@" in url:
        score += 5
        flags.append("'@' symbol in URL (hides real host) (+5)")

    # ── Rule 5: Double slash in path ─────────────────────────────────────────
    if "//" in path:
        score += 3
        flags.append("Double slash (//) in path (+3)")

    # ── Rule 6: Suspicious subdomain depth ───────────────────────────────────
    parts = raw_host.split(".")
    subdomain_depth = max(0, len(parts) - 2)
    details["subdomain_depth"] = subdomain_depth
    if subdomain_depth >= 4:
        score += 5
        flags.append(f"Excessive subdomain depth ({subdomain_depth}) (+5)")
    elif subdomain_depth >= 2:
        score += 2
        flags.append(f"Multiple subdomains ({subdomain_depth}) (+2)")

    # ── Rule 7: Suspicious TLD ────────────────────────────────────────────────
    tld = "." + parts[-1] if parts else ""
    details["tld"] = tld
    if tld in SUSPICIOUS_TLDS:
        score += 4
        flags.append(f"High-risk TLD '{tld}' (+4)")

    # ── Rule 8: Brand impersonation ───────────────────────────────────────────
    host_and_path = (raw_host + full_path).lower()
    matched_brands = [b for b in TARGET_BRANDS if b in host_and_path]
    details["brand_hits"] = matched_brands
    if matched_brands:
        score += min(5, len(matched_brands) * 2)
        flags.append(f"Brand keyword(s) detected: {', '.join(matched_brands)} (+{min(5,len(matched_brands)*2)})")

    # ── Rule 9: Homoglyph / lookalike characters ──────────────────────────────
    suspicious_patterns = [
        (r"rn(?=[a-z])", "homoglyph 'rn' resembles 'm'"),
        (r"0(?=[a-z])|(?<=[a-z])0", "digit '0' replacing letter 'o'"),
        (r"1(?=[a-z])|(?<=[a-z])1", "digit '1' replacing letter 'l' or 'i'"),
    ]
    for pattern, reason in suspicious_patterns:
        if re.search(pattern, raw_host):
            score += 3
            flags.append(f"Lookalike character: {reason} (+3)")
            break  # one hit is enough

    # ── Rule 10: Excessive hyphens ────────────────────────────────────────────
    hyphen_count = raw_host.count("-")
    details["hyphen_count"] = hyphen_count
    if hyphen_count >= 4:
        score += 3
        flags.append(f"Excessive hyphens in domain ({hyphen_count}) (+3)")
    elif hyphen_count >= 2:
        score += 1
        flags.append(f"Multiple hyphens in domain ({hyphen_count}) (+1)")

    # ── Rule 11: Encoded characters ──────────────────────────────────────────
    encoded_count = url.count("%")
    details["encoded_chars"] = encoded_count
    if encoded_count >= 3:
        score += 3
        flags.append(f"Heavy URL encoding ({encoded_count} '%' chars) (+3)")

    # ── Rule 12: URL entropy (randomness) ─────────────────────────────────────
    entropy = _shannon_entropy(raw_host.replace(".", ""))
    details["host_entropy"] = round(entropy, 2)
    if entropy > 3.8:
        score += 2
        flags.append(f"High domain entropy ({entropy:.2f}) suggesting DGA (+2)")

    # Cap at 25
    score = min(score, 25)

    if not flags:
        flags.append("No suspicious URL patterns detected")

    return {"score": score, "flags": flags, "details": details}


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in freq.values())
