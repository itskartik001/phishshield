# =============================================================================
# PhishShield — Threat Intelligence API Scanner
# Queries VirusTotal v3 (with Google Safe Browsing fallback).
# Returns risk score (0–25).
# =============================================================================

import base64
import time
import requests
from typing import Dict, Any
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config


# ── VirusTotal helpers ────────────────────────────────────────────────────────

def _vt_url_id(url: str) -> str:
    """VirusTotal v3 expects base64url (no padding) encoded URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _query_virustotal(url: str) -> Dict[str, Any]:
    """Submit URL to VT and retrieve analysis results."""
    api_key = config.VIRUSTOTAL_API_KEY
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"error": "no_api_key", "message": "VirusTotal API key not configured"}

    headers = {"x-apikey": api_key, "Accept": "application/json"}

    # ── Step 1: Submit URL for scanning ──────────────────────────────────────
    try:
        submit_resp = requests.post(
            config.VIRUSTOTAL_URL_SCAN,
            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
            data=f"url={requests.utils.quote(url, safe='')}",
            timeout=config.API_TIMEOUT,
        )
        submit_resp.raise_for_status()
    except requests.exceptions.Timeout:
        return {"error": "timeout", "message": "VirusTotal submission timed out"}
    except requests.exceptions.HTTPError as exc:
        if exc.response.status_code == 429:
            return {"error": "rate_limit", "message": "VirusTotal rate limit reached"}
        return {"error": "http_error", "message": str(exc)}
    except requests.exceptions.RequestException as exc:
        return {"error": "network", "message": str(exc)}

    # Give VT a moment to process
    time.sleep(2)

    # ── Step 2: Retrieve report ───────────────────────────────────────────────
    url_id = _vt_url_id(url)
    try:
        report_resp = requests.get(
            config.VIRUSTOTAL_URL_REPORT.format(id=url_id),
            headers=headers,
            timeout=config.API_TIMEOUT,
        )
        report_resp.raise_for_status()
        data = report_resp.json()
    except requests.exceptions.Timeout:
        return {"error": "timeout", "message": "VirusTotal report fetch timed out"}
    except Exception as exc:
        return {"error": "report_fetch", "message": str(exc)}

    # ── Parse stats ───────────────────────────────────────────────────────────
    attrs   = data.get("data", {}).get("attributes", {})
    stats   = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected

    # Collect names of engines that flagged it
    flagging_engines = [
        engine for engine, res in results.items()
        if res.get("category") in ("malicious", "phishing", "suspicious")
    ]

    return {
        "malicious":        malicious,
        "suspicious":       suspicious,
        "harmless":         harmless,
        "undetected":       undetected,
        "total_engines":    total,
        "flagging_engines": flagging_engines[:10],  # cap list length
        "reputation":       attrs.get("reputation", 0),
        "categories":       attrs.get("categories", {}),
        "last_scan":        attrs.get("last_analysis_date", None),
    }


# ── Google Safe Browsing fallback ─────────────────────────────────────────────

def _query_google_safe_browsing(url: str) -> Dict[str, Any]:
    """Query Google Safe Browsing API v4."""
    api_key = config.GOOGLE_API_KEY
    if not api_key or api_key == "YOUR_GOOGLE_API_KEY_HERE":
        return {"error": "no_api_key"}

    endpoint = config.GOOGLE_SAFE_BROWSING_URL.format(key=api_key)
    payload  = {
        "client":    {"clientId": "phishshield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=config.API_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        return {"threat_count": len(matches), "matches": matches}
    except Exception as exc:
        return {"error": str(exc)}


# ── Public interface ──────────────────────────────────────────────────────────

def scan_url(url: str) -> Dict[str, Any]:
    """
    Scan URL using VirusTotal (with GSB fallback).

    Returns:
        dict with keys:
          - score      (int 0–25)
          - flags      (list[str])
          - details    (dict)
          - source     ("virustotal" | "google_safe_browsing" | "unavailable")
    """
    flags: list[str] = []
    score = 0

    # ── Try VirusTotal ────────────────────────────────────────────────────────
    vt_result = _query_virustotal(url)

    if "error" not in vt_result:
        malicious  = vt_result["malicious"]
        suspicious = vt_result["suspicious"]
        total      = vt_result["total_engines"]

        vt_result["source"] = "virustotal"

        if malicious > 5:
            score += 25
            flags.append(f"{malicious}/{total} VT engines flagged as MALICIOUS (+25)")
        elif malicious > 0:
            score += 15
            flags.append(f"{malicious}/{total} VT engines flagged as malicious (+15)")
        elif suspicious > 3:
            score += 10
            flags.append(f"{suspicious}/{total} VT engines flagged as suspicious (+10)")
        elif suspicious > 0:
            score += 5
            flags.append(f"{suspicious}/{total} VT engines flagged as suspicious (+5)")
        else:
            flags.append(f"0/{total} VT engines flagged this URL ✓")

        if vt_result.get("reputation", 0) < -10:
            score += 5
            flags.append(f"Poor VirusTotal community reputation ({vt_result['reputation']}) (+5)")

        return {
            "score":   min(score, 25),
            "flags":   flags,
            "details": vt_result,
            "source":  "virustotal",
        }

    # ── VirusTotal failed — try Google Safe Browsing ──────────────────────────
    gsb_result = _query_google_safe_browsing(url)

    if "error" not in gsb_result:
        threat_count = gsb_result.get("threat_count", 0)
        if threat_count > 0:
            score += 25
            flags.append(f"Google Safe Browsing flagged {threat_count} threat(s) (+25)")
        else:
            flags.append("Google Safe Browsing: no threats found ✓")
        return {
            "score":   min(score, 25),
            "flags":   flags,
            "details": gsb_result,
            "source":  "google_safe_browsing",
        }

    # ── Both APIs unavailable ─────────────────────────────────────────────────
    reason = vt_result.get("message", vt_result.get("error", "unknown"))
    flags.append(f"Threat API unavailable ({reason}) — skipping API check")
    return {
        "score":   0,
        "flags":   flags,
        "details": {"error": reason},
        "source":  "unavailable",
    }
