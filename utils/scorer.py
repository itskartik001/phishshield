# =============================================================================
# PhishShield — Scoring Engine
# Combines module scores into a final verdict.
# =============================================================================

from typing import Dict, Any
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config


VERDICT_SAFE       = "SAFE"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_PHISHING   = "PHISHING"

# Score weights  (must sum to 100 theoretical max)
# url_analysis :  25 pts
# ssl_checker  :  20 pts
# whois_lookup :  20 pts
# api_scanner  :  25 pts
# ml_model     :  10 pts  (bonus)
# ─────────────────────────────
# total max    : 100 pts


def compute_verdict(
    url_score:   int,
    ssl_score:   int,
    whois_score: int,
    api_score:   int,
    ml_score:    int = 0,
) -> Dict[str, Any]:
    """
    Aggregate module scores and return a verdict dict.

    Args:
        url_score   : 0–25
        ssl_score   : 0–20
        whois_score : 0–20
        api_score   : 0–25
        ml_score    : 0–10  (optional ML bonus)

    Returns:
        {
            "final_score"      : int (0–100),
            "verdict"          : str,
            "verdict_emoji"    : str,
            "verdict_class"    : str   (CSS class hint),
            "score_breakdown"  : dict,
            "confidence"       : str,
        }
    """
    # Clamp individual scores to their maxima
    url_score   = max(0, min(url_score,   25))
    ssl_score   = max(0, min(ssl_score,   20))
    whois_score = max(0, min(whois_score, 20))
    api_score   = max(0, min(api_score,   25))
    ml_score    = max(0, min(ml_score,    10))

    final_score = url_score + ssl_score + whois_score + api_score + ml_score
    final_score = min(final_score, 100)  # hard cap

    # ── Determine verdict ─────────────────────────────────────────────────────
    if final_score <= config.SAFE_MAX:
        verdict       = VERDICT_SAFE
        verdict_emoji = "✅"
        verdict_class = "safe"
        confidence    = _confidence(final_score, 0, config.SAFE_MAX)
    elif final_score <= config.SUSPICIOUS_MAX:
        verdict       = VERDICT_SUSPICIOUS
        verdict_emoji = "⚠️"
        verdict_class = "suspicious"
        confidence    = _confidence(final_score, config.SAFE_MAX + 1, config.SUSPICIOUS_MAX)
    else:
        verdict       = VERDICT_PHISHING
        verdict_emoji = "❌"
        verdict_class = "phishing"
        confidence    = _confidence(final_score, config.SUSPICIOUS_MAX + 1, 100)

    return {
        "final_score":  final_score,
        "verdict":      verdict,
        "verdict_emoji": verdict_emoji,
        "verdict_class": verdict_class,
        "confidence":   confidence,
        "score_breakdown": {
            "url_analysis": url_score,
            "ssl_check":    ssl_score,
            "whois":        whois_score,
            "threat_api":   api_score,
            "ml_model":     ml_score,
        },
    }


def _confidence(score: int, low: int, high: int) -> str:
    """Map a score within a band to a confidence label."""
    band = high - low if high > low else 1
    pct  = (score - low) / band
    if pct >= 0.7:
        return "High"
    elif pct >= 0.4:
        return "Medium"
    else:
        return "Low"
