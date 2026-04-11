# =============================================================================
# PhishShield — ML Model Module  (optional bonus layer)
# Trains a lightweight Random Forest on URL features the first time it runs,
# then persists the model to models/phishing_model.pkl.
# Returns a bonus risk score (0–10).
# =============================================================================

import os
import re
import math
import pickle
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Resolve model path relative to this file
_BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH  = os.path.join(_BASE_DIR, "models", "phishing_model.pkl")

# ── Feature extraction (must mirror training) ─────────────────────────────────

SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "club",
    "work", "date", "download", "racing", "win", "stream",
    "bid", "loan", "review", "trade",
}


def _extract_features(url: str) -> Optional[list]:
    """Return a flat feature vector for a URL, or None on error."""
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed  = urlparse(url)
        host    = (parsed.hostname or "").lower()
        path    = parsed.path
        tld     = host.split(".")[-1] if "." in host else ""

        ip_pat  = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        entropy = _shannon(host.replace(".", ""))

        return [
            len(url),                                        # 0
            int(url.startswith("https")),                   # 1
            url.count("-"),                                  # 2
            url.count("."),                                  # 3
            url.count("/"),                                  # 4
            url.count("@"),                                  # 5
            url.count("%"),                                  # 6
            url.count("?"),                                  # 7
            url.count("="),                                  # 8
            int(bool(ip_pat.match(host))),                  # 9
            max(0, len(host.split(".")) - 2),               # 10 subdomain depth
            int(tld in SUSPICIOUS_TLDS),                    # 11
            len(path),                                       # 12
            round(entropy, 3),                              # 13
            int("//" in path),                              # 14
            int(len(url) > 75),                             # 15
        ]
    except Exception:
        return None


def _shannon(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in freq.values())


# ── Training data (built-in minimal dataset) ─────────────────────────────────

_TRAINING_URLS = [
    # (url, label)  label: 0 = legit, 1 = phishing
    ("https://www.google.com", 0),
    ("https://www.github.com/login", 0),
    ("https://www.amazon.com/gp/cart", 0),
    ("https://stackoverflow.com/questions", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.microsoft.com/en-us/windows", 0),
    ("https://www.apple.com/iphone", 0),
    ("https://www.youtube.com/watch?v=abc123", 0),
    ("https://www.linkedin.com/in/user-profile", 0),
    ("https://news.ycombinator.com", 0),
    ("http://192.168.1.1/login", 1),
    ("http://paypal-secure-update.xyz/confirm", 1),
    ("http://signin-amazon-account.tk/verify", 1),
    ("http://apple-id.ml/update-billing", 1),
    ("http://bank.customer.update.phish.net/login?usr=1&pw=2", 1),
    ("http://secure-login.bankofamerica.phishing.top/auth", 1),
    ("http://bit.ly/3xPhishMe", 1),
    ("http://malware-download.win/setup.exe?id=abc&ref=123", 1),
    ("http://free-prize.win/claim?user=you&token=xyz", 1),
    ("http://google-login.verify-secure.cf/signin?next=", 1),
    ("https://www.reddit.com/r/programming", 0),
    ("https://www.netflix.com/browse", 0),
    ("https://accounts.google.com/o/oauth2/auth", 0),
    ("http://phishybank.net/update@account//secure", 1),
    ("http://secure-update.xyz/password-reset?email=user@mail.com&token=abc", 1),
]


def _train_and_save() -> bool:
    """Train on built-in data and save model. Returns True on success."""
    try:
        from sklearn.ensemble import RandomForestClassifier

        X, y = [], []
        for url, label in _TRAINING_URLS:
            feats = _extract_features(url)
            if feats:
                X.append(feats)
                y.append(label)

        if len(X) < 5:
            return False

        clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=8)
        clf.fit(X, y)

        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(clf, f)

        logger.info("PhishShield ML model trained and saved to %s", MODEL_PATH)
        return True
    except Exception as exc:
        logger.warning("ML model training failed: %s", exc)
        return False


def _load_model():
    """Load saved model or train a fresh one."""
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass
    # Try training
    if _train_and_save():
        try:
            with open(MODEL_PATH, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass
    return None


# ── Public interface ──────────────────────────────────────────────────────────

_cached_model = None


def ml_predict(url: str) -> Dict[str, Any]:
    """
    Run ML classifier on URL.

    Returns:
        dict with keys:
          - score       (int 0–10)
          - flags       (list[str])
          - details     (dict)
    """
    global _cached_model
    flags: list[str] = []

    if _cached_model is None:
        _cached_model = _load_model()

    if _cached_model is None:
        return {
            "score":   0,
            "flags":   ["ML model unavailable (scikit-learn not installed or training failed)"],
            "details": {"error": "model_unavailable"},
        }

    feats = _extract_features(url)
    if feats is None:
        return {
            "score":   0,
            "flags":   ["ML: could not extract features from URL"],
            "details": {"error": "feature_extraction_failed"},
        }

    try:
        proba      = _cached_model.predict_proba([feats])[0]
        phish_prob = proba[1] if len(proba) > 1 else proba[0]
        score      = int(round(phish_prob * 10))  # scale to 0–10

        label = "phishing" if phish_prob >= 0.5 else "legitimate"
        flags.append(
            f"ML model: {phish_prob*100:.1f}% phishing probability → '{label}' (+{score})"
        )
        return {
            "score":   score,
            "flags":   flags,
            "details": {
                "phishing_probability": round(float(phish_prob), 4),
                "label": label,
                "model": "RandomForest",
            },
        }
    except Exception as exc:
        return {
            "score":   0,
            "flags":   [f"ML prediction error: {exc}"],
            "details": {"error": str(exc)},
        }
