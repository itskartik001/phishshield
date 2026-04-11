# =============================================================================
# PhishShield — Main Flask Application
# Run: python app.py
# =============================================================================

import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from urllib.parse import urlparse

from flask import Flask, request, jsonify, render_template
try:
    from flask_cors import CORS
    _CORS_AVAILABLE = True
except ImportError:
    _CORS_AVAILABLE = False

import config
from utils.url_analysis import analyze_url
from utils.ssl_checker   import check_ssl
from utils.whois_lookup  import whois_lookup
from utils.api_scanner   import scan_url
from utils.scorer        import compute_verdict
from utils.ml_model      import ml_predict

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("phishshield")

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = config.SECRET_KEY
if _CORS_AVAILABLE:
    CORS(app, resources={r"/api/*": {"origins": "*"}})

# Thread pool for parallel module execution
_executor = ThreadPoolExecutor(max_workers=4)

# ── Rate limiting (simple in-memory) ─────────────────────────────────────────
_rate_store: dict[str, list[float]] = {}
RATE_LIMIT        = 30   # requests
RATE_WINDOW       = 60   # seconds


def _is_rate_limited(ip: str) -> bool:
    now     = time.time()
    history = _rate_store.get(ip, [])
    history = [t for t in history if now - t < RATE_WINDOW]
    if len(history) >= RATE_LIMIT:
        return True
    history.append(now)
    _rate_store[ip] = history
    return False


# ── URL validation ────────────────────────────────────────────────────────────

_URL_REGEX = re.compile(
    r"^(https?://)?"                       # optional scheme
    r"(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})"  # domain
    r"(:\d+)?"                             # optional port
    r"(/[^\s]*)?"                          # optional path
    r"$",
    re.IGNORECASE,
)


def _validate_url(url: str) -> tuple[bool, str]:
    if not url:
        return False, "URL cannot be empty."
    if len(url) > 2048:
        return False, "URL too long (max 2048 characters)."
    # Basic injection guard
    forbidden = [";", "&&", "|", "`", "$", "<", ">"]
    if any(c in url for c in forbidden):
        return False, "URL contains forbidden characters."
    if not _URL_REGEX.match(url.strip()):
        return False, "Not a valid URL. Example: https://example.com"
    return True, ""


def _normalise_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    """
    POST /api/scan
    Body:  { "url": "https://example.com" }
    Returns full analysis JSON.
    """
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")

    # ── Rate limit ────────────────────────────────────────────────────────────
    if _is_rate_limited(client_ip):
        return jsonify({"error": "Too many requests. Please wait a moment."}), 429

    # ── Parse body ────────────────────────────────────────────────────────────
    body = request.get_json(silent=True) or {}
    raw_url = body.get("url", "").strip()

    valid, err_msg = _validate_url(raw_url)
    if not valid:
        return jsonify({"error": err_msg}), 400

    url = _normalise_url(raw_url)
    logger.info("Scanning: %s  (from %s)", url, client_ip)

    t_start = time.time()

    # ── Run all modules in parallel ───────────────────────────────────────────
    def safe_run(fn, *args):
        try:
            future = _executor.submit(fn, *args)
            return future.result(timeout=15)
        except FutureTimeout:
            return {"score": 0, "flags": [f"{fn.__name__} timed out"], "details": {}}
        except Exception as exc:
            logger.exception("Module %s raised: %s", fn.__name__, exc)
            return {"score": 0, "flags": [f"{fn.__name__} error: {exc}"], "details": {}}

    futures = {
        "url":   _executor.submit(analyze_url, url),
        "ssl":   _executor.submit(check_ssl,   url),
        "whois": _executor.submit(whois_lookup, url),
        "api":   _executor.submit(scan_url,    url),
        "ml":    _executor.submit(ml_predict,  url),
    }

    results = {}
    for key, future in futures.items():
        try:
            results[key] = future.result(timeout=20)
        except FutureTimeout:
            results[key] = {"score": 0, "flags": [f"{key} module timed out"], "details": {}}
        except Exception as exc:
            logger.exception("Module %s failed: %s", key, exc)
            results[key] = {"score": 0, "flags": [f"{key} error: {str(exc)}"], "details": {}}

    # ── Compute verdict ───────────────────────────────────────────────────────
    verdict_data = compute_verdict(
        url_score   = results["url"]["score"],
        ssl_score   = results["ssl"]["score"],
        whois_score = results["whois"]["score"],
        api_score   = results["api"]["score"],
        ml_score    = results["ml"]["score"],
    )

    elapsed = round(time.time() - t_start, 2)

    response = {
        "url":          url,
        "scan_time_s":  elapsed,
        "url_analysis": {
            "score": results["url"]["score"],
            "flags": results["url"]["flags"],
            "details": results["url"]["details"],
        },
        "ssl_status": {
            "score": results["ssl"]["score"],
            "flags": results["ssl"]["flags"],
            "details": results["ssl"]["details"],
        },
        "whois": {
            "score": results["whois"]["score"],
            "flags": results["whois"]["flags"],
            "details": results["whois"]["details"],
        },
        "api_result": {
            "score":   results["api"]["score"],
            "flags":   results["api"]["flags"],
            "details": results["api"]["details"],
            "source":  results["api"].get("source", "unavailable"),
        },
        "ml_result": {
            "score":   results["ml"]["score"],
            "flags":   results["ml"]["flags"],
            "details": results["ml"]["details"],
        },
        **verdict_data,
    }

    logger.info(
        "Done: %s → %s (score=%d) in %.2fs",
        url, verdict_data["verdict"], verdict_data["final_score"], elapsed,
    )
    return jsonify(response), 200


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "PhishShield"}), 200


# ── Error handlers ─────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(exc):
    logger.exception("Internal error: %s", exc)
    return jsonify({"error": "Internal server error"}), 500


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("Starting PhishShield on %s:%d  debug=%s", config.HOST, config.PORT, config.DEBUG)
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG, threaded=True)
