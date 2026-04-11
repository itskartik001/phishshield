# =============================================================================
# PhishShield — SSL Certificate Checker
# Verifies TLS/SSL health and returns a risk score (0–20).
# =============================================================================

import ssl
import socket
import datetime
from urllib.parse import urlparse
from typing import Dict, Any
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config


def check_ssl(url: str) -> Dict[str, Any]:
    """
    Verify the SSL certificate of a URL.

    Returns:
        dict with keys:
          - score      (int 0–20)
          - flags      (list[str])
          - details    (dict)
    """
    flags: list[str] = []
    score = 0
    details: Dict[str, Any] = {}

    # ── Extract hostname ───────────────────────────────────────────────────────
    try:
        parsed = urlparse(url if url.startswith(("http://", "https://")) else "https://" + url)
        hostname = parsed.hostname or parsed.netloc.split(":")[0]
        port     = parsed.port or 443
    except Exception as exc:
        return {"score": 20, "flags": [f"Could not parse URL: {exc}"], "details": {}}

    details["hostname"] = hostname

    # ── Rule 1: HTTP (no SSL at all) ──────────────────────────────────────────
    if url.startswith("http://"):
        score += 10
        flags.append("Site uses plain HTTP — no SSL/TLS at all (+10)")
        details["protocol"] = "http"
        # Still try to connect on 443 to see if HTTPS is available
        https_available = _probe_https(hostname, port)
        details["https_also_available"] = https_available
        if not https_available:
            score += 5
            flags.append("No HTTPS listener found on port 443 (+5)")
        return {"score": min(score, 20), "flags": flags, "details": details}

    details["protocol"] = "https"

    # ── Attempt TLS handshake ──────────────────────────────────────────────────
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=config.SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

        details["cipher"]   = cipher[0] if cipher else "unknown"
        details["tls_ver"]  = cipher[1] if cipher else "unknown"

        # ── Rule 2: Check cert expiry ─────────────────────────────────────────
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_left  = (not_after - datetime.datetime.utcnow()).days
            details["cert_expiry"]   = not_after.isoformat()
            details["days_remaining"] = days_left

            if days_left < 0:
                score += 15
                flags.append(f"Certificate EXPIRED {abs(days_left)} days ago (+15)")
            elif days_left < 7:
                score += 8
                flags.append(f"Certificate expires in {days_left} days — critical (+8)")
            elif days_left < 30:
                score += 4
                flags.append(f"Certificate expires soon ({days_left} days) (+4)")
            else:
                flags.append(f"Certificate valid for {days_left} more days ✓")

        # ── Rule 3: Issued date — very new cert ──────────────────────────────
        not_before_str = cert.get("notBefore", "")
        if not_before_str:
            not_before  = datetime.datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            cert_age_days = (datetime.datetime.utcnow() - not_before).days
            details["cert_issued_days_ago"] = cert_age_days
            if cert_age_days < 30:
                score += 5
                flags.append(f"Certificate issued only {cert_age_days} days ago (+5)")

        # ── Rule 4: Subject common name vs hostname ───────────────────────────
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        cn      = subject.get("commonName", "")
        details["cert_cn"]     = cn
        details["cert_issuer"] = issuer.get("organizationName", "unknown")

        # Check SAN / CN match
        san_names: list[str] = []
        for san_type, san_val in cert.get("subjectAltName", []):
            if san_type == "DNS":
                san_names.append(san_val.lower())
        details["san"] = san_names

        matched = _hostname_matches_cert(hostname, cn, san_names)
        details["hostname_matches_cert"] = matched
        if not matched:
            score += 10
            flags.append(f"Certificate CN '{cn}' does NOT match hostname '{hostname}' (+10)")
        else:
            flags.append(f"Hostname matches certificate ✓")

        # ── Rule 5: Self-signed check (issuer == subject) ─────────────────────
        issuer_org = issuer.get("organizationName", "")
        subj_org   = subject.get("organizationName", "")
        if issuer_org and issuer_org == subj_org:
            score += 5
            flags.append(f"Certificate appears self-signed (+5)")

        # ── Rule 6: Weak cipher ───────────────────────────────────────────────
        if cipher and ("RC4" in cipher[0] or "DES" in cipher[0] or "NULL" in cipher[0]):
            score += 3
            flags.append(f"Weak cipher suite in use: {cipher[0]} (+3)")

    except ssl.SSLCertVerificationError as exc:
        score += 15
        flags.append(f"SSL certificate verification failed: {exc.reason} (+15)")
        details["ssl_error"] = str(exc)
    except ssl.SSLError as exc:
        score += 12
        flags.append(f"SSL handshake error: {exc} (+12)")
        details["ssl_error"] = str(exc)
    except socket.timeout:
        score += 5
        flags.append("SSL connection timed out — inconclusive (+5)")
        details["ssl_error"] = "timeout"
    except ConnectionRefusedError:
        score += 8
        flags.append("Connection refused on port 443 (+8)")
        details["ssl_error"] = "connection_refused"
    except Exception as exc:
        score += 5
        flags.append(f"Could not establish SSL connection: {type(exc).__name__} (+5)")
        details["ssl_error"] = str(exc)

    return {"score": min(score, 20), "flags": flags, "details": details}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _probe_https(hostname: str, port: int) -> bool:
    """Quick check if port 443 is reachable."""
    try:
        with socket.create_connection((hostname, 443), timeout=3):
            return True
    except Exception:
        return False


def _hostname_matches_cert(hostname: str, cn: str, san_names: list[str]) -> bool:
    """Check whether hostname is covered by the certificate."""
    hostname = hostname.lower()

    def wildcard_match(pattern: str, host: str) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[2:]
            parts  = host.split(".")
            return ".".join(parts[1:]) == suffix and len(parts) >= 2
        return pattern == host

    all_names = san_names or [cn.lower()]
    return any(wildcard_match(name, hostname) for name in all_names)
