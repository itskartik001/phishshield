# ⚡ PhishShield — Real-Time Phishing Detection System

A production-ready, multi-layer phishing detection web application.
Built with **Flask · scikit-learn · VirusTotal API · WHOIS · SSL inspection**.

---

## 🧩 Architecture

```
Browser (HTML/CSS/JS)
        │
        ▼  POST /api/scan
Flask REST API (app.py)
        │
        ├─── URL Heuristic Analyser  (utils/url_analysis.py)   → 0–25 pts
        ├─── SSL Certificate Checker (utils/ssl_checker.py)    → 0–20 pts
        ├─── WHOIS Domain Lookup     (utils/whois_lookup.py)   → 0–20 pts
        ├─── VirusTotal API Scanner  (utils/api_scanner.py)    → 0–25 pts
        ├─── ML Random Forest        (utils/ml_model.py)       → 0–10 pts
        └─── Scoring Engine          (utils/scorer.py)
                    │
                    ▼
         0–30  → ✅ SAFE
        31–60  → ⚠️  SUSPICIOUS
        61–100 → ❌ PHISHING
```

---

## 📁 Project Structure

```
phishshield/
├── app.py                  ← Flask app, REST endpoint, parallel execution
├── config.py               ← API keys, thresholds, timeouts
├── requirements.txt
├── utils/
│   ├── url_analysis.py     ← Heuristic URL feature extraction
│   ├── ssl_checker.py      ← TLS/SSL certificate validation
│   ├── whois_lookup.py     ← WHOIS domain age & registration
│   ├── api_scanner.py      ← VirusTotal v3 + Google Safe Browsing
│   ├── ml_model.py         ← Random Forest classifier (auto-trains)
│   └── scorer.py           ← Weighted score aggregation
├── templates/
│   └── index.html          ← Single-page frontend
├── static/
│   ├── style.css           ← Dark cyberpunk UI
│   └── script.js           ← Fetch API, result rendering
└── models/
    └── phishing_model.pkl  ← Auto-generated on first run
```

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt** includes:
```
flask>=3.0.0
flask-cors>=4.0.0
requests>=2.31.0
python-whois>=0.9.3
scikit-learn>=1.4.0
```

### 2. Configure API keys (optional but recommended)

Edit `config.py` or set environment variables:

```bash
# VirusTotal (free key — https://www.virustotal.com/gui/join-us)
export VT_API_KEY="your_virustotal_api_key_here"

# Google Safe Browsing (optional fallback)
export GOOGLE_API_KEY="your_google_api_key_here"
```

> ⚠️ Without API keys the system still works via URL heuristics + SSL + WHOIS + ML.
> With VirusTotal it becomes dramatically more accurate.

### 3. Run

```bash
python app.py
```

Open **http://localhost:5000** in your browser.

---

## 🔌 API Reference

### `POST /api/scan`

**Request:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "url": "https://example.com",
  "scan_time_s": 3.2,
  "final_score": 15,
  "verdict": "SAFE",
  "verdict_emoji": "✅",
  "verdict_class": "safe",
  "confidence": "Medium",
  "score_breakdown": {
    "url_analysis": 2,
    "ssl_check": 0,
    "whois": 0,
    "threat_api": 0,
    "ml_model": 1
  },
  "url_analysis": { "score": 2, "flags": [...], "details": {...} },
  "ssl_status":   { "score": 0, "flags": [...], "details": {...} },
  "whois":        { "score": 0, "flags": [...], "details": {...} },
  "api_result":   { "score": 0, "flags": [...], "details": {...}, "source": "virustotal" },
  "ml_result":    { "score": 1, "flags": [...], "details": {...} }
}
```

### `GET /api/health`
```json
{ "status": "ok", "service": "PhishShield" }
```

---

## 🔍 Detection Modules

| Module | Max Score | What it checks |
|--------|-----------|----------------|
| URL Analysis | 25 | Length, IP-as-host, `@`, subdomains, TLD, brand impersonation, homoglyphs, entropy |
| SSL Certificate | 20 | HTTPS presence, cert validity, expiry, CN match, self-signed |
| WHOIS Lookup | 20 | Domain age, expiry, registrar, DNSSEC |
| VirusTotal API | 25 | 90+ AV engines, community reputation |
| ML Classifier | 10 | Random Forest on 16 URL features |

---

## 🧪 Test URLs

| URL | Expected Verdict |
|-----|-----------------|
| `https://google.com` | ✅ SAFE |
| `https://github.com` | ✅ SAFE |
| `http://paypal-secure-update.xyz/confirm` | ❌ PHISHING |
| `http://192.168.1.1/login` | ⚠️ SUSPICIOUS / ❌ PHISHING |
| `http://apple-id.ml/billing` | ❌ PHISHING |
| `http://free-prize.win/claim?token=abc` | ❌ PHISHING |

---

## 🛡️ Security Notes

- All inputs sanitised — command injection characters blocked
- API keys never exposed to frontend
- Rate limited: 30 requests / 60 seconds per IP
- All modules run in parallel with 20-second timeout safety net
- Graceful degradation: any module failure returns score=0 and continues

---

## 🔮 Extending the System

**Add more training data** — edit `_TRAINING_URLS` in `utils/ml_model.py`,
then delete `models/phishing_model.pkl` to retrain.

**Add page-content analysis** — extend `api_scanner.py` with a `requests.get(url)`
and DOM/JS inspection pipeline.

**Database logging** — add SQLAlchemy to `app.py` and log each scan result
for trend analysis (structure described in the research paper).

---

## 📄 Based On

*"Phishing Detection System: The Web Application"*
Prakruthi G, Sheethal P P — IJSCI Vol.2 No.12, December 2025
