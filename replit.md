# PhishShield

## Overview
PhishShield is a Flask web application for real-time phishing URL analysis. It serves a single-page frontend from `templates/index.html` and static assets in `static/`, with JSON APIs in `app.py`.

## Runtime
- Python 3.12
- Flask app entrypoint: `app.py`
- Development workflow command: `python app.py`
- Development web port: `5000`
- Development host: `0.0.0.0`

## Dependencies
Project dependencies are tracked in `requirements.txt` and installed through Replit package management. The production server uses Gunicorn.

## Configuration
- `PORT` defaults to `5000` for Replit preview compatibility.
- `HOST` defaults to `0.0.0.0`.
- Optional API keys can be provided through environment variables:
  - `VT_API_KEY`
  - `GOOGLE_API_KEY`
  - `SECRET_KEY`

## Deployment
Deployment is configured for an autoscale Python web service using Gunicorn against `app:app`.
