# Sentinel AI - Phishing Detection System

> AI-Powered Phishing Detection System with Chrome Browser Extension

A production-grade phishing URL detection system that combines **Machine Learning**, **heuristic rule analysis**, and **threat intelligence** into a single composable pipeline. Ships with a sleek Chrome Extension for real-time protection.

---

## Architecture

```
Chrome Extension (popup/background/content)
        |
        | POST /analyze { url }
        v
  FastAPI Backend (main.py)
        |
        +---> Feature Extractor (10 URL features)
        |           |
        |           v
        +---> ML Model (GradientBoosting / LogisticRegression)
        |           |
        +---> Rule Engine (8 YARA-style heuristic rules)
        |           |
        +---> Threat Intel APIs (VirusTotal/PhishTank/SafeBrowsing sim)
        |
        v
  Composite Score = 0.6*ML + 0.2*Rules + 0.2*ThreatIntel
        |
        v
  JSON Response --> Extension UI (color-coded verdict)
```

---

## Project Structure

```
phishing-detector/
|
|-- backend/
|   |-- __init__.py
|   |-- main.py              # FastAPI entry point (endpoints, caching, rate limiting)
|   |-- models.py            # Pydantic request/response schemas with validation
|   |-- analyzer.py          # Core orchestration (ML + Rules + ThreatIntel)
|   |-- feature_extractor.py # 10-feature URL analysis + explainability
|   |-- rule_engine.py       # 8 YARA-style heuristic detection rules
|   |-- threat_intel.py      # Simulated VirusTotal/PhishTank/SafeBrowsing
|   |-- requirements.txt     # Python dependencies
|   |-- core/
|       |-- __init__.py
|       |-- config.py         # Centralized settings (weights, thresholds, API keys)
|
|-- ml_model/
|   |-- train.py             # Training pipeline (synthetic data + dual model)
|   |-- model.pkl            # Saved best model (auto-selected)
|   |-- model_metadata.json  # Accuracy, F1, feature list
|   |-- training_data.csv    # Generated dataset (5000 samples)
|
|-- extension/
|   |-- manifest.json        # Chrome Manifest V3
|   |-- popup.html           # Extension popup UI
|   |-- popup.css            # Dark cyber-security theme
|   |-- popup.js             # API communication + history + rendering
|   |-- background.js        # Auto-scan on page load + badge updates
|   |-- content.js           # Page metadata extraction
|   |-- icon.png             # Extension icon
|
|-- .env.example             # Environment variable template
|-- Dockerfile               # Multi-stage Docker build
|-- README.md                # This file
```

---

## Setup Instructions

### Prerequisites
- **Python 3.9+** (tested with 3.13)
- **Google Chrome** browser
- **pip** package manager

### Step 1: Clone / Navigate to the Project
```bash
cd "d:\project 1\phishing-detector"
```

### Step 2: Install Python Dependencies
```bash
pip install -r backend/requirements.txt
```

### Step 3: Train the ML Model
This generates a synthetic dataset and trains both Logistic Regression and Gradient Boosting classifiers. The best model is auto-selected.
```bash
python ml_model/train.py
```
You should see output like:
```
SELECTED MODEL: GradientBoostingClassifier (F1=1.0000)
Model saved to ...\ml_model\model.pkl
```

### Step 4: Start the Backend API
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
The server will start at `http://127.0.0.1:8000`

Verify it works:
```bash
# PowerShell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health"

# cURL (Git Bash / Linux / Mac)
curl http://127.0.0.1:8000/health
```
Expected: `{"status": "healthy", "model_loaded": true, ...}`

### Step 5: Load the Chrome Extension
1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `extension/` folder inside `phishing-detector`
5. Pin the extension for easy access

### Step 6: Test It!
- Navigate to any website
- Click the Sentinel AI extension icon
- The popup will analyze the current page and show results

---

## API Reference

### `GET /health`
Health check endpoint.
```json
{
  "status": "healthy",
  "model_loaded": true,
  "cached_results": 3,
  "total_requests": 12
}
```

### `GET /stats`
Returns usage statistics and recently cached URLs.

### `POST /analyze`
Analyze a URL for phishing indicators.

**Request:**
```json
{
  "url": "http://login-verify-bank.evil.xyz/account"
}
```

**Response:**
```json
{
  "phishing_probability": 0.9022,
  "label": "phishing",
  "reasons": [
    "Unusually long URL (78 chars)",
    "Connection is NOT secured with HTTPS",
    "URL contains 7 suspicious keyword(s)",
    "[SUSP_KEYWORDS] URL contains phishing-associated keywords",
    "[NO_HTTPS] No TLS/SSL - connection is unencrypted",
    "VirusTotal: Domain contains blacklisted term 'evil'",
    "Threat Intel: High-risk TLD detected (.xyz)"
  ],
  "confidence_breakdown": {
    "ML Engine": 1.0,
    "Heuristic Rules": 0.5111,
    "Threat Intelligence": 1.0
  },
  "feature_values": {
    "url_length": 78,
    "num_dots": 4,
    "has_https": 0,
    "has_ip": 0,
    "keyword_count": 7,
    "num_hyphens": 3,
    "num_slashes": 3,
    "has_at_symbol": 0,
    "path_length": 23,
    "subdomain_depth": 3
  }
}
```

---

## Test Cases

### Safe URLs (Expected: legitimate, score < 40%)

```powershell
# Test 1: GitHub
Invoke-RestMethod -Uri "http://127.0.0.1:8000/analyze" -Method Post -ContentType "application/json" -Body '{"url": "https://github.com/microsoft"}'
# Result: label=legitimate, score=4%

# Test 2: Google
Invoke-RestMethod -Uri "http://127.0.0.1:8000/analyze" -Method Post -ContentType "application/json" -Body '{"url": "https://www.google.com/search?q=hello"}'
# Result: label=legitimate, score=0%

# Test 3: StackOverflow
Invoke-RestMethod -Uri "http://127.0.0.1:8000/analyze" -Method Post -ContentType "application/json" -Body '{"url": "https://stackoverflow.com/questions/12345"}'
# Result: label=legitimate, score=4%
```

### Phishing URLs (Expected: phishing, score > 70%)

```powershell
# Test 4: Multi-indicator phishing URL
Invoke-RestMethod -Uri "http://127.0.0.1:8000/analyze" -Method Post -ContentType "application/json" -Body '{"url": "http://login-verify-bank.com.suspicious-domain.evil.xyz/account/update/confirm"}'
# Result: label=phishing, score=90%

# Test 5: Risky TLD with @ symbol
Invoke-RestMethod -Uri "http://127.0.0.1:8000/analyze" -Method Post -ContentType "application/json" -Body '{"url": "http://secure-update-verify.account-login.tk/signin/confirm?user=admin@bank.com"}'
# Result: label=phishing, score=78%

# Test 6: IP address (rejected by validation)
Invoke-RestMethod -Uri "http://127.0.0.1:8000/analyze" -Method Post -ContentType "application/json" -Body '{"url": "http://192.168.1.100/paypal-login/verify.html"}'
# Result: 422 Validation Error - private IPs not allowed
```

---

## Features Implemented

### Backend
- [x] FastAPI with async support
- [x] Input validation (URL format, protocol, private IP rejection)
- [x] Rate limiting (30 requests/minute via slowapi)
- [x] In-memory result caching
- [x] Structured logging (UTF-8 safe for Windows)
- [x] Model loaded once at startup (not per-request)
- [x] CORS enabled for extension
- [x] Health check and stats endpoints
- [x] Centralized config (config.py with .env support)

### Machine Learning
- [x] 10-feature extraction pipeline
- [x] Dual model training (Logistic Regression + Gradient Boosting)
- [x] Auto-selection of best model by F1 score
- [x] StandardScaler pipeline for Logistic Regression
- [x] Model metadata export (JSON)
- [x] Reproducible synthetic dataset (5000 samples, CSV export)

### Rule Engine
- [x] 8 YARA-style heuristic rules
- [x] Normalized scoring (0-1)
- [x] Rules: keywords, HTTPS, subdomains, IP, @-symbol, long URL, hyphens, deep path

### Threat Intelligence
- [x] Simulated VirusTotal, PhishTank, Google Safe Browsing
- [x] Blacklist term detection
- [x] Keyword combination analysis
- [x] Domain age heuristic (deterministic hash)
- [x] Risky TLD detection (.xyz, .tk, .ml, .ga, etc.)

### Scoring
- [x] Composite: 60% ML + 20% Rules + 20% Threat Intel
- [x] Three-tier classification: legitimate / suspicious / phishing
- [x] Configurable weights and thresholds in config.py

### Explainability
- [x] Feature-to-reason mapping with descriptive text
- [x] Per-engine confidence breakdown
- [x] Full feature values in response for debugging

### Chrome Extension
- [x] Manifest V3
- [x] Premium dark cyber-security UI
- [x] Animated score ring with color coding (green/yellow/red)
- [x] Visual confidence progress bars per engine
- [x] Threat indicator list
- [x] Scan history panel (last 8 URLs, persisted in localStorage)
- [x] Auto-scan on page load (background.js)
- [x] Dynamic badge color/text on extension icon
- [x] Phishing alert banner injected into high-risk pages
- [x] Loading spinner + error state + retry button
- [x] Request timeout handling (10s)
- [x] Re-scan button

### Production
- [x] Multi-stage Dockerfile with health check
- [x] .env support for API keys
- [x] Pinned dependency versions
- [x] UTF-8 safe logging for Windows compatibility

---

## Configuration

Edit `backend/core/config.py` or create a `.env` file:

```env
# API Keys (leave empty to use simulation mode)
VIRUSTOTAL_API_KEY=
PHISHTANK_API_KEY=
SAFEBROWSING_API_KEY=

# Scoring Weights (must sum to 1.0)
WEIGHT_ML=0.6
WEIGHT_RULES=0.2
WEIGHT_API=0.2

# Classification Thresholds
THRESHOLD_PHISHING=0.70
THRESHOLD_SUSPICIOUS=0.40
```

---

## Docker (Optional)

```bash
# Build
docker build -t sentinel-ai .

# Run
docker run -p 8000:8000 sentinel-ai
```

---

## Tech Stack

| Component         | Technology                          |
|-------------------|-------------------------------------|
| Backend Framework | FastAPI + Uvicorn                   |
| ML Library        | scikit-learn (GradientBoosting)     |
| Data Processing   | pandas + numpy                      |
| Rate Limiting     | slowapi                             |
| Configuration     | pydantic-settings + python-dotenv   |
| Extension         | Chrome Manifest V3 + Vanilla JS/CSS |
| Containerization  | Docker (multi-stage)                |

---

## License

This project is for educational and demonstration purposes.
