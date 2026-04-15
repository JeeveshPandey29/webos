# Sentinel: AI-Powered Phishing Detection System

A complete end-to-end phishing detection system comprising a Chrome Extension frontend and a highly performant FastAPI backend. It utilizes Logistic Regression for Machine Learning classification, a YARA-like heuristic rule engine, and simulated Threat Intelligence API checks.

## Project Structure
```
phishing-detector/
├── backend/
│   ├── core/
│   │   └── config.py        # Settings, weights, thresholds
│   ├── main.py              # FastAPI entry point
│   ├── models.py            # Pydantic schema schemas
│   ├── feature_extractor.py # URL manipulation and explainability
│   ├── rule_engine.py       # YARA-style heuristic rules
│   ├── threat_intel.py      # Simulated API integrations
│   └── requirements.txt     # Python dependencies
├── extension/
│   ├── manifest.json        # Extension config (Manifest V3)
│   ├── popup.html           # Extension UI
│   ├── popup.css            # Clean, dark-mode styling
│   ├── popup.js             # API request and state management
│   ├── content.js           # DOM manipulation stub
│   └── background.js        # Service worker stub
├── ml_model/
│   ├── train.py             # Script to generate synthetic dataset and train model
│   └── model.pkl            # Pickled model instance
├── .env.example             # Config template 
├── Dockerfile               # Container spec
└── README.md
```

## Setup Instructions

### 1. Prerequisites
- Python 3.9+
- Google Chrome browser

### 2. Backend Setup
1. Navigate to the project directory:
   ```bash
   cd "d:\project 1\phishing-detector"
   ```
2. Setup environment variables:
   ```bash
   cp .env.example .env
   ```
3. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
4. Generate the ML Model:
   ```bash
   python ml_model/train.py
   ```
5. Run the Backend API:
   ```bash
   uvicorn backend.main:app --reload
   ```
   The backend should now be running on `http://127.0.0.1:8000`.

### 3. Extension Setup
1. Open Google Chrome.
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** in the top right corner.
4. Click **Load unpacked** in the top left.
5. Select the `extension` folder located inside `phishing-detector/extension`.
6. Pin the extension for easy access.

---

## Testing

Visit different websites and click the extension. The extension grabs the current active tab's URL and analyzes it. You can also manually test the API with cURL.

**Example 1: Legitimate Domain**
```bash
curl -X POST "http://127.0.0.1:8000/analyze" \
-H "Content-Type: application/json" \
-d "{\"url\": \"https://github.com/microsoft\"}"
```
*Expected Output:* `{"label": "legitimate", "phishing_probability": <low score>, ...}`

**Example 2: Suspicious / Phishing Traits**
```bash
curl -X POST "http://127.0.0.1:8000/analyze" \
-H "Content-Type: application/json" \
-d "{\"url\": \"http://login-verify-bank.com.suspicious-domain.xyz\"}"
```
*Expected Output:* `{"label": "phishing", "phishing_probability": <high score>, ...}`

## Advanced Features Implemented
- **Explainable AI:** Feature mapping to simple human-readable explanations.
- **Normalization:** Rule outputs and Threat Intel scores are clipped (0-1).
- **FastAPI Enhancements:** Pydantic validation, IP verification (rejects localhost via validation regex), and Slowapi Rate-Limiting.
- **Resiliency:** Global result caching and dynamic fallback.
- **Docker-Ready:** Fully containerized backend spec.
