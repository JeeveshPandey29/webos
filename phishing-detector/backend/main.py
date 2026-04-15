"""
FastAPI Backend — AI-Powered Phishing Detection API
=====================================================
Endpoints:
  POST /analyze   → Analyze a URL for phishing indicators
  GET  /health    → Health check (model status)
  GET  /stats     → Cache and request statistics

Production features:
  ✓ Rate limiting (slowapi)
  ✓ CORS for Chrome extension
  ✓ Request caching (in-memory)
  ✓ Model loaded once at startup
  ✓ Structured logging
  ✓ Input validation
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import logging
import joblib
import os
import sys
import time

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models import AnalyzeRequest, AnalyzeResponse
from backend.core.config import settings
from backend.analyzer import Analyzer

# ── Logging ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("backend_app.log", encoding="utf-8"),
    ]
)
logger = logging.getLogger("sentinel")

# ── Global State ─────────────────────────────────────────────────────────
ml_model = None
analyzer = None
results_cache: dict = {}
request_count: int = 0

# ── Lifespan (replaces deprecated on_event) ──────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global ml_model, analyzer
    logger.info("🚀 Starting Sentinel Phishing Detection API...")
    
    model_path = os.path.normpath(settings.MODEL_PATH)
    logger.info(f"📦 Loading ML model from: {model_path}")
    try:
        ml_model = joblib.load(model_path)
        logger.info("✅ ML model loaded successfully.")
    except FileNotFoundError:
        logger.error(f"❌ Model file not found at {model_path}. Run ml_model/train.py first!")
    except Exception as e:
        logger.error(f"❌ Failed to load model: {e}")

    analyzer = Analyzer(settings)
    logger.info("✅ Analyzer pipeline initialized.")
    
    yield  # App runs here
    
    logger.info("🛑 Shutting down Sentinel API.")


# ── FastAPI App ──────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="Sentinel — AI Phishing Detection API",
    version="2.0.0",
    description="Detects phishing URLs using ML + heuristic rules + threat intelligence.",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — allow the Chrome extension to call us
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Endpoints ────────────────────────────────────────────────────────────

@app.get("/health")
def health_check():
    """Simple health check."""
    return {
        "status": "healthy",
        "model_loaded": ml_model is not None,
        "cached_results": len(results_cache),
        "total_requests": request_count,
    }


@app.get("/stats")
def get_stats():
    """Return usage statistics."""
    return {
        "total_analyzed": request_count,
        "cached_urls": len(results_cache),
        "cache_keys": list(results_cache.keys())[-10:],  # last 10
    }


@app.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("30/minute")
async def analyze_url(request: Request, payload: AnalyzeRequest):
    """Analyze a URL and return phishing probability + reasons."""
    global request_count
    request_count += 1

    url = payload.url
    logger.info(f"📥 Request #{request_count}: {url}")

    # Cache check
    if url in results_cache:
        logger.info("⚡ Returning cached result.")
        return results_cache[url]

    # Model check
    if ml_model is None:
        logger.error("Model not loaded — cannot analyze.")
        raise HTTPException(
            status_code=503,
            detail="ML model not loaded. Please run ml_model/train.py and restart the server."
        )

    # Run analysis pipeline
    start = time.perf_counter()
    try:
        result = analyzer.analyze(url, ml_model)
    except Exception as e:
        logger.exception(f"Analysis failed for {url}")
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")
    elapsed = time.perf_counter() - start
    logger.info(f"⏱️ Analysis completed in {elapsed:.3f}s")

    # Cache result
    results_cache[url] = result
    return result
