"""
Application Configuration
==========================
Central config for scoring weights, thresholds, API keys, and model path.
Reads from .env file if present.
"""

import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings — loaded from environment / .env file."""

    # ── Threat Intelligence API Keys ─────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = ""
    PHISHTANK_API_KEY: str = ""
    SAFEBROWSING_API_KEY: str = ""

    # ── Scoring Weights (must sum to 1.0) ────────────────────────────────
    WEIGHT_ML: float = 0.6
    WEIGHT_RULES: float = 0.2
    WEIGHT_API: float = 0.2

    # ── Classification Thresholds ────────────────────────────────────────
    THRESHOLD_PHISHING: float = 0.70
    THRESHOLD_SUSPICIOUS: float = 0.40

    # ── ML Model Path ────────────────────────────────────────────────────
    MODEL_PATH: str = os.path.join(
        os.path.dirname(__file__), '..', '..', 'ml_model', 'model.pkl'
    )

    # ── Server Config ────────────────────────────────────────────────────
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()
