"""
Core Analyzer / Orchestration Module
======================================
Combines ML Model, Rule Engine, and Threat Intelligence
into a single composite phishing probability score.

Final Score = (W_ML × ML_prob) + (W_RULES × rule_score) + (W_API × api_score)
All component scores are normalized to [0, 1].
"""

import pandas as pd
import logging
from .feature_extractor import FeatureExtractor, FEATURE_COLUMNS
from .rule_engine import RuleEngine
from .threat_intel import ThreatIntelAPI

logger = logging.getLogger(__name__)


class Analyzer:
    """Central analysis pipeline — the heart of the backend."""

    def __init__(self, settings):
        self.settings = settings
        self.feature_extractor = FeatureExtractor()
        self.rule_engine = RuleEngine()
        self.threat_intel = ThreatIntelAPI(settings)

    def analyze(self, url: str, ml_model) -> dict:
        logger.info(f"{'='*50}")
        logger.info(f"ANALYZING: {url}")
        logger.info(f"{'='*50}")

        # ── 1. Feature Extraction ────────────────────────────────────────
        features = self.feature_extractor.extract_features(url)
        feature_reasons = self.feature_extractor.explain_features(features)
        logger.info(f"Features: {features}")

        # Build DataFrame with correct column order for the model
        model_input = {col: features[col] for col in FEATURE_COLUMNS}
        df = pd.DataFrame([model_input])

        # ── 2. ML Prediction ─────────────────────────────────────────────
        ml_prob = float(ml_model.predict_proba(df)[0][1])
        logger.info(f"ML phishing probability: {ml_prob:.4f}")

        # ── 3. Rule Engine ───────────────────────────────────────────────
        rule_score, rule_matches = self.rule_engine.evaluate(features)
        logger.info(f"Rule engine score: {rule_score:.4f}")

        # ── 4. Threat Intelligence ───────────────────────────────────────
        api_score, api_flags = self.threat_intel.check_url(url)
        logger.info(f"Threat intel score: {api_score:.4f}")

        # ── 5. Composite Score ───────────────────────────────────────────
        final_score = (
            self.settings.WEIGHT_ML * ml_prob +
            self.settings.WEIGHT_RULES * rule_score +
            self.settings.WEIGHT_API * api_score
        )
        final_score = round(min(max(final_score, 0.0), 1.0), 4)

        # ── 6. Label Assignment ──────────────────────────────────────────
        if final_score > self.settings.THRESHOLD_PHISHING:
            label = "phishing"
        elif final_score > self.settings.THRESHOLD_SUSPICIOUS:
            label = "suspicious"
        else:
            label = "legitimate"

        # ── 7. Combine all reasons (deduplicated, ordered) ───────────────
        all_reasons = []
        seen = set()
        for r in feature_reasons + rule_matches + api_flags:
            if r not in seen:
                all_reasons.append(r)
                seen.add(r)
        if not all_reasons:
            all_reasons = ["✅ No suspicious indicators found."]

        # ── 8. Build response ────────────────────────────────────────────
        confidence_breakdown = {
            "ML Engine": round(ml_prob, 4),
            "Heuristic Rules": round(rule_score, 4),
            "Threat Intelligence": round(api_score, 4)
        }

        result = {
            "phishing_probability": round(final_score, 4),
            "label": label,
            "reasons": all_reasons,
            "confidence_breakdown": confidence_breakdown,
            "feature_values": features
        }

        logger.info(f"VERDICT: {label} ({final_score:.2%})")
        logger.info(f"{'='*50}")
        return result
