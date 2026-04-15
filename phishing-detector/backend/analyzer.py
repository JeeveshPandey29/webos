"""
Core Analyzer / Orchestration Module
======================================
Combines ML Model, Rule Engine, Threat Intelligence,
SSL Checking, WHOIS Domain Analysis, and HTML Content Analysis
into a single composite phishing probability score.
"""

import pandas as pd
import logging
from .feature_extractor import FeatureExtractor, FEATURE_COLUMNS
from .rule_engine import RuleEngine
from .threat_intel import ThreatIntelAPI
from .ssl_checker import SSLChecker
from .domain_analyzer import DomainAnalyzer
from .html_analyzer import HTMLAnalyzer

logger = logging.getLogger(__name__)


class Analyzer:
    """Central analysis pipeline."""

    def __init__(self, settings):
        self.settings = settings
        self.feature_extractor = FeatureExtractor()
        self.rule_engine = RuleEngine()
        self.threat_intel = ThreatIntelAPI(settings)
        self.ssl_checker = SSLChecker()
        self.domain_analyzer = DomainAnalyzer()
        self.html_analyzer = HTMLAnalyzer()

    def analyze(self, url: str, ml_model) -> dict:
        logger.info("=" * 50)
        logger.info(f"ANALYZING: {url}")
        logger.info("=" * 50)

        # -- 1. URL Feature Extraction (for ML model) ---------------------
        features = self.feature_extractor.extract_features(url)
        feature_reasons = self.feature_extractor.explain_features(features)
        logger.info(f"Features: {features}")

        model_input = {col: features[col] for col in FEATURE_COLUMNS}
        df = pd.DataFrame([model_input])

        # -- 2. ML Prediction ---------------------------------------------
        ml_prob = float(ml_model.predict_proba(df)[0][1])
        logger.info(f"ML phishing probability: {ml_prob:.4f}")

        # -- 3. Rule Engine -----------------------------------------------
        rule_score, rule_matches = self.rule_engine.evaluate(features)
        logger.info(f"Rule engine score: {rule_score:.4f}")

        # -- 4. Threat Intelligence ---------------------------------------
        api_score, api_flags = self.threat_intel.check_url(url)
        logger.info(f"Threat intel score: {api_score:.4f}")

        # -- 5. SSL Certificate Check -------------------------------------
        ssl_info = self.ssl_checker.check(url)
        ssl_reasons = []
        if not ssl_info.get("has_ssl"):
            ssl_reasons.append("[SSL] No valid SSL/TLS certificate found.")
        elif not ssl_info.get("is_valid"):
            ssl_reasons.append("[SSL] Certificate is expired or invalid.")
        elif ssl_info.get("expires_in_days") is not None and ssl_info["expires_in_days"] < 30:
            ssl_reasons.append(f"[SSL] Certificate expires very soon ({ssl_info['expires_in_days']} days).")

        # -- 6. WHOIS Domain Analysis -------------------------------------
        domain_info = self.domain_analyzer.analyze(url)
        domain_reasons = []
        age = domain_info.get("domain_age_days")
        if age is not None and age < 90:
            domain_reasons.append(f"[WHOIS] Domain is very young ({age} days old) - high risk.")
        elif age is not None and age < 365:
            domain_reasons.append(f"[WHOIS] Domain is relatively new ({age} days old).")

        # -- 7. HTML Content Analysis -------------------------------------
        html_info = self.html_analyzer.analyze(url)
        html_reasons = []
        if html_info.get("hidden_iframes_count", 0) > 0:
            html_reasons.append(f"[HTML] {html_info['hidden_iframes_count']} hidden iframe(s) detected.")
        if html_info.get("password_fields", 0) > 0:
            html_reasons.append(f"[HTML] Page contains {html_info['password_fields']} password field(s).")
        if len(html_info.get("external_form_actions", [])) > 0:
            html_reasons.append(f"[HTML] Form submits data to external domain(s).")
        if html_info.get("meta_redirects"):
            html_reasons.append(f"[HTML] Meta refresh redirect detected.")
        if html_info.get("external_link_ratio", 0) > 0.7 and html_info.get("total_links", 0) > 5:
            html_reasons.append(f"[HTML] High ratio of external links ({html_info['external_link_ratio']:.0%}).")

        # -- 8. Composite Score -------------------------------------------
        final_score = (
            self.settings.WEIGHT_ML * ml_prob +
            self.settings.WEIGHT_RULES * rule_score +
            self.settings.WEIGHT_API * api_score
        )

        # Boost score based on enrichment analysis
        enrichment_boost = 0.0
        if ssl_reasons:
            enrichment_boost += 0.05
        if domain_reasons and age is not None and age < 90:
            enrichment_boost += 0.08
        if html_reasons:
            enrichment_boost += 0.03 * len(html_reasons)

        final_score = round(min(max(final_score + enrichment_boost, 0.0), 1.0), 4)

        # -- 9. Label Assignment ------------------------------------------
        if final_score > self.settings.THRESHOLD_PHISHING:
            label = "phishing"
        elif final_score > self.settings.THRESHOLD_SUSPICIOUS:
            label = "suspicious"
        else:
            label = "legitimate"

        # -- 10. Combine all reasons (deduplicated, ordered) ---------------
        all_reasons = []
        seen = set()
        for r in feature_reasons + rule_matches + api_flags + ssl_reasons + domain_reasons + html_reasons:
            if r not in seen:
                all_reasons.append(r)
                seen.add(r)
        if not all_reasons:
            all_reasons = ["No suspicious indicators found."]

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
            "feature_values": features,
            "ssl_info": ssl_info,
            "domain_info": domain_info,
            "html_info": html_info,
        }

        logger.info(f"VERDICT: {label} ({final_score:.2%})")
        logger.info("=" * 50)
        return result
