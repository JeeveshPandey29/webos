"""
Feature Extractor Module
========================
Extracts numerical features from a raw URL string.
Features MUST match the column order used in ml_model/train.py.
Also provides an explainability layer that maps features → human-readable reasons.
"""

from urllib.parse import urlparse
import ipaddress
import re
import logging

logger = logging.getLogger(__name__)

# Must match FEATURE_COLUMNS in ml_model/train.py
FEATURE_COLUMNS = [
    'url_length', 'num_dots', 'has_https', 'has_ip',
    'keyword_count', 'num_hyphens', 'num_slashes',
    'has_at_symbol', 'path_length', 'subdomain_depth'
]

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'bank', 'secure', 'update',
    'account', 'auth', 'confirm', 'signin', 'password',
    'credential', 'suspend', 'alert', 'verify', 'wallet',
    'paypal', 'ebay', 'apple', 'netflix', 'amazon'
]


class FeatureExtractor:
    """Extracts a feature dictionary from a URL string."""

    def _is_ip(self, hostname: str) -> int:
        try:
            ipaddress.ip_address(hostname)
            return 1
        except ValueError:
            return 0

    def extract_features(self, url: str) -> dict:
        """Return a dict of all features for the given URL."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""

        url_length = len(url)
        num_dots = hostname.count('.')
        has_https = 1 if parsed.scheme == 'https' else 0
        has_ip = self._is_ip(hostname)

        url_lower = url.lower()
        keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

        num_hyphens = url.count('-')
        num_slashes = path.count('/')
        has_at_symbol = 1 if '@' in url else 0
        path_length = len(path)

        # subdomain depth: e.g. "a.b.example.com" → 2  
        parts = hostname.split('.')
        subdomain_depth = max(len(parts) - 2, 0)  # strip TLD + domain

        features = {
            'url_length': url_length,
            'num_dots': num_dots,
            'has_https': has_https,
            'has_ip': has_ip,
            'keyword_count': keyword_count,
            'num_hyphens': num_hyphens,
            'num_slashes': num_slashes,
            'has_at_symbol': has_at_symbol,
            'path_length': path_length,
            'subdomain_depth': subdomain_depth,
        }

        logger.debug(f"Extracted features: {features}")
        return features

    def explain_features(self, features: dict) -> list:
        """Map raw feature values to human-readable threat indicators."""
        reasons = []

        if features['url_length'] > 75:
            reasons.append(f"⚠ Unusually long URL ({features['url_length']} chars) — often used to hide the real domain.")
        if features['num_dots'] >= 4:
            reasons.append(f"⚠ Excessive dots in hostname ({features['num_dots']}) — suggests nested subdomains.")
        if features['has_https'] == 0:
            reasons.append("🔓 Connection is NOT secured with HTTPS.")
        if features['has_ip'] == 1:
            reasons.append("🌐 URL uses a raw IP address instead of a domain name.")
        if features['keyword_count'] > 0:
            reasons.append(f"🔑 URL contains {features['keyword_count']} suspicious keyword(s) (e.g. login, verify, bank).")
        if features['num_hyphens'] >= 3:
            reasons.append(f"➖ Excessive hyphens ({features['num_hyphens']}) — common in spoofed domains.")
        if features['num_slashes'] >= 5:
            reasons.append(f"📂 Deep URL path ({features['num_slashes']} slashes) — may hide redirect chains.")
        if features['has_at_symbol'] == 1:
            reasons.append("📧 URL contains '@' — can be used to obscure the real destination.")
        if features['path_length'] > 50:
            reasons.append(f"📏 Very long URL path ({features['path_length']} chars).")
        if features['subdomain_depth'] >= 3:
            reasons.append(f"🔗 Deep subdomain nesting (depth {features['subdomain_depth']}) — suspicious structure.")

        return reasons
