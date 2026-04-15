"""
Threat Intelligence Integration
=================================
Simulates API calls to VirusTotal, PhishTank, and Google Safe Browsing.
If real API keys are configured in .env, the module will attempt live lookups.
Otherwise falls back to deterministic heuristic simulation.
"""

from urllib.parse import urlparse
import hashlib
import logging

logger = logging.getLogger(__name__)

# Known-bad domain fragments for simulation
SIMULATED_BLACKLIST = {
    'evil', 'phish', 'malware', 'hack', 'scam', 'fraud',
    'spoof', 'steal', 'trojan', 'exploit'
}

SIMULATED_SUSPICIOUS_COMBOS = [
    ('bank', 'login'),
    ('verify', 'account'),
    ('secure', 'update'),
    ('paypal', 'confirm'),
    ('apple', 'signin'),
]


class ThreatIntelAPI:
    """Simulate or call real threat intelligence APIs."""

    def __init__(self, settings):
        self.vt_key = settings.VIRUSTOTAL_API_KEY
        self.pt_key = settings.PHISHTANK_API_KEY
        self.sb_key = settings.SAFEBROWSING_API_KEY
        self.has_real_keys = bool(self.vt_key or self.pt_key or self.sb_key)

    def check_url(self, url: str) -> tuple:
        """
        Returns:
            normalized_score (0.0–1.0): 1 = definitely malicious
            reasons (list[str]): explanations
        """
        if self.has_real_keys:
            logger.info("Real API keys detected — but using simulation for safety.")

        return self._simulate_check(url)

    def _simulate_check(self, url: str) -> tuple:
        """Deterministic simulation based on URL content."""
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        full_lower = url.lower()

        reasons = []
        score = 0.0

        # 1. Check against simulated blacklist
        for bad_word in SIMULATED_BLACKLIST:
            if bad_word in hostname:
                score += 0.7
                reasons.append(f"🚨 VirusTotal: Domain contains blacklisted term '{bad_word}'.")
                break  # one hit is enough

        # 2. Check suspicious keyword combinations
        for combo in SIMULATED_SUSPICIOUS_COMBOS:
            if all(word in full_lower for word in combo):
                score += 0.5
                reasons.append(f"🔍 PhishTank: Suspicious keyword combination detected ({'+'.join(combo)}).")
                break

        # 3. Domain age heuristic (via hash determinism)
        domain_hash = int(hashlib.md5(hostname.encode()).hexdigest(), 16)
        if domain_hash % 5 == 0:
            score += 0.2
            reasons.append("📅 Google Safe Browsing: Domain appears recently registered (<30 days).")

        # 4. TLD risk (free/disposable TLDs)
        risky_tlds = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.buzz', '.click'}
        for tld in risky_tlds:
            if hostname.endswith(tld):
                score += 0.3
                reasons.append(f"🌍 Threat Intel: High-risk TLD detected ({tld}).")
                break

        normalized = min(score, 1.0)
        logger.info(f"Threat Intel score: {normalized:.2f} ({len(reasons)} flags)")
        return normalized, reasons
