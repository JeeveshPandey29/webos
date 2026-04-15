"""
Rule Engine (YARA-like Heuristic Detection)
=============================================
Each rule has a name, severity weight, description, and trigger function.
The engine evaluates all rules and returns a normalized score (0–1)
plus the list of matched rule names.
"""

import logging

logger = logging.getLogger(__name__)


class Rule:
    """Single heuristic rule definition."""
    def __init__(self, name: str, severity: int, description: str, trigger):
        self.name = name
        self.severity = severity
        self.description = description
        self.trigger = trigger  # callable(features_dict) -> bool


class RuleEngine:
    """Evaluate a set of YARA-like heuristic rules against URL features."""

    def __init__(self):
        self.rules = [
            Rule(
                name="SUSP_KEYWORDS",
                severity=25,
                description="URL contains phishing-associated keywords",
                trigger=lambda f: f.get('keyword_count', 0) > 0
            ),
            Rule(
                name="NO_HTTPS",
                severity=35,
                description="No TLS/SSL – connection is unencrypted",
                trigger=lambda f: f.get('has_https', 1) == 0
            ),
            Rule(
                name="EXCESSIVE_SUBDOMAINS",
                severity=20,
                description="Hostname has 4+ subdomains",
                trigger=lambda f: f.get('subdomain_depth', 0) >= 3
            ),
            Rule(
                name="RAW_IP_ADDRESS",
                severity=45,
                description="URL uses a raw IP address as hostname",
                trigger=lambda f: f.get('has_ip', 0) == 1
            ),
            Rule(
                name="AT_SYMBOL",
                severity=50,
                description="URL contains '@' to obscure destination",
                trigger=lambda f: f.get('has_at_symbol', 0) == 1
            ),
            Rule(
                name="LONG_URL",
                severity=15,
                description="URL length exceeds 75 characters",
                trigger=lambda f: f.get('url_length', 0) > 75
            ),
            Rule(
                name="HYPHEN_BOMB",
                severity=20,
                description="URL contains 3+ hyphens (domain spoofing)",
                trigger=lambda f: f.get('num_hyphens', 0) >= 3
            ),
            Rule(
                name="DEEP_PATH",
                severity=15,
                description="URL path has 5+ slashes (redirect chains)",
                trigger=lambda f: f.get('num_slashes', 0) >= 5
            ),
        ]

    def evaluate(self, features: dict) -> tuple:
        """
        Returns:
            normalized_score (float): 0.0–1.0
            matched_rules (list[str]): descriptions of matched rules
        """
        matched = []
        total_severity = 0

        for rule in self.rules:
            if rule.trigger(features):
                matched.append(f"[{rule.name}] {rule.description}")
                total_severity += rule.severity
                logger.info(f"Rule triggered: {rule.name} (severity={rule.severity})")

        max_possible = sum(r.severity for r in self.rules)
        normalized = min(total_severity / max_possible, 1.0) if max_possible > 0 else 0.0

        logger.info(f"Rule engine score: {normalized:.2f} ({len(matched)}/{len(self.rules)} rules matched)")
        return normalized, matched
