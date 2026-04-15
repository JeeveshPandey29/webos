"""
Domain Analyzer (WHOIS)
========================
Performs WHOIS lookups to extract domain registration info:
  - Domain age
  - Registrar
  - Creation / expiration dates
  - Name servers

Uses python-whois for live lookups with fallback simulation.
"""

import logging
from urllib.parse import urlparse
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    logger.warning("[WHOIS] python-whois not installed. Using simulation mode.")


class DomainAnalyzer:
    """Analyze domain registration details via WHOIS."""

    def analyze(self, url: str) -> dict:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        result = {
            "domain": hostname,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "domain_age_days": None,
            "name_servers": [],
            "country": None,
            "error": None,
        }

        if not hostname:
            result["error"] = "No hostname found"
            return result

        # Extract registrable domain (strip subdomains for WHOIS)
        parts = hostname.split('.')
        if len(parts) >= 2:
            registrable = '.'.join(parts[-2:])
        else:
            registrable = hostname

        if HAS_WHOIS:
            return self._live_lookup(registrable, result)
        else:
            return self._simulate(registrable, result)

    def _live_lookup(self, domain: str, result: dict) -> dict:
        """Perform real WHOIS lookup."""
        try:
            w = whois.whois(domain)

            result["registrar"] = w.registrar or "Unknown"

            # Creation date can be a list or single value
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                result["creation_date"] = str(creation)
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                if hasattr(creation, 'replace'):
                    creation = creation.replace(tzinfo=None)
                age = (now - creation).days
                result["domain_age_days"] = age

            # Expiration date
            expiration = w.expiration_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            if expiration:
                result["expiration_date"] = str(expiration)

            # Name servers
            ns = w.name_servers
            if ns:
                if isinstance(ns, list):
                    result["name_servers"] = [str(n).lower() for n in ns[:5]]
                else:
                    result["name_servers"] = [str(ns).lower()]

            # Country
            result["country"] = getattr(w, 'country', None)

            logger.info(f"[WHOIS] {domain}: Age={result['domain_age_days']}d, "
                        f"Registrar={result['registrar']}")

        except Exception as e:
            result["error"] = f"WHOIS lookup failed: {str(e)[:80]}"
            logger.warning(f"[WHOIS] {domain}: {e}")

        return result

    def _simulate(self, domain: str, result: dict) -> dict:
        """Simulate WHOIS for when python-whois is not installed."""
        import hashlib

        domain_hash = int(hashlib.md5(domain.encode()).hexdigest(), 16)

        # Well-known domains get realistic ages
        known_domains = {
            'google.com': 9500, 'github.com': 6200, 'microsoft.com': 11000,
            'stackoverflow.com': 5800, 'amazon.com': 10500, 'facebook.com': 7300,
            'mituniversity.ac.in': 3650,
        }

        if domain in known_domains:
            result["domain_age_days"] = known_domains[domain]
            result["registrar"] = "Well-known registrar"
        else:
            # Simulate based on hash — suspicious domains get young ages
            age = domain_hash % 3000
            result["domain_age_days"] = age
            result["registrar"] = "Simulated Registrar Inc."

        result["creation_date"] = "Simulated"
        result["name_servers"] = ["ns1.simulated.com", "ns2.simulated.com"]

        logger.info(f"[WHOIS-SIM] {domain}: Age={result['domain_age_days']}d")
        return result
