"""
Pydantic Request / Response Schemas
====================================
Includes input URL validation with edge case handling.
"""

from pydantic import BaseModel, field_validator
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
import ipaddress


class AnalyzeRequest(BaseModel):
    """Incoming analysis request from the Chrome extension."""
    url: str

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        # Strip whitespace
        v = v.strip()

        # Must be HTTP or HTTPS
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')

        # Must have a valid netloc
        parsed = urlparse(v)
        if not parsed.netloc or not parsed.hostname:
            raise ValueError('URL must contain a valid domain or IP address')

        # Reject empty / too-short URLs
        if len(v) < 10:
            raise ValueError('URL is too short to be valid')

        # Reject localhost and private IPs
        hostname = parsed.hostname
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                raise ValueError('Localhost, private, and reserved IPs are not allowed')
        except ValueError as e:
            # If it's our own raised ValueError, re-raise it
            if 'not allowed' in str(e):
                raise
            # Otherwise it's a normal domain name → fine
            pass

        # Reject non-HTTP schemes that snuck through
        if parsed.scheme not in ('http', 'https'):
            raise ValueError('Only HTTP and HTTPS protocols are supported')

        return v


class AnalyzeResponse(BaseModel):
    """API response returned to the Chrome extension."""
    phishing_probability: float
    label: str   # "phishing" | "suspicious" | "legitimate"
    reasons: List[str]
    confidence_breakdown: Dict[str, float]
    feature_values: Optional[Dict[str, Any]] = None
