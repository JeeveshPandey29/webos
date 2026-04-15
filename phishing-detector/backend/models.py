"""
Pydantic Request / Response Schemas
====================================
Includes input URL validation and rich response models.
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
        v = v.strip()
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        parsed = urlparse(v)
        if not parsed.netloc or not parsed.hostname:
            raise ValueError('URL must contain a valid domain or IP address')
        if len(v) < 10:
            raise ValueError('URL is too short to be valid')
        hostname = parsed.hostname
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_reserved:
                raise ValueError('Localhost, private, and reserved IPs are not allowed')
        except ValueError as e:
            if 'not allowed' in str(e):
                raise
            pass
        if parsed.scheme not in ('http', 'https'):
            raise ValueError('Only HTTP and HTTPS protocols are supported')
        return v


class SSLInfo(BaseModel):
    """SSL certificate analysis."""
    has_ssl: bool = False
    is_valid: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    expires_in_days: Optional[int] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    protocol: Optional[str] = None
    serial_number: Optional[str] = None
    error: Optional[str] = None


class DomainInfo(BaseModel):
    """WHOIS domain analysis."""
    domain: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    name_servers: List[str] = []
    country: Optional[str] = None
    error: Optional[str] = None


class HTMLInfo(BaseModel):
    """HTML content analysis."""
    page_title: Optional[str] = None
    forms_count: int = 0
    external_form_actions: List[str] = []
    external_scripts_count: int = 0
    external_scripts: List[str] = []
    hidden_iframes_count: int = 0
    hidden_iframes: List[str] = []
    password_fields: int = 0
    meta_redirects: List[str] = []
    total_links: int = 0
    external_links: int = 0
    external_link_ratio: float = 0.0
    error: Optional[str] = None


class AnalyzeResponse(BaseModel):
    """Full API response with all analysis details."""
    phishing_probability: float
    label: str
    reasons: List[str]
    confidence_breakdown: Dict[str, float]
    feature_values: Optional[Dict[str, Any]] = None
    ssl_info: Optional[SSLInfo] = None
    domain_info: Optional[DomainInfo] = None
    html_info: Optional[HTMLInfo] = None
