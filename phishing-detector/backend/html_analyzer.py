"""
HTML Content Analyzer
======================
Fetches the target page and analyzes its HTML for phishing indicators:
  - Forms pointing to external domains
  - Hidden iframes
  - External scripts from third-party domains
  - Password input fields
  - Meta refresh redirects
  - Suspicious title/content patterns
"""

import logging
import re
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

try:
    import requests
    from html.parser import HTMLParser
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

FETCH_TIMEOUT = 8  # seconds


class SimpleHTMLAnalyzer(HTMLParser):
    """Lightweight HTML parser to extract security-relevant elements."""

    def __init__(self, base_domain: str):
        super().__init__()
        self.base_domain = base_domain
        self.forms = []                # form action URLs
        self.external_scripts = []     # scripts from other domains
        self.hidden_iframes = []       # hidden or tiny iframes
        self.password_fields = 0
        self.meta_refreshes = []       # meta refresh redirects
        self.title = ""
        self._in_title = False
        self.total_links = 0
        self.external_links = 0

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == 'form':
            action = attrs_dict.get('action', '')
            self.forms.append(action)

        elif tag == 'script':
            src = attrs_dict.get('src', '')
            if src:
                self._check_external(src, self.external_scripts)

        elif tag == 'iframe':
            style = attrs_dict.get('style', '').lower()
            width = attrs_dict.get('width', '999')
            height = attrs_dict.get('height', '999')
            hidden = attrs_dict.get('hidden', None)

            is_hidden = (
                hidden is not None or
                'display:none' in style or
                'visibility:hidden' in style or
                'display: none' in style or
                width in ('0', '1') or
                height in ('0', '1')
            )
            if is_hidden:
                src = attrs_dict.get('src', 'unknown')
                self.hidden_iframes.append(src)

        elif tag == 'input':
            input_type = attrs_dict.get('type', '').lower()
            if input_type == 'password':
                self.password_fields += 1

        elif tag == 'meta':
            http_equiv = attrs_dict.get('http-equiv', '').lower()
            content = attrs_dict.get('content', '')
            if http_equiv == 'refresh' and 'url=' in content.lower():
                self.meta_refreshes.append(content)

        elif tag == 'a':
            href = attrs_dict.get('href', '')
            if href.startswith('http'):
                self.total_links += 1
                try:
                    link_domain = urlparse(href).hostname or ''
                    if link_domain and not link_domain.endswith(self.base_domain):
                        self.external_links += 1
                except Exception:
                    pass

        elif tag == 'title':
            self._in_title = True

    def handle_data(self, data):
        if self._in_title:
            self.title += data

    def handle_endtag(self, tag):
        if tag == 'title':
            self._in_title = False

    def _check_external(self, url: str, target_list: list):
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ''
            if host and not host.endswith(self.base_domain):
                target_list.append(url)
        except Exception:
            pass


class HTMLAnalyzer:
    """Fetch and analyze a web page for phishing indicators."""

    def analyze(self, url: str) -> dict:
        result = {
            "page_title": None,
            "forms_count": 0,
            "external_form_actions": [],
            "external_scripts_count": 0,
            "external_scripts": [],
            "hidden_iframes_count": 0,
            "hidden_iframes": [],
            "password_fields": 0,
            "meta_redirects": [],
            "total_links": 0,
            "external_links": 0,
            "external_link_ratio": 0.0,
            "error": None,
        }

        if not HAS_REQUESTS:
            result["error"] = "requests library not available"
            return result

        parsed = urlparse(url)
        base_domain = parsed.hostname or ""

        try:
            resp = requests.get(url, timeout=FETCH_TIMEOUT, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Sentinel-AI/2.0'
            }, verify=True, allow_redirects=True)

            html_content = resp.text[:500000]  # Limit to 500KB

            parser = SimpleHTMLAnalyzer(base_domain)
            parser.feed(html_content)

            result["page_title"] = parser.title.strip() if parser.title else None
            result["forms_count"] = len(parser.forms)
            result["password_fields"] = parser.password_fields
            result["hidden_iframes_count"] = len(parser.hidden_iframes)
            result["hidden_iframes"] = parser.hidden_iframes[:5]
            result["meta_redirects"] = parser.meta_refreshes[:3]
            result["total_links"] = parser.total_links
            result["external_links"] = parser.external_links

            # External form actions
            for action in parser.forms:
                if action and action.startswith('http'):
                    try:
                        action_host = urlparse(action).hostname or ''
                        if action_host and not action_host.endswith(base_domain):
                            result["external_form_actions"].append(action)
                    except Exception:
                        pass

            # External scripts
            result["external_scripts_count"] = len(parser.external_scripts)
            result["external_scripts"] = parser.external_scripts[:5]

            # External link ratio
            if parser.total_links > 0:
                result["external_link_ratio"] = round(
                    parser.external_links / parser.total_links, 2
                )

            logger.info(f"[HTML] {base_domain}: Forms={result['forms_count']}, "
                        f"ExtScripts={result['external_scripts_count']}, "
                        f"Passwords={result['password_fields']}, "
                        f"HiddenIframes={result['hidden_iframes_count']}")

        except requests.exceptions.SSLError:
            result["error"] = "SSL certificate error when fetching page"
            logger.warning(f"[HTML] {url}: SSL error")
        except requests.exceptions.Timeout:
            result["error"] = "Page fetch timed out"
            logger.warning(f"[HTML] {url}: Timeout")
        except requests.exceptions.ConnectionError:
            result["error"] = "Could not connect to page"
            logger.warning(f"[HTML] {url}: Connection error")
        except Exception as e:
            result["error"] = f"HTML analysis failed: {str(e)[:80]}"
            logger.warning(f"[HTML] {url}: {e}")

        return result
