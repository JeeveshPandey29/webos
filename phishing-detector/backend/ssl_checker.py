"""
SSL Certificate Checker
========================
Performs real SSL/TLS certificate analysis on the target domain.
Returns certificate validity, issuer, expiry, and protocol info.
"""

import ssl
import socket
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

TIMEOUT = 5  # seconds


class SSLChecker:
    """Analyze SSL/TLS certificates for a given URL."""

    def check(self, url: str) -> dict:
        """
        Returns a dict with SSL analysis results.
        Keys: has_ssl, is_valid, issuer, subject, expires_in_days,
              not_before, not_after, protocol, serial_number
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        result = {
            "has_ssl": False,
            "is_valid": False,
            "issuer": None,
            "subject": None,
            "expires_in_days": None,
            "not_before": None,
            "not_after": None,
            "protocol": parsed.scheme.upper(),
            "serial_number": None,
            "error": None,
        }

        if parsed.scheme != 'https':
            result["error"] = "Site does not use HTTPS"
            logger.info(f"[SSL] {hostname}: No HTTPS")
            return result

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol_version = ssock.version()

                    result["has_ssl"] = True
                    result["protocol"] = protocol_version or "TLS"

                    # Issuer
                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    result["issuer"] = issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Unknown'))

                    # Subject
                    subject_dict = dict(x[0] for x in cert.get('subject', []))
                    result["subject"] = subject_dict.get('commonName', hostname)

                    # Validity dates
                    not_before = cert.get('notBefore', '')
                    not_after = cert.get('notAfter', '')

                    if not_after:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        now = datetime.now(timezone.utc).replace(tzinfo=None)
                        days_left = (expiry - now).days
                        result["expires_in_days"] = days_left
                        result["not_after"] = not_after
                        result["is_valid"] = days_left > 0

                    if not_before:
                        result["not_before"] = not_before

                    # Serial
                    result["serial_number"] = cert.get('serialNumber', None)

                    logger.info(f"[SSL] {hostname}: Valid={result['is_valid']}, "
                                f"Issuer={result['issuer']}, Expires in {result['expires_in_days']}d")

        except ssl.SSLCertVerificationError as e:
            result["error"] = f"Certificate verification failed: {str(e)[:80]}"
            logger.warning(f"[SSL] {hostname}: Cert verification error: {e}")
        except socket.timeout:
            result["error"] = "Connection timed out"
            logger.warning(f"[SSL] {hostname}: Timeout")
        except socket.gaierror:
            result["error"] = "Could not resolve hostname"
            logger.warning(f"[SSL] {hostname}: DNS resolution failed")
        except Exception as e:
            result["error"] = f"SSL check failed: {str(e)[:80]}"
            logger.warning(f"[SSL] {hostname}: {e}")

        return result
