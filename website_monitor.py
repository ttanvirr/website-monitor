#!/usr/bin/env python3
"""Daily website availability, DNS, SSL, and domain-expiration monitor.

The script checks one homepage per URL. It does not log in to hosting accounts
and therefore cannot confirm whether a hosting subscription has been paid.
"""

from __future__ import annotations

import argparse
import csv
import html
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import quote, urlsplit, urlunsplit

import requests
from cryptography import x509

PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_URLS_FILE = PROJECT_DIR / "data" / "urls.txt"
DEFAULT_REPORTS_DIR = PROJECT_DIR / "reports"
DEFAULT_LOGS_DIR = PROJECT_DIR / "logs"
USER_AGENT = "WebsiteMonitor/1.0 (+daily availability audit)"

# These phrases are deliberately specific to reduce false positives.
HOSTING_PAGE_PHRASES: dict[str, tuple[str, ...]] = {
    "Possible hosting/account suspension page": (
        "this account has been suspended",
        "hosting account has been suspended",
        "account suspended by hosting provider",
        "your hosting account is suspended",
    ),
    "Possible domain-expiration page": (
        "this domain has expired",
        "this domain name has expired",
        "domain registration has expired",
        "domain expired - renew",
    ),
    "Possible hosting-plan expiration page": (
        "hosting plan has expired",
        "hosting service has expired",
        "hosting subscription has expired",
    ),
    "Possible resource/bandwidth limit page": (
        "resource limit is reached",
        "508 resource limit reached",
        "bandwidth limit exceeded",
        "cpu resource limit exceeded",
    ),
}


@dataclass
class CheckConfig:
    connect_timeout: float = 5.0
    read_timeout: float = 15.0
    warning_days: int = 30


@dataclass
class WebsiteResult:
    website: str
    checked_at: str
    normalized_url: str = ""
    final_url: str = ""
    http_status: str = "N/A"
    availability: str = "NOT_CHECKED"
    response_time_ms: int | str = "N/A"
    content_type: str = "N/A"
    dns_status: str = "NOT_CHECKED"
    resolved_ips: str = "N/A"
    ip_network_info: str = "N/A"
    domain: str = "N/A"
    domain_expiration: str = "Unknown"
    domain_days_remaining: str = "N/A"
    rdap_status: str = "NOT_CHECKED"
    ssl_status: str = "NOT_APPLICABLE"
    ssl_expires_at: str = "N/A"
    ssl_days_remaining: str = "N/A"
    hosting_indicators: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    final_status: str = "UNABLE_TO_VERIFY"

    def csv_row(self) -> dict[str, str]:
        return {
            "Website URL": self.website,
            "HTTP Status": self.http_status,
            "Availability": self.availability,
            "Response Time (ms)": str(self.response_time_ms),
            "Domain Expiration": self.domain_expiration,
            "Domain Days Remaining": str(self.domain_days_remaining),
            "SSL Status": self.ssl_status,
            "SSL Expiration": self.ssl_expires_at,
            "SSL Days Remaining": str(self.ssl_days_remaining),
            "DNS Status": self.dns_status,
            "Resolved IPs": self.resolved_ips,
            "IP Network RDAP (not necessarily host)": self.ip_network_info,
            "Final Status": self.final_status,
            "Final URL": self.final_url or "N/A",
            "Issues": "; ".join(self.issues) or "None detected",
            "Recommended Actions": "; ".join(self.recommendations) or "None",
        }


def normalize_url(raw_url: str) -> tuple[str | None, str | None]:
    """Normalize a URL and reject malformed or unsupported URLs."""
    value = raw_url.strip()
    if not value:
        return None, "URL is empty."
    if "://" not in value:
        value = f"https://{value}"

    try:
        parsed = urlsplit(value)
        # Accessing .port also validates malformed port values.
        _ = parsed.port
        hostname = parsed.hostname
    except ValueError as exc:
        return None, f"Invalid URL: {exc}"

    if parsed.scheme.lower() not in {"http", "https"}:
        return None, "Only http:// and https:// URLs are supported."
    if not hostname:
        return None, "URL does not contain a valid hostname."
    if parsed.username or parsed.password:
        return None, "URLs containing embedded usernames or passwords are not supported."

    # Normalize internationalized hostnames to ASCII for DNS and TLS APIs.
    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return None, "Hostname could not be converted to a valid IDN hostname."

    netloc = ascii_host
    if parsed.port is not None:
        netloc = f"{ascii_host}:{parsed.port}"
    if ":" in ascii_host and not ascii_host.startswith("["):
        netloc = f"[{ascii_host}]" + (f":{parsed.port}" if parsed.port else "")

    normalized = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
    return normalized, None


def get_domain(hostname: str) -> str:
    """Return the hostname used for RDAP lookup (strip the common www prefix)."""
    return hostname[4:] if hostname.lower().startswith("www.") else hostname


def resolve_dns(hostname: str, port: int = 443) -> tuple[str, list[str], str | None]:
    """Resolve a host using the operating system resolver."""
    try:
        try:
            address = ipaddress.ip_address(hostname)
            return "RESOLVED", [str(address)], None
        except ValueError:
            pass

        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in records})
        if not addresses:
            return "FAILED", [], "DNS returned no addresses."
        return "RESOLVED", addresses, None
    except socket.gaierror as exc:
        return "FAILED", [], f"DNS resolution failed: {exc}"
    except OSError as exc:
        return "FAILED", [], f"DNS check failed: {exc}"


def _days_until(expiration: datetime, now: datetime | None = None) -> int:
    current = now or datetime.now(timezone.utc)
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=timezone.utc)
    return int((expiration.astimezone(timezone.utc) - current.astimezone(timezone.utc)).total_seconds() // 86400)


def _parse_rdap_datetime(value: str) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed_date = date.fromisoformat(candidate[:10])
            parsed = datetime.combine(parsed_date, time.min, tzinfo=timezone.utc)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_whois_expiration_text(text: str) -> datetime | None:
    """Extract and parse an expiration date from raw WHOIS text."""
    for line in text.splitlines():
        match = re.search(
            r"(?:registry expiry date|expiry date|expiration date|paid-till|expire date|expires on|expires)\s*[:=]\s*(.+)$",
            line,
            re.IGNORECASE,
        )
        if match:
            candidate = match.group(1).strip()
            dt = _parse_rdap_datetime(candidate)
            if dt:
                return dt
            for fmt in (
                "%d/%m/%Y",
                "%d-%m-%Y",
                "%d.%m.%Y",
                "%d/%m/%Y %H:%M:%S",
                "%d-%m-%Y %H:%M:%S",
                "%Y/%m/%d",
                "%d-%b-%Y",
                "%d-%b-%Y %H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%b %d %Y",
                "%d %b %Y",
            ):
                try:
                    parsed = datetime.strptime(candidate, fmt)
                    return parsed.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
    return None


def lookup_whois_expiration(
    domain: str,
    config: CheckConfig,
) -> tuple[str, str, int | str, str | None]:
    """Look up domain expiration through standard port-43 WHOIS servers as a fallback."""
    lower_domain = domain.lower()
    # Specialized regional servers for ccTLDs without public IANA port-43/RDAP entries
    if lower_domain.endswith(".bd"):
        server = "whois.get.bd"
    else:
        # Check IANA referral for the TLD
        tld = lower_domain.rsplit(".", 1)[-1]
        server = None
        try:
            with socket.create_connection(("whois.iana.org", 43), timeout=config.connect_timeout) as sock:
                sock.sendall(f"{tld}\r\n".encode("utf-8"))
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                for line in response.decode("utf-8", errors="ignore").splitlines():
                    if line.lower().startswith("whois:"):
                        server = line.split(":", 1)[1].strip()
                        break
        except OSError:
            server = None

    if not server:
        return "UNAVAILABLE", "Unknown", "N/A", f"No public WHOIS server identified for domain '{domain}'."

    try:
        with socket.create_connection((server, 43), timeout=config.connect_timeout) as sock:
            sock.sendall(f"{domain}\r\n".encode("utf-8"))
            response = b""
            while len(response) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            text = response.decode("utf-8", errors="ignore")
    except OSError as exc:
        return "UNAVAILABLE", "Unknown", "N/A", f"WHOIS query to {server} failed: {exc}"

    expiration = _parse_whois_expiration_text(text)
    if expiration is None:
        return "NO_EXPIRATION_DATA", "Not published", "N/A", None

    remaining = _days_until(expiration)
    label = expiration.strftime("%Y-%m-%d %H:%M UTC")
    return "FOUND", label, remaining, None


def lookup_domain_expiration(
    domain: str,
    session: requests.Session,
    config: CheckConfig,
) -> tuple[str, str, int | str, str | None]:
    """Look up a domain's expiration event through public RDAP with WHOIS fallback."""
    try:
        ipaddress.ip_address(domain)
        return "NOT_APPLICABLE", "N/A", "N/A", None
    except ValueError:
        pass

    # RDAP provides registration data where the registry publishes it. Some
    # registries redact or omit expiration events, so an unknown result is normal.
    endpoint = f"https://rdap.org/domain/{quote(domain, safe='.-')}"
    rdap_error = None
    try:
        response = session.get(
            endpoint,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"},
            timeout=(config.connect_timeout, config.read_timeout),
            allow_redirects=True,
        )
        if response.status_code == 200:
            data = response.json()
            expiration: datetime | None = None
            for event in data.get("events", []) if isinstance(data, dict) else []:
                if not isinstance(event, dict):
                    continue
                action = str(event.get("eventAction", "")).lower()
                if "expir" in action:
                    expiration = _parse_rdap_datetime(event.get("eventDate", ""))
                    if expiration:
                        break
            if expiration is not None:
                remaining = _days_until(expiration)
                label = expiration.strftime("%Y-%m-%d %H:%M UTC")
                return "FOUND", label, remaining, None
            rdap_error = "RDAP record did not publish an expiration event."
        else:
            rdap_error = f"RDAP lookup returned HTTP {response.status_code}."
    except requests.RequestException as exc:
        rdap_error = f"RDAP lookup failed: {exc}"
    except (ValueError, TypeError) as exc:
        rdap_error = f"RDAP response could not be parsed: {exc}"

    # Fallback to port-43 WHOIS lookup (for ccTLDs like .bd where RDAP is not available)
    whois_status, whois_label, whois_days, whois_error = lookup_whois_expiration(domain, config)
    if whois_status == "FOUND":
        return whois_status, whois_label, whois_days, None

    if whois_status == "NO_EXPIRATION_DATA":
        return "NO_EXPIRATION_DATA", "Not published", "N/A", None

    return "UNAVAILABLE", "Unknown", "N/A", rdap_error or whois_error


def lookup_ip_network_info(
    ip_address: str,
    session: requests.Session,
    config: CheckConfig,
) -> str:
    """Return public IP network-registration clues, not a definitive host identity."""
    try:
        parsed_ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return "Unavailable (invalid IP address)"
    if not parsed_ip.is_global:
        return "Private/reserved IP; public network lookup not applicable"

    endpoint = f"https://rdap.org/ip/{quote(str(parsed_ip), safe=':.')}"
    try:
        response = session.get(
            endpoint,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"},
            timeout=(config.connect_timeout, config.read_timeout),
            allow_redirects=True,
        )
        if response.status_code != 200:
            return f"Unavailable (RDAP HTTP {response.status_code})"
        data = response.json()
    except (requests.RequestException, ValueError, TypeError):
        return "Unavailable"

    if not isinstance(data, dict):
        return "Unavailable"
    details: list[str] = []
    for key, label in (("name", "Network"), ("handle", "Handle"), ("country", "Country")):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            details.append(f"{label}: {value.strip()}")
    start = data.get("startAddress")
    end = data.get("endAddress")
    if start and end:
        details.append(f"Range: {start}–{end}")

    # vCard full-name/org fields sometimes identify the network registrant.
    for entity in data.get("entities", []) if isinstance(data.get("entities", []), list) else []:
        vcard = entity.get("vcardArray") if isinstance(entity, dict) else None
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            continue
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] in {"fn", "org"}:
                value = item[3]
                if isinstance(value, list):
                    value = " ".join(str(part) for part in value if part)
                if isinstance(value, str) and value.strip():
                    details.append(f"Registrant: {value.strip()}")
                    break
        if any(detail.startswith("Registrant:") for detail in details):
            break

    return "; ".join(dict.fromkeys(details)) or "RDAP record available; network name not provided"


def check_ssl_certificate(hostname: str, port: int, config: CheckConfig) -> tuple[str, str, int | str, str | None]:
    """Inspect an HTTPS certificate, including expiry for untrusted certificates."""
    timeout = max(config.connect_timeout, config.read_timeout)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                certificate = tls_socket.getpeercert()
        not_after = certificate.get("notAfter")
        if not not_after:
            return "CHECK_FAILED", "Unknown", "N/A", "Certificate did not include an expiration date."
        expiration = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        remaining = _days_until(expiration)
        status = "EXPIRED" if remaining < 0 else "EXPIRES_SOON" if remaining <= config.warning_days else "VALID"
        return status, expiration.strftime("%Y-%m-%d %H:%M UTC"), remaining, None

    except ssl.SSLCertVerificationError as exc:
        # Inspect the certificate without trusting it, only to report its dates.
        # This does NOT disable certificate verification for the HTTP request.
        verification_error = str(exc)
        try:
            unverified_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            unverified_context.check_hostname = False
            unverified_context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as raw_socket:
                with unverified_context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                    certificate_der = tls_socket.getpeercert(binary_form=True)
            certificate = x509.load_der_x509_certificate(certificate_der)
            expiration = getattr(certificate, "not_valid_after_utc", None)
            if expiration is None:
                expiration = certificate.not_valid_after.replace(tzinfo=timezone.utc)
            remaining = _days_until(expiration)
            status = "EXPIRED" if remaining < 0 else "INVALID_OR_UNTRUSTED"
            return status, expiration.strftime("%Y-%m-%d %H:%M UTC"), remaining, verification_error
        except Exception as inspect_exc:  # A failed secondary inspection is non-fatal.
            return "INVALID_OR_UNTRUSTED", "Unknown", "N/A", f"{verification_error}; certificate date inspection failed: {inspect_exc}"
    except (OSError, ssl.SSLError, ValueError) as exc:
        return "CHECK_FAILED", "Unknown", "N/A", f"SSL check failed: {exc}"


def detect_hosting_indicators(page_text: str) -> list[str]:
    text = (page_text or "").lower()
    found: list[str] = []
    for label, phrases in HOSTING_PAGE_PHRASES.items():
        if any(phrase in text for phrase in phrases):
            found.append(label)
    return found


def _get_port(url: str) -> int:
    parsed = urlsplit(url)
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _classify_result(result: WebsiteResult, warning_days: int) -> str:
    if result.availability == "INVALID_URL":
        return "UNABLE_TO_VERIFY"

    indicator_text = " ".join(result.hosting_indicators).lower()
    if (
        (isinstance(result.domain_days_remaining, int) and result.domain_days_remaining < 0)
        or "domain-expiration" in indicator_text
        or "hosting/account suspension" in indicator_text
        or "hosting-plan expiration" in indicator_text
    ):
        return "POTENTIAL_EXPIRATION"
    if result.hosting_indicators:
        return "WARNING"

    if result.http_status.isdigit() and int(result.http_status) >= 500:
        return "DOWN"
    if result.availability in {"TIMEOUT", "CONNECTION_ERROR", "DNS_ERROR", "TOO_MANY_REDIRECTS", "REQUEST_ERROR"}:
        # If the only reason HTTPS failed is certificate verification, report a
        # security warning rather than incorrectly implying the host is offline.
        if result.availability == "REQUEST_ERROR" and result.ssl_status in {"EXPIRED", "INVALID_OR_UNTRUSTED"}:
            return "WARNING"
        return "DOWN"

    if result.http_status.isdigit() and int(result.http_status) >= 400:
        return "WARNING"
    if result.availability == "SSL_ERROR":
        return "WARNING"
    if result.availability == "AVAILABLE" and result.content_type not in {"text/html", "application/xhtml+xml", "HTML (detected)"}:
        return "WARNING"
    if result.normalized_url.startswith("http://"):
        return "WARNING"
    if result.dns_status == "FAILED":
        return "WARNING"  # An HTTP proxy may work even if local DNS does not.
    if result.ssl_status in {"EXPIRED", "INVALID_OR_UNTRUSTED", "EXPIRES_SOON", "CHECK_FAILED"}:
        return "WARNING"
    if isinstance(result.ssl_days_remaining, int) and result.ssl_days_remaining <= warning_days:
        return "WARNING"
    if isinstance(result.domain_days_remaining, int) and result.domain_days_remaining <= warning_days:
        return "WARNING"
    if result.availability == "AVAILABLE":
        return "WORKING"
    return "UNABLE_TO_VERIFY"


def _build_recommendations(result: WebsiteResult, warning_days: int) -> list[str]:
    actions: list[str] = []
    if result.final_status == "POTENTIAL_EXPIRATION":
        actions.append("Verify the domain/hosting account with the registrar or hosting provider immediately; public evidence does not confirm payment status.")
    if result.final_status == "DOWN":
        actions.append("Check the origin server, web-server logs, DNS configuration, and hosting provider status.")
    if result.http_status.isdigit() and int(result.http_status) >= 400:
        actions.append("Investigate the HTTP error and confirm the homepage is intended to be publicly accessible.")
    if result.ssl_status == "EXPIRED":
        actions.append("Renew or replace the expired SSL certificate and verify the full certificate chain.")
    elif result.ssl_status == "INVALID_OR_UNTRUSTED":
        actions.append("Inspect the certificate hostname, trust chain, and certificate installation.")
    elif result.ssl_status == "EXPIRES_SOON" or (isinstance(result.ssl_days_remaining, int) and result.ssl_days_remaining <= warning_days):
        actions.append("Renew the SSL certificate before its expiration date.")
    if isinstance(result.domain_days_remaining, int):
        if result.domain_days_remaining < 0:
            actions.append("Check the registrar account and renew or recover the domain if possible.")
        elif result.domain_days_remaining <= warning_days:
            actions.append("Confirm domain renewal is scheduled with the registrar.")
    if result.ssl_status == "NOT_APPLICABLE" and result.normalized_url.startswith("http://"):
        actions.append("Consider enabling HTTPS and installing a valid SSL certificate.")
    if result.content_type not in {"text/html", "application/xhtml+xml", "HTML (detected)", "N/A"} and result.availability == "AVAILABLE":
        actions.append("Confirm that the homepage is expected to return HTML rather than another content type.")
    if result.rdap_status in {"UNAVAILABLE", "NO_EXPIRATION_DATA"}:
        actions.append("Domain expiration could not be confirmed from public RDAP data; verify it in the registrar account.")
    if result.ssl_status == "CHECK_FAILED":
        actions.append("Recheck the SSL endpoint; the certificate could not be fully inspected.")
    if not actions and result.final_status == "UNABLE_TO_VERIFY":
        actions.append("Correct the URL or repeat the check from a network that can reach the website.")
    return list(dict.fromkeys(actions))


def check_website(
    raw_url: str,
    session: requests.Session,
    config: CheckConfig,
    ip_info_cache: dict[str, str] | None = None,
) -> WebsiteResult:
    checked_at = datetime.now().astimezone().isoformat(timespec="seconds")
    result = WebsiteResult(website=raw_url, checked_at=checked_at)
    normalized_url, url_error = normalize_url(raw_url)
    if url_error or not normalized_url:
        result.availability = "INVALID_URL"
        result.issues.append(url_error or "Invalid URL.")
        result.final_status = "UNABLE_TO_VERIFY"
        result.recommendations = ["Correct the URL in data/urls.txt and run the monitor again."]
        return result

    result.normalized_url = normalized_url
    parsed = urlsplit(normalized_url)
    hostname = parsed.hostname or ""
    port = _get_port(normalized_url)
    domain = get_domain(hostname)
    result.domain = domain

    dns_status, addresses, dns_error = resolve_dns(hostname, port)
    result.dns_status = dns_status
    result.resolved_ips = ", ".join(addresses) if addresses else "N/A"
    if dns_error:
        result.issues.append(dns_error)
    if addresses:
        first_ip = addresses[0]
        cache = ip_info_cache if ip_info_cache is not None else {}
        if first_ip not in cache:
            cache[first_ip] = lookup_ip_network_info(first_ip, session, config)
        result.ip_network_info = cache[first_ip]

    try:
        ipaddress.ip_address(hostname)
        result.rdap_status = "NOT_APPLICABLE"
        result.domain_expiration = "N/A (IP address)"
    except ValueError:
        rdap_status, expiration_label, days_remaining, rdap_error = lookup_domain_expiration(domain, session, config)
        result.rdap_status = rdap_status
        result.domain_expiration = expiration_label
        result.domain_days_remaining = days_remaining
        if rdap_error:
            result.issues.append(rdap_error)
        if isinstance(days_remaining, int) and days_remaining < 0:
            result.issues.append("The public RDAP record indicates that the domain expiration date has passed.")
        elif isinstance(days_remaining, int) and days_remaining <= config.warning_days:
            result.issues.append(f"The domain is due to expire in approximately {days_remaining} day(s).")

    if parsed.scheme == "https":
        ssl_status, ssl_expiration, ssl_days, ssl_error = check_ssl_certificate(hostname, port, config)
        result.ssl_status = ssl_status
        result.ssl_expires_at = ssl_expiration
        result.ssl_days_remaining = ssl_days
        if ssl_error:
            result.issues.append(f"SSL: {ssl_error}")
        if isinstance(ssl_days, int) and ssl_days < 0:
            result.issues.append("The SSL certificate has expired.")
        elif isinstance(ssl_days, int) and ssl_days <= config.warning_days:
            result.issues.append(f"The SSL certificate expires in approximately {ssl_days} day(s).")
    else:
        result.ssl_status = "NOT_APPLICABLE"
        result.issues.append("The URL uses HTTP rather than HTTPS; no SSL certificate is used for this URL.")

    try:
        response = session.get(
            normalized_url,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"},
            timeout=(config.connect_timeout, config.read_timeout),
            allow_redirects=True,
        )
        result.http_status = str(response.status_code)
        result.final_url = response.url
        result.response_time_ms = int(response.elapsed.total_seconds() * 1000)
        raw_content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        body = response.text or ""
        if raw_content_type:
            result.content_type = raw_content_type
        elif re.search(r"<\s*!doctype\s+html|<\s*html\b", body[:1000], re.IGNORECASE):
            result.content_type = "HTML (detected)"
        else:
            result.content_type = "Unknown"

        if 200 <= response.status_code < 400:
            result.availability = "AVAILABLE"
        elif response.status_code >= 500:
            result.availability = "SERVER_ERROR"
            result.issues.append(f"The server returned HTTP {response.status_code}.")
        else:
            result.availability = "HTTP_ERROR"
            result.issues.append(f"The website returned HTTP {response.status_code}.")

        # Search the response body even if the server mislabeled the content type.
        result.hosting_indicators = detect_hosting_indicators(body)
        if result.hosting_indicators:
            result.issues.extend(result.hosting_indicators)
        if result.content_type not in {"text/html", "application/xhtml+xml", "HTML (detected)"} and result.availability == "AVAILABLE":
            result.issues.append(f"Homepage returned {result.content_type}, not an identified HTML response.")

        if response.history:
            redirect_count = len(response.history)
            result.issues.append(f"The request followed {redirect_count} redirect(s); final URL: {response.url}")

    except requests.exceptions.SSLError as exc:
        result.availability = "SSL_ERROR"
        result.issues.append(f"HTTPS request failed certificate/security verification: {exc}")
    except requests.exceptions.Timeout as exc:
        result.availability = "TIMEOUT"
        result.issues.append(f"The website request timed out: {exc}")
    except requests.exceptions.TooManyRedirects as exc:
        result.availability = "TOO_MANY_REDIRECTS"
        result.issues.append(f"The website exceeded the redirect limit: {exc}")
    except requests.exceptions.ConnectionError as exc:
        message = str(exc)
        result.availability = "DNS_ERROR" if "Name or service not known" in message or "getaddrinfo failed" in message else "CONNECTION_ERROR"
        result.issues.append(f"Could not establish an HTTP connection: {exc}")
    except requests.exceptions.RequestException as exc:
        result.availability = "REQUEST_ERROR"
        result.issues.append(f"HTTP request failed: {exc}")

    result.final_status = _classify_result(result, config.warning_days)
    result.recommendations = _build_recommendations(result, config.warning_days)
    return result


def check_all_websites(
    urls: Iterable[str],
    session: requests.Session,
    config: CheckConfig,
    logger: logging.Logger | None = None,
) -> list[WebsiteResult]:
    """Check every URL independently so a single unexpected error is isolated."""
    results: list[WebsiteResult] = []
    ip_info_cache: dict[str, str] = {}
    for url in urls:
        try:
            if logger:
                logger.info("Checking %s", url)
            results.append(check_website(url, session, config, ip_info_cache))
        except Exception as exc:  # Defensive boundary: keep processing other URLs.
            if logger:
                logger.exception("Unexpected error while checking %s", url)
            result = WebsiteResult(
                website=url,
                checked_at=datetime.now().astimezone().isoformat(timespec="seconds"),
                availability="REQUEST_ERROR",
                issues=[f"Unexpected check error: {type(exc).__name__}: {exc}"],
                final_status="UNABLE_TO_VERIFY",
                recommendations=["Review the execution log and retry this website."]
            )
            results.append(result)
    return results


def load_urls(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"URL list not found: {path}")
    urls: list[str] = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            urls.append(value)
    return urls


def _report_base_path(reports_dir: Path, now: datetime) -> Path:
    date_stem = f"website_report_{now.strftime('%Y-%m-%d')}"
    base = reports_dir / date_stem
    if not Path(f"{base}.html").exists() and not Path(f"{base}.csv").exists():
        return base

    timestamp_stem = f"{date_stem}_{now.strftime('%H%M%S')}"
    candidate = reports_dir / timestamp_stem
    counter = 2
    while Path(f"{candidate}.html").exists() or Path(f"{candidate}.csv").exists():
        candidate = reports_dir / f"{timestamp_stem}_{counter}"
        counter += 1
    return candidate


def _summary_counts(results: list[WebsiteResult]) -> dict[str, int]:
    statuses = ["WORKING", "WARNING", "DOWN", "POTENTIAL_EXPIRATION", "UNABLE_TO_VERIFY"]
    return {status: sum(result.final_status == status for result in results) for status in statuses}


def write_reports(results: list[WebsiteResult], reports_dir: Path, now: datetime | None = None) -> tuple[Path, Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_time = now or datetime.now().astimezone()
    base = _report_base_path(reports_dir, report_time)
    # Append extensions instead of Path.with_suffix(): the date's final ".DD"
    # can otherwise be interpreted as a suffix and silently remove the day.
    csv_path = Path(f"{base}.csv")
    html_path = Path(f"{base}.html")

    fieldnames = list(results[0].csv_row().keys()) if results else [
        "Website URL", "HTTP Status", "Availability", "Domain Expiration", "Domain Days Remaining",
        "SSL Status", "SSL Expiration", "SSL Days Remaining", "DNS Status", "Resolved IPs",
        "IP Network RDAP (not necessarily host)", "Hosting Indicators", "Final Status", "Final URL", "Issues", "Recommended Actions",
    ]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result.csv_row())

    counts = _summary_counts(results)
    table_rows: list[str] = []
    for result in results:
        status_class = result.final_status.lower()
        issues = "<ul>" + "".join(f"<li>{html.escape(item)}</li>" for item in result.issues) + "</ul>" if result.issues else "None detected"
        recommendations = "<ul>" + "".join(f"<li>{html.escape(item)}</li>" for item in result.recommendations) + "</ul>" if result.recommendations else "None"
        if result.normalized_url:
            website_label = (
                f"<a href=\"{html.escape(result.normalized_url, quote=True)}\">"
                f"{html.escape(result.website)}</a>"
            )
        else:
            # Invalid/untrusted input is shown as text, never emitted as a link.
            website_label = html.escape(result.website)
        if isinstance(result.response_time_ms, (int, float)):
            if result.response_time_ms >= 1000:
                response_time_display = f"{result.response_time_ms / 1000:.2f} s<small>{result.response_time_ms} ms</small>"
            else:
                response_time_display = f"{result.response_time_ms} ms"
        else:
            response_time_display = html.escape(str(result.response_time_ms))

        table_rows.append(
            "<tr>"
            f"<td>{website_label}"
            f"<small>Final URL: {html.escape(result.final_url or 'N/A')}</small></td>"
            f"<td>{html.escape(result.http_status)}</td>"
            f"<td>{html.escape(result.availability)}</td>"
            f"<td>{response_time_display}</td>"
            f"<td>{html.escape(result.domain_expiration)}<small>{html.escape(str(result.domain_days_remaining))} day(s) remaining</small></td>"
            f"<td>{html.escape(result.ssl_status)}<small>{html.escape(result.ssl_expires_at)}; {html.escape(str(result.ssl_days_remaining))} day(s)</small></td>"
            f"<td>{html.escape(result.dns_status)}<small>{html.escape(result.resolved_ips)}</small></td>"
            f"<td>{html.escape(result.ip_network_info)}</td>"
            f"<td><span class=\"status {status_class}\">{html.escape(result.final_status)}</span></td>"
            f"<td>{issues}</td><td>{recommendations}</td>"
            "</tr>"
        )

    summary_cards = "".join(
        f"<div class='summary-card'><strong>{counts[key]}</strong><span>{html.escape(key.replace('_', ' ').title())}</span></div>"
        for key in ["WORKING", "WARNING", "DOWN", "POTENTIAL_EXPIRATION", "UNABLE_TO_VERIFY"]
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Website Monitoring Report - {report_time.strftime('%Y-%m-%d')}</title>
<style>
:root {{ color-scheme: light; font-family: Arial, Helvetica, sans-serif; }}
body {{ margin: 0; padding: 28px; background: #f4f6f8; color: #1f2937; }}
main {{ max-width: 1600px; margin: auto; }}
h1 {{ margin-bottom: 6px; }}
.meta {{ color: #596579; margin-bottom: 22px; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 18px 0 24px; }}
.summary-card {{ background: #fff; border: 1px solid #e1e6eb; border-radius: 9px; padding: 16px; }}
.summary-card strong {{ display: block; font-size: 25px; margin-bottom: 5px; }}
.summary-card span {{ color: #596579; font-size: 13px; }}
.table-wrap {{ overflow-x: auto; background: #fff; border: 1px solid #e1e6eb; border-radius: 9px; }}
table {{ width: 100%; border-collapse: collapse; min-width: 1300px; font-size: 13px; }}
th, td {{ padding: 12px; border-bottom: 1px solid #e8ecf0; text-align: left; vertical-align: top; }}
th {{ background: #f8fafc; position: sticky; top: 0; }}
td small {{ display: block; margin-top: 5px; color: #667085; max-width: 220px; overflow-wrap: anywhere; }}
td ul {{ padding-left: 18px; margin: 0; }}
td li {{ margin: 0 0 5px; }}
a {{ color: #175cd3; overflow-wrap: anywhere; }}
.status {{ display: inline-block; border-radius: 20px; padding: 5px 8px; font-weight: 700; font-size: 11px; white-space: nowrap; }}
.working {{ color: #067647; background: #ecfdf3; }} .warning {{ color: #b54708; background: #fffaeb; }}
.down, .potential_expiration {{ color: #b42318; background: #fef3f2; }} .unable_to_verify {{ color: #475467; background: #f2f4f7; }}
.note {{ margin-top: 18px; color: #596579; font-size: 13px; line-height: 1.5; }}
@media (max-width: 600px) {{ body {{ padding: 14px; }} }}
</style>
</head>
<body><main>
<h1>Website Availability and Hosting Monitor</h1>
<div class="meta">Audit time: {html.escape(report_time.isoformat(timespec='seconds'))} · Total websites checked: {len(results)}</div>
<div class="summary">{summary_cards}</div>
<div class="table-wrap"><table>
<thead><tr><th>Website</th><th>HTTP</th><th>Availability</th><th>Response time</th><th>Domain expiration</th><th>SSL</th><th>DNS</th><th>IP network RDAP (not necessarily host)</th><th>Final status</th><th>Issues</th><th>Recommended actions</th></tr></thead>
<tbody>{''.join(table_rows)}</tbody>
</table></div>
<p class="note"><strong>Important:</strong> This report checks public website behavior and public registration/certificate data. It cannot confirm whether a hosting invoice has been paid or a hosting subscription is active. A website can be down for reasons other than hosting expiration, and RDAP data may omit domain expiration dates.</p>
</main></body></html>"""
    html_path.write_text(document, encoding="utf-8")
    return csv_path, html_path


def configure_logging(logs_dir: Path) -> logging.Logger:
    logs_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("website_monitor")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    file_handler = RotatingFileHandler(
        logs_dir / "website_monitor.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check website availability, DNS, SSL, and public domain expiration data.")
    parser.add_argument("--urls-file", type=Path, default=DEFAULT_URLS_FILE, help="Path to the URL list (default: data/urls.txt).")
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR, help="Directory for CSV and HTML reports.")
    parser.add_argument("--logs-dir", type=Path, default=DEFAULT_LOGS_DIR, help="Directory for execution logs.")
    parser.add_argument("--connect-timeout", type=float, default=5.0, help="Connection timeout in seconds (default: 5).")
    parser.add_argument("--read-timeout", type=float, default=15.0, help="Response timeout in seconds (default: 15).")
    parser.add_argument("--warning-days", type=int, default=30, help="Flag domain/SSL expirations within this many days (default: 30).")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    if args.connect_timeout <= 0 or args.read_timeout <= 0 or args.warning_days < 0:
        print("Timeouts must be positive and warning-days cannot be negative.", file=sys.stderr)
        return 2

    logger = configure_logging(args.logs_dir)
    try:
        urls = load_urls(args.urls_file)
    except (OSError, UnicodeError) as exc:
        logger.error("Could not load URL list: %s", exc)
        return 1

    if not urls:
        logger.error("No website URLs found in %s", args.urls_file)
        return 1

    config = CheckConfig(
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        warning_days=args.warning_days,
    )
    logger.info("Starting audit for %d website(s).", len(urls))
    with requests.Session() as session:
        results = check_all_websites(urls, session, config, logger)

    csv_path, html_path = write_reports(results, args.reports_dir)
    counts = _summary_counts(results)
    logger.info(
        "Audit finished. Working=%d Warning=%d Down=%d Potential expiration=%d Unable to verify=%d",
        counts["WORKING"], counts["WARNING"], counts["DOWN"],
        counts["POTENTIAL_EXPIRATION"], counts["UNABLE_TO_VERIFY"],
    )
    logger.info("CSV report: %s", csv_path)
    logger.info("HTML report: %s", html_path)
    print(f"\nReports created:\n- {csv_path}\n- {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
