# Import libraries
import re
from urllib.parse import urlparse

import tldextract  # pip install tldextract

from utilities import load_safe_hosts, read_file

# Load lists once at the top
TRUSTED_SITES = read_file("legitimate_domains.csv")  # Set of trusted domains
SAFE_URLS = load_safe_hosts("safe_urls.txt")  # Set of safe hostnames

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)
IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def extract_urls(email):
    """
    Extracts domains from URLs found in an email string.
    Returns a list of registrable domains (e.g. 'paypal.com', 'google.com').
    """
    if not isinstance(email, str):
        return None

    url_pattern = (
        r"(?:https?://|www\.)[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(?:[/?#][^\s]*)?"
    )
    urls = re.findall(url_pattern, email)

    domains = []

    for url in urls:
        if url.startswith("www."):
            url = "http://" + url

        parsed = urlparse(url)
        host = parsed.hostname

        if host:
            ext = tldextract.extract(host)
            if ext.domain and ext.suffix:
                registrable_domain = f"{ext.domain}.{ext.suffix}".lower()
                if registrable_domain not in domains:
                    domains.append(registrable_domain)
            else:
                host_lower = host.lower()
                if host_lower not in domains:
                    domains.append(host_lower)

    return domains if domains else None


def _prepare_hostname(url):
    if not isinstance(url, str) or not url.strip():
        return None, None, "Missing URL or domain."

    candidate = url.strip()
    if "://" not in candidate:
        candidate = "https://" + candidate

    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        return None, None, "Only http and https links are supported."

    if not parsed.hostname:
        return None, None, "URL does not contain a valid hostname."

    hostname = parsed.hostname.lower().rstrip(".")
    if not DOMAIN_PATTERN.match(hostname):
        return None, None, "Hostname format looks invalid."

    registrable_domain = hostname
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        registrable_domain = f"{ext.domain}.{ext.suffix}".lower()

    return hostname, registrable_domain, ""


def _strong_suspicion_reason(hostname, registrable_domain):
    if IPV4_PATTERN.fullmatch(hostname or ""):
        return "Uses an IP address instead of a normal domain."

    if hostname.startswith("xn--") or ".xn--" in hostname:
        return "Uses punycode encoding, which is often used in lookalike domains."

    if (hostname or "").count("-") >= 4:
        return "Uses an unusually hyphenated domain name."

    digit_count = sum(character.isdigit() for character in registrable_domain or "")
    alpha_count = sum(character.isalpha() for character in registrable_domain or "")
    if digit_count >= 4 and digit_count > alpha_count:
        return "Uses unusually heavy digit patterns in the domain."

    return ""


def analyze_url(url):
    """
    Return a richer URL assessment with statuses:
    - trusted: known good domain
    - unlisted: valid but not recognized
    - suspicious: invalid or strongly suspicious structure
    """
    hostname, registrable_domain, error_reason = _prepare_hostname(url)

    if error_reason:
        return {
            "status": "suspicious",
            "domain": str(url).strip() if url is not None else "",
            "reason": error_reason,
            "is_trusted": False,
            "is_suspicious": True,
        }

    if registrable_domain in TRUSTED_SITES or registrable_domain in SAFE_URLS or hostname in SAFE_URLS:
        return {
            "status": "trusted",
            "domain": registrable_domain,
            "reason": "Domain matched the trusted list.",
            "is_trusted": True,
            "is_suspicious": False,
        }

    suspicion_reason = _strong_suspicion_reason(hostname, registrable_domain)
    if suspicion_reason:
        return {
            "status": "suspicious",
            "domain": registrable_domain,
            "reason": suspicion_reason,
            "is_trusted": False,
            "is_suspicious": True,
        }

    return {
        "status": "unlisted",
        "domain": registrable_domain,
        "reason": "Domain is valid but not in the trusted list.",
        "is_trusted": False,
        "is_suspicious": False,
    }


def URLvalidator(url):
    """
    Backward-compatible trusted-domain check.
    Returns True only when the URL is recognized as trusted/safe.
    """
    return analyze_url(url)["status"] == "trusted"


def is_trusted_domain(domain):
    """
    Check if a domain (registrable domain like 'paypal.com') is in trusted sites.
    """
    if not domain:
        return False
    return domain.lower() in TRUSTED_SITES


def is_safe_hostname(hostname):
    """
    Check if a hostname (full hostname like 'secure.paypal.com') is in safe URLs.
    """
    if not hostname:
        return False
    return hostname.lower() in SAFE_URLS
