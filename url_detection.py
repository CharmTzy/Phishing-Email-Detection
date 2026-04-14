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
TOKEN_SPLIT_PATTERN = re.compile(r"[^a-z0-9]+")

RISKY_BRAND_MODIFIERS = {
    "account",
    "auth",
    "billing",
    "bonus",
    "check",
    "claim",
    "confirm",
    "gift",
    "invoice",
    "limited",
    "logon",
    "login",
    "pay",
    "payment",
    "portal",
    "prize",
    "recover",
    "reset",
    "secure",
    "security",
    "signin",
    "support",
    "update",
    "verify",
    "wallet",
    "web",
}


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


def normalize_registrable_domain(value):
    """
    Normalize a URL or hostname into a registrable/base domain.
    """
    _, registrable_domain, error_reason = _prepare_hostname(value)
    if error_reason:
        return ""
    return registrable_domain


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


def _token_distance(left, right):
    if left == right:
        return 0

    previous = list(range(len(right) + 1))
    current = [0] * (len(right) + 1)

    for i, left_char in enumerate(left, start=1):
        current[0] = i
        for j, right_char in enumerate(right, start=1):
            if left_char == right_char:
                current[j] = previous[j - 1]
            else:
                current[j] = 1 + min(previous[j - 1], previous[j], current[j - 1])
        previous, current = current, previous

    return previous[-1]


def _trusted_brand_map():
    brand_map = {}

    for trusted_site in TRUSTED_SITES:
        extracted = tldextract.extract(trusted_site)
        if extracted.domain and extracted.suffix:
            brand_map.setdefault(extracted.domain.lower(), trusted_site.lower())

    return brand_map


def _brand_impersonation_details(registrable_domain):
    extracted = tldextract.extract(registrable_domain or "")
    domain_label = extracted.domain.lower()
    if not domain_label:
        return None

    tokens = [token for token in TOKEN_SPLIT_PATTERN.split(domain_label) if token]
    if not tokens:
        tokens = [domain_label]

    brand_map = _trusted_brand_map()

    best_match = None
    best_distance = 99

    for brand_label, trusted_site in brand_map.items():
        if len(brand_label) < 4:
            continue

        for token in tokens:
            if len(token) < 4:
                continue

            distance = _token_distance(token, brand_label)
            allowed_distance = 1 if len(brand_label) < 8 else 2

            if token == brand_label:
                modifiers = [item for item in tokens if item != brand_label]
                risky_modifiers = sorted(set(modifiers) & RISKY_BRAND_MODIFIERS)
                if risky_modifiers:
                    return {
                        "closest_trusted": trusted_site,
                        "distance": 0,
                        "reason": (
                            "Domain reuses a trusted brand name with risky modifiers: "
                            + ", ".join(risky_modifiers[:3])
                            + "."
                        ),
                    }
                continue

            if distance <= allowed_distance and distance < best_distance:
                best_distance = distance
                best_match = {
                    "closest_trusted": trusted_site,
                    "distance": distance,
                    "reason": (
                        f'Domain looks similar to trusted site "{trusted_site}" '
                        f"(distance {distance})."
                    ),
                }

    return best_match


def analyze_url(url, sender_domain=None):
    """
    Return a richer URL assessment with statuses:
    - trusted: known good domain
    - aligned: valid link that matches the sender domain
    - normal: valid link that looks structurally normal
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
            "closest_trusted": registrable_domain,
            "lookalike_distance": 0,
        }

    suspicion_reason = _strong_suspicion_reason(hostname, registrable_domain)
    if suspicion_reason:
        return {
            "status": "suspicious",
            "domain": registrable_domain,
            "reason": suspicion_reason,
            "is_trusted": False,
            "is_suspicious": True,
            "closest_trusted": "",
            "lookalike_distance": None,
        }

    normalized_sender_domain = normalize_registrable_domain(sender_domain) if sender_domain else ""
    if normalized_sender_domain and registrable_domain == normalized_sender_domain:
        brand_impersonation = _brand_impersonation_details(registrable_domain)
        if not brand_impersonation:
            return {
                "status": "aligned",
                "domain": registrable_domain,
                "reason": "Domain matches the sender domain.",
                "is_trusted": False,
                "is_suspicious": False,
                "closest_trusted": "",
                "lookalike_distance": None,
            }

    brand_impersonation = _brand_impersonation_details(registrable_domain)
    if brand_impersonation:
        return {
            "status": "suspicious",
            "domain": registrable_domain,
            "reason": brand_impersonation["reason"],
            "is_trusted": False,
            "is_suspicious": True,
            "closest_trusted": brand_impersonation["closest_trusted"],
            "lookalike_distance": brand_impersonation["distance"],
        }

    return {
        "status": "normal",
        "domain": registrable_domain,
        "reason": "Domain is valid and looks structurally normal.",
        "is_trusted": False,
        "is_suspicious": False,
        "closest_trusted": "",
        "lookalike_distance": None,
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
