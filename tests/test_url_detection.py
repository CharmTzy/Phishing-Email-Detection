import pytest
from urllib.parse import urlparse
import url_detection

# Mock trusted sites and safe URLs
MOCK_TRUSTED = {"paypal.com", "google.com"}
MOCK_SAFE = {"safe.example.com", "trusted.site.com"}

@pytest.fixture(autouse=True)
def patch_trusted_and_safe(monkeypatch):
    """Automatically patch TRUSTED_SITES and SAFE_URLS for all tests."""
    monkeypatch.setattr(url_detection, "TRUSTED_SITES", MOCK_TRUSTED)
    monkeypatch.setattr(url_detection, "SAFE_URLS", MOCK_SAFE)

def test_extract_urls_basic():
    email_text = "Visit https://paypal.com or http://google.com for info."
    domains = url_detection.extract_urls(email_text)
    assert "paypal.com" in domains
    assert "google.com" in domains

def test_extract_urls_with_www():
    email_text = "Check www.facebook.com and www.twitter.com now."
    domains = url_detection.extract_urls(email_text)
    assert "facebook.com" in domains
    assert "twitter.com" in domains

def test_extract_urls_no_urls():
    email_text = "Hello, this text has no links."
    domains = url_detection.extract_urls(email_text)
    assert domains is None

def test_extract_urls_invalid_input():
    assert url_detection.extract_urls(None) is None
    assert url_detection.extract_urls(12345) is None

def test_urlvalidator_trusted_sites():
    assert url_detection.URLvalidator("paypal.com") is True
    assert url_detection.URLvalidator("https://google.com") is True

def test_urlvalidator_safe_urls():
    assert url_detection.URLvalidator("safe.example.com") is True
    assert url_detection.URLvalidator("trusted.site.com") is True

def test_urlvalidator_untrusted():
    assert url_detection.URLvalidator("malicious.com") is False
    assert url_detection.URLvalidator("http://unknown.site") is False

def test_urlvalidator_invalid_scheme():
    assert url_detection.URLvalidator("ftp://paypal.com") is False
    assert url_detection.URLvalidator("mailto:test@example.com") is False

def test_urlvalidator_empty_or_none():
    assert url_detection.URLvalidator("") is False
    assert url_detection.URLvalidator(None) is False

def test_is_trusted_domain():
    assert url_detection.is_trusted_domain("paypal.com") is True
    assert url_detection.is_trusted_domain("unknown.com") is False
    assert url_detection.is_trusted_domain("") is False
    assert url_detection.is_trusted_domain(None) is False

def test_is_safe_hostname():
    assert url_detection.is_safe_hostname("safe.example.com") is True
    assert url_detection.is_safe_hostname("untrusted.com") is False
    assert url_detection.is_safe_hostname("") is False
    assert url_detection.is_safe_hostname(None) is False
