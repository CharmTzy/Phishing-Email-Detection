import pytest
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from unittest import mock
from domain_detection import check_domain_in_csv

# Sample CSV content
CSV_CONTENT = """domain,legitimacy_score,total_occurrences,in_spam,in_ham,sources,category
example.com,95,10,2,8,from,legitimate
lowocc.com,85,3,1,2,urls,uncertain
"""

def test_check_existing_domain(monkeypatch):
    """Check a domain that exists with high legitimacy."""
    m = mock.mock_open(read_data=CSV_CONTENT)
    monkeypatch.setattr("builtins.open", m)
    monkeypatch.setattr("os.path.isfile", lambda path: True)

    result = check_domain_in_csv("user@example.com")
    assert result["domain"] == "example.com"
    assert result["category"] == "legitimate"

def test_check_low_occurrence_domain(monkeypatch):
    """Check a domain that exists but has low occurrence and moderate legitimacy."""
    m = mock.mock_open(read_data=CSV_CONTENT)
    monkeypatch.setattr("builtins.open", m)
    monkeypatch.setattr("os.path.isfile", lambda path: True)

    result = check_domain_in_csv("someone@lowocc.com")
    assert result["domain"] == "lowocc.com"
    assert result["category"] == "suspicious"  # reclassified due to low occurrence & score < 90

def test_check_non_existing_domain(monkeypatch):
    """Check a domain that does not exist in CSV."""
    m = mock.mock_open(read_data=CSV_CONTENT)
    monkeypatch.setattr("builtins.open", m)
    monkeypatch.setattr("os.path.isfile", lambda path: True)

    result = check_domain_in_csv("user@unknown.com")
    assert result["domain"] == "unknown.com"
    assert result["category"] == "unknown"
    assert result["total_occurrences"] == 0

def test_invalid_email(monkeypatch):
    """Check behavior when an invalid email is passed."""
    m = mock.mock_open(read_data=CSV_CONTENT)
    monkeypatch.setattr("builtins.open", m)
    monkeypatch.setattr("os.path.isfile", lambda path: True)

    result = check_domain_in_csv("not-an-email")
    assert result["domain"] == "Not Found"
    assert result["category"] == "Not Found"

def test_missing_csv_file(monkeypatch):
    """Check behavior when CSV file is missing."""
    monkeypatch.setattr("os.path.isfile", lambda path: False)

    result = check_domain_in_csv("user@example.com")
    assert result["domain"] == "example.com"
    assert result["category"] == "unknown"
