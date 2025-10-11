import pytest
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from keyword_detection import (
    extract_keywords,
    keyword_score,
    find_keywords,
    suspicious_keywords
)

@pytest.fixture(autouse=True)
def reset_keywords():
    """
    Automatically reset the global suspicious_keywords list before each test.
    """
    suspicious_keywords.clear()
    yield
    suspicious_keywords.clear()


def test_extract_keywords_basic():
    text = "Verify your account information urgently."
    keywords = extract_keywords(text)
    # Should remove common/positive words
    assert isinstance(keywords, list)
    assert "account" not in keywords  # filtered common word
    assert "verify" not in keywords   # 'verify' likely verb → excluded
    assert "urgently" not in keywords # not a NOUN/PROPN
    # Ensure non-empty only if nouns exist
    assert all(isinstance(k, str) for k in keywords)


def test_extract_keywords_removes_common_words():
    text = "Hello customer support, please check the account status."
    keywords = extract_keywords(text)
    assert "account" not in keywords
    assert "support" not in keywords
    assert "status" in keywords  # expected noun, not filtered out


def test_keyword_score_with_spam_content(monkeypatch):
    """
    Use monkeypatch to simulate a spam dataset with minimal data.
    """
    import keyword_detection

    # Mock DataFrame to simulate spam emails
    import pandas as pd
    keyword_detection.df = pd.DataFrame({
        "label": [1],
        "subject": ["urgent verify account"],
        "body": ["please verify your account immediately or get suspended"]
    })

    subject = "URGENT: Verify your account now"
    body = "Please verify your account immediately"
    score = keyword_score(subject, body)

    assert isinstance(score, (float, int))
    assert score >= 0
    assert score <= 100

    # Since this looks spammy, expect non-empty suspicious keywords
    assert len(find_keywords()) > 0


def test_keyword_score_with_safe_content(monkeypatch):
    """
    Test that non-spammy content gives a low score.
    """
    import keyword_detection
    import pandas as pd
    keyword_detection.df = pd.DataFrame({
        "label": [1],
        "subject": ["urgent verify account"],
        "body": ["please verify your account immediately"]
    })

    subject = "Meeting agenda"
    body = "Let's discuss project updates tomorrow."
    score = keyword_score(subject, body)
    assert score < 20  # safe content → low risk
    assert len(find_keywords()) >= 0


def test_find_keywords_after_score(monkeypatch):
    """
    find_keywords should reflect updated suspicious_keywords after scoring.
    """
    import keyword_detection
    import pandas as pd
    keyword_detection.df = pd.DataFrame({
        "label": [1],
        "subject": ["password reset required"],
        "body": ["reset your password now"]
    })

    _ = keyword_score("Password Reset Required", "Reset now")
    keywords = find_keywords()
    assert isinstance(keywords, list)
    assert "password" in keywords or "reset" in keywords

def test_highlight_keywords(monkeypatch):
    """
    Check that highlight_keywords correctly wraps detected keywords in HTML.
    """
    import keyword_detection
    import pandas as pd
    import re

    # Mock dataset with a noun ("password") that will be extracted as a keyword
    keyword_detection.df = pd.DataFrame({
        "label": [1],
        "subject": ["reset your password"],
        "body": ["click here to reset your password immediately"]
    })

    # Run keyword scoring to populate suspicious_keywords
    _ = keyword_detection.keyword_score("Reset your password", "Click here to reset your password immediately")

    # Highlight keywords in text
    highlighted = keyword_detection.highlight_keywords("reset your password")

    # Should contain <span> tags for highlighting of "password"
    assert re.search(r"<span .*?>password</span>", highlighted, re.IGNORECASE)
