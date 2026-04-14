import re
import sys, os

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from keyword_detection import (
    extract_keywords,
    find_keywords,
    keyword_score,
    suspicious_keywords,
)


@pytest.fixture(autouse=True)
def reset_keywords():
    suspicious_keywords.clear()
    yield
    suspicious_keywords.clear()


def test_extract_keywords_basic():
    keywords = extract_keywords("Verify your account information urgently.")

    assert isinstance(keywords, list)
    assert "account" not in keywords
    assert "verify" not in keywords
    assert "urgently" not in keywords


def test_extract_keywords_removes_common_words():
    keywords = extract_keywords("Hello customer support, please check the account status.")

    assert "account" not in keywords
    assert "support" not in keywords
    assert "status" not in keywords


def test_keyword_score_with_phishing_content():
    score = keyword_score(
        "URGENT: Verify your account now",
        "Please verify your account immediately",
    )

    assert isinstance(score, (float, int))
    assert 50 <= score <= 100
    assert {"urgent", "verify"} <= set(find_keywords())


def test_keyword_score_with_safe_content():
    score = keyword_score(
        "Meeting agenda",
        "Let's discuss project updates tomorrow.",
    )

    assert score < 20


def test_find_keywords_after_score():
    _ = keyword_score("Password Reset Required", "Reset now")
    keywords = find_keywords()

    assert isinstance(keywords, list)
    assert "password" in keywords or "reset" in keywords


def test_keyword_score_high_for_explicit_adult_spam():
    score = keyword_score(
        "Tonight we're going to do something I've wanted to do for a long time.",
        (
            "FIRST FREE ADULT CHAT\n"
            "Private Chat\n"
            "Exclusive Photos\n"
            "Special Moments\n"
            "ACCEPT\n"
            "I AM 18+"
        ),
    )

    assert score >= 50
    assert {"adult", "chat", "private", "exclusive", "photos"} <= set(find_keywords())


def test_highlight_keywords():
    from keyword_detection import highlight_keywords

    _ = keyword_score(
        "Reset your password",
        "Click here to reset your password immediately",
    )
    highlighted = highlight_keywords("reset your password")

    assert re.search(r"<span .*?>password</span>", highlighted, re.IGNORECASE)
