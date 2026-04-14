import pytest
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from server import app

# Use Flask's test client fixture
@pytest.fixture
def client():
    app.testing = True
    with app.test_client() as client:
        yield client


def test_analyse_email_valid_input(client):
    """
    Test /analyse_email with a valid sample email.
    """
    sample_email = {
        "sender_email": "alerts@paypal.com",
        "subject": "Important: Verify your PayPal account",
        "body": "Click here https://secure-paypal-login.com to verify.",
        "url": "https://secure-paypal-login.com"
    }

    response = client.post("/analyse_email", json=sample_email)
    data = response.get_json()

    assert response.status_code == 200
    assert "final_label" in data
    assert "overall_score" in data
    assert isinstance(data["spam_votes"], int)
    assert "keyword_score" in data
    assert "model_score" in data
    assert "model_probability" in data
    assert "reasons" in data
    assert "urls" in data
    assert isinstance(data["urlCheck"], list)
    assert isinstance(data["editCheck"], list)


def test_analyse_email_missing_fields(client):
    """
    Test with missing fields (graceful handling of None or missing keys).
    """
    response = client.post("/analyse_email", json={"body": "Hello world"})
    data = response.get_json()

    assert response.status_code == 200
    assert "final_label" in data
    assert data["final_label"] in ["Safe", "Spam", "Error"]
    assert "model_prediction" in data


def test_analyse_email_empty_body(client):
    """
    Test with empty email input (edge case).
    """
    response = client.post("/analyse_email", json={})
    data = response.get_json()

    assert response.status_code == 200
    assert "final_label" in data
    assert "overall_score" in data
    assert "model_probability" in data


def test_analyse_email_invalid_json(client):
    """
    Test sending invalid (non-JSON) data.
    Flask should handle it gracefully.
    """
    response = client.post("/analyse_email", data="not a json")
    data = response.get_json()

    assert response.status_code == 200  # still returns JSON with error fallback
    assert "error" in data
    assert data["final_label"] == "Error"
    assert data["overall_score"] == 0
    assert data["model_prediction"] == "Error"


def test_analyse_email_phishing_url(client):
    """
    Test detection of phishing-looking URLs with edit distance similarity.
    """
    email = {
        "sender_email": "noreply@secure-gooogle.com",
        "subject": "Update your Google account immediately",
        "body": "Your account may be at risk. Please click https://gooogle-security-check.com",
        "url": "https://gooogle-security-check.com"
    }
    response = client.post("/analyse_email", json=email)
    data = response.get_json()

    assert response.status_code == 200
    assert "final_label" in data
    assert data["final_label"] in ["Spam", "Safe"]
    assert "checks_breakdown" in data
    assert isinstance(data["editCheck"], list)
    assert data["urlStatus"] == ["suspicious"]
    assert data["check_flags"]["url_safety"] is True
    assert data["check_flags"]["lookalike_domains"] is True
    assert data["spam_votes"] >= 3


def test_analyse_email_company_url_matches_sender(client):
    email = {
        "sender_email": "office@company-example.com",
        "subject": "Project meeting moved to Friday",
        "body": (
            "Hi team, the weekly project sync has moved to Friday at 3:00 pm. "
            "Please review the agenda at https://company-example.com/meetings/q2-planning."
        ),
        "url": "https://company-example.com/meetings/q2-planning",
    }

    response = client.post("/analyse_email", json=email)
    data = response.get_json()

    assert response.status_code == 200
    assert data["final_label"] == "Safe"
    assert data["urlStatus"] == ["aligned"]
    assert data["spam_votes"] == 0


def test_analyse_email_explicit_adult_spam_is_flagged(client):
    email = {
        "sender_email": "nxfkopyp@scenmatgigegalital.ru",
        "subject": "Tonight we're going to do something I've wanted to do for a long time. It's gonna be so much fun!",
        "body": (
            "FIRST FREE ADULT CHAT\n\n"
            "What would you like to experience with me?\n\n"
            "Date\nPrivate Chat\nExclusive Photos\nSpecial Moments\n\n"
            "ACCEPT\n\nI AM 18+"
        ),
        "url": "",
    }

    response = client.post("/analyse_email", json=email)
    data = response.get_json()

    assert response.status_code == 200
    assert data["final_label"] == "Spam"
    assert data["model_prediction"] == "Spam"
    assert data["keyword_label"] == "Spam"
    assert data["keyword_score"] >= 50
    assert data["check_flags"]["trained_model"] is True
    assert data["check_flags"]["keyword_scan"] is True
    assert data["check_flags"]["url_safety"] is False
    assert data["check_flags"]["lookalike_domains"] is False
