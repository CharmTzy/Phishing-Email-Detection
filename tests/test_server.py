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


def test_analyse_email_empty_body(client):
    """
    Test with empty email input (edge case).
    """
    response = client.post("/analyse_email", json={})
    data = response.get_json()

    assert response.status_code == 200
    assert "final_label" in data
    assert "overall_score" in data


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
    assert isinstance(data["editCheck"], list)
