import pytest
from edit_distance import editDistance

def test_exact_match():
    """Test when the site exactly matches a trusted site."""
    trusted_sites = ["paypal.com", "google.com", "example.com"]
    site = "paypal.com"
    distance, closest = editDistance(trusted_sites, site)
    assert distance == 0
    assert closest == "paypal.com"

def test_one_character_difference():
    """Test a site with one character difference."""
    trusted_sites = ["paypal.com", "google.com", "example.com"]
    site = "paypa.com"
    distance, closest = editDistance(trusted_sites, site)
    assert distance == 1
    assert closest == "paypal.com"

def test_multiple_differences():
    """Test a site with multiple differences."""
    trusted_sites = ["paypal.com", "google.com", "example.com"]
    site = "paypol.com"
    distance, closest = editDistance(trusted_sites, site)
    assert distance == 1
    assert closest == "paypal.com"

def test_no_trusted_sites():
    """Test behavior when trusted site list is empty."""
    trusted_sites = []
    site = "randomsite.com"
    distance, closest = editDistance(trusted_sites, site)
    assert distance == 99  # default max distance
    assert closest == ""
