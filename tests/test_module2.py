"""
test_module2.py - Comprehensive Unit & Integration Tests for Module 2: Domain Intelligence.
Tests SSRF Protection, Domain Extraction, Age Calculation, Risk Penalty Integration,
Graceful Degradation, and API Integration in URL mode.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from Pw_app import create_app
from Pw_services.Pw_domain_intel import (
    is_ssrf_safe,
    extract_domain,
    get_domain_age_days,
    analyze_domain,
    _build_domain_report
)

@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    with app.test_client() as client:
        yield client


# ==========================================
# 1. SSRF Protection Tests (Security)
# ==========================================

def test_ssrf_blocks_loopback():
    safe, msg = is_ssrf_safe("http://127.0.0.1:5000/api")
    assert not safe
    assert "restricted" in msg.lower()

    safe, msg = is_ssrf_safe("http://localhost:3000")
    assert not safe

    safe, msg = is_ssrf_safe("http://0.0.0.0/")
    assert not safe


def test_ssrf_blocks_private_networks():
    safe, msg = is_ssrf_safe("http://192.168.1.1/admin")
    assert not safe

    safe, msg = is_ssrf_safe("https://10.0.0.5/confidential")
    assert not safe

    safe, msg = is_ssrf_safe("http://172.16.0.10:8080")
    assert not safe


def test_ssrf_blocks_cloud_metadata():
    safe, msg = is_ssrf_safe("http://169.254.169.254/latest/meta-data/")
    assert not safe
    assert "metadata" in msg.lower()


def test_ssrf_blocks_illegal_schemes():
    safe, msg = is_ssrf_safe("file:///etc/passwd")
    assert not safe

    safe, msg = is_ssrf_safe("ftp://files.example.com")
    assert not safe


def test_ssrf_allows_legitimate_domains():
    safe, _ = is_ssrf_safe("https://www.google.com")
    assert safe

    safe, _ = is_ssrf_safe("http://careers-amazon-security.xyz/apply?ref=123")
    assert safe


# ==========================================
# 2. Domain Extraction Tests (Efficiency)
# ==========================================

def test_extract_domain():
    assert extract_domain("https://google.com") == "google.com"
    assert extract_domain("http://www.google.com/search?q=test") == "google.com"
    assert extract_domain("sub.careers.amazon.co.uk:8080/jobs") == "sub.careers.amazon.co.uk"
    assert extract_domain("careers-amazon-security.xyz") == "careers-amazon-security.xyz"
    assert extract_domain("") is None
    assert extract_domain("not-a-domain") is None


# ==========================================
# 3. Domain Age & Risk Calculation Tests
# ==========================================

def test_get_domain_age_days():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ten_days_ago = now - timedelta(days=10)
    assert get_domain_age_days(ten_days_ago) == 10

    # List of datetimes (common in whois)
    assert get_domain_age_days([ten_days_ago, now]) == 10

    assert get_domain_age_days(None) is None
    assert get_domain_age_days("invalid") is None


def test_demo_preset_resolution():
    res = analyze_domain("https://careers-amazon-security.xyz/login")
    assert res["status"] == "success"
    assert res["domain"] == "careers-amazon-security.xyz"
    assert res["age_days"] == 12
    assert res["is_new_domain"] is True
    assert res["risk_penalty"] >= 25
    assert len(res["flags"]) > 0

    flag_types = [f["type"] for f in res["flags"]]
    assert "domain_new" in flag_types


def test_brand_impersonation_and_suspicious_tld():
    res = _build_domain_report(
        domain="google-verify-career.xyz",
        age_days=15,
        creation_date_str="2026-09-07",
        registrar="Test Registrar",
        status="success"
    )
    assert res["is_new_domain"] is True
    flag_titles = [f["title"] for f in res["flags"]]
    # Should flag new domain, brand impersonation, and suspicious TLD
    assert any("Newly Registered Domain" in t for t in flag_titles)
    assert any("Brand Impersonation" in t for t in flag_titles)
    assert any("Suspicious / High-Abuse Top-Level Domain" in t for t in flag_titles)


# ==========================================
# 4. Graceful Degradation Tests (Robustness)
# ==========================================

@patch("Pw_services.Pw_domain_intel._query_whois_raw")
def test_whois_query_failure_graceful_degradation(mock_whois):
    # Simulate network failure or timeout
    mock_whois.side_effect = Exception("WHOIS server unreachable")
    res = analyze_domain("https://unknown-domain-test-12345.com")
    assert res["status"] == "lookup_failed"
    assert res["age_days"] is None
    assert res["domain"] == "unknown-domain-test-12345.com"
    # Must not raise exception


# ==========================================
# 5. API Endpoint URL Mode Integration Tests
# ==========================================

def test_api_analyze_url_ssrf_rejection(client):
    payload = {"mode": "url", "content": "http://127.0.0.1:8000/secret"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 400
    data = response.get_json()
    assert data["code"] == "SECURITY_RESTRICTION"


def test_api_analyze_url_preset_success(client):
    payload = {"mode": "url", "content": "https://verify-google-careers.top/apply"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"

    result = data["data"]
    assert result["scan_type"] == "url"
    assert result["threat_score"] >= 25
    assert result["domain_intelligence"] is not None
    assert result["domain_intelligence"]["domain"] == "verify-google-careers.top"
    assert result["domain_intelligence"]["age_days"] == 8
    assert result["domain_intelligence"]["is_new_domain"] is True


def test_api_analyze_url_graceful_on_unknown(client):
    # When an unknown domain fails whois, it still returns HTTP 200 with domain_intelligence
    with patch("Pw_services.Pw_domain_intel._query_whois_raw", side_effect=Exception("Timeout")):
        payload = {"mode": "url", "content": "https://example-fallback-test.org/path"}
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "success"
        assert data["data"]["domain_intelligence"]["status"] == "lookup_failed"
