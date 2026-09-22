"""
test_module1.py - Comprehensive Unit & Integration Tests for Module 1.
Tests Deterministic Scoring, Heuristic Fallback, Input Validation, Security Headers, and API Endpoints.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from Pw_app import create_app
from Pw_services.Pw_analyzer import (
    calculate_threat_score,
    analyze_with_heuristic_rules,
    inspect_offer_text,
    analyze_with_gemini_api,
    SIGNAL_WEIGHTS
)

@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    with app.test_client() as client:
        yield client


# ==========================================
# 1. Deterministic Scoring Unit Tests
# ==========================================

def test_deterministic_weights():
    assert SIGNAL_WEIGHTS["upfront_fee"] == 30
    assert SIGNAL_WEIGHTS["deposit"] == 25
    assert SIGNAL_WEIGHTS["urgency"] == 15
    assert SIGNAL_WEIGHTS["suspicious_channel"] == 10
    assert SIGNAL_WEIGHTS["sensitive_info"] == 10
    assert SIGNAL_WEIGHTS["other"] == 10


def test_calculate_threat_score_levels():
    # Empty flags -> 0 score -> LOW
    res = calculate_threat_score([])
    assert res["threat_score"] == 0
    assert res["risk_level"] == "LOW"

    # Only urgency (+15) -> 15 -> LOW
    res = calculate_threat_score([{"type": "urgency"}])
    assert res["threat_score"] == 15
    assert res["risk_level"] == "LOW"

    # Upfront fee (+30) -> 30 -> MEDIUM
    res = calculate_threat_score([{"type": "upfront_fee"}])
    assert res["threat_score"] == 30
    assert res["risk_level"] == "MEDIUM"

    # Upfront fee (+30) + Deposit (+25) + Urgency (+15) -> 70 -> HIGH
    res = calculate_threat_score([
        {"type": "upfront_fee"},
        {"type": "deposit"},
        {"type": "urgency"}
    ])
    assert res["threat_score"] == 70
    assert res["risk_level"] == "HIGH"

    # All major flags -> > 75 -> CRITICAL
    res = calculate_threat_score([
        {"type": "upfront_fee"},
        {"type": "deposit"},
        {"type": "urgency"},
        {"type": "suspicious_channel"},
        {"type": "sensitive_info"}
    ])
    assert res["threat_score"] == 90
    assert res["risk_level"] == "CRITICAL"


def test_score_clamping():
    # Massive number of flags shouldn't exceed 100
    huge_flags = [{"type": "upfront_fee"}] * 10 + [{"type": "deposit"}] * 10
    res = calculate_threat_score(huge_flags)
    assert res["threat_score"] <= 100
    assert res["risk_level"] == "CRITICAL"


# ==========================================
# 2. Heuristic Analysis Unit Tests
# ==========================================

def test_heuristic_detects_scam_signals():
    scam_text = (
        "Congratulations! You are selected as Senior Cloud Architect. "
        "Pay courier fee of INR 4,999 for your company laptop. "
        "Also a refundable deposit of 5,000 is required. "
        "Offer expires today within 24 hours. Contact recruiter on Telegram @scam_agent."
    )
    result = analyze_with_heuristic_rules(scam_text)
    assert result["threat_score"] >= 70
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert len(result["flags"]) >= 3

    flag_types = [f["type"] for f in result["flags"]]
    assert "upfront_fee" in flag_types
    assert "deposit" in flag_types
    assert "urgency" in flag_types
    assert "suspicious_channel" in flag_types


def test_heuristic_clean_text():
    clean_text = (
        "Dear Candidate, Thank you for interviewing with Google. "
        "We are pleased to extend this formal offer of employment for the Software Engineer position. "
        "Please review the attached contract and let your recruiter know if you have any questions."
    )
    result = analyze_with_heuristic_rules(clean_text)
    assert result["threat_score"] <= 25
    assert result["risk_level"] == "LOW"
    assert len(result["flags"]) == 0


# ==========================================
# 3. Gemini API Mocking Unit Test
# ==========================================

@patch("requests.post")
def test_gemini_api_parsing(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_gemini_json = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "flags": [
                                    {
                                        "title": "Equipment Fee Demand",
                                        "severity": "high",
                                        "type": "upfront_fee",
                                        "evidence": "Deposit $200 for dispatch of MacBook",
                                        "explanation": "Legitimate jobs don't demand equipment fees."
                                    },
                                    {
                                        "title": "Extreme Urgency",
                                        "severity": "medium",
                                        "type": "urgency",
                                        "evidence": "Respond in 2 hours",
                                        "explanation": "High pressure tactic."
                                    }
                                ],
                                "summary": "Multiple scam indicators found.",
                                "recommended_action": "Do not pay any money."
                            })
                        }
                    ]
                }
            }
        ]
    }
    mock_response.json.return_value = mock_gemini_json
    mock_post.return_value = mock_response

    res = analyze_with_gemini_api("Some text", api_key="fake_key")
    assert res is not None
    assert res["threat_score"] == 45  # 30 + 15
    assert res["risk_level"] == "MEDIUM"
    assert len(res["flags"]) == 2
    assert "gemini_ai_engine" in res["engine"]


# ==========================================
# 4. Flask API Endpoint Integration Tests
# ==========================================

def test_health_check(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert "gemini_configured" in data
    assert "timestamp" in data


def test_security_headers(client):
    response = client.get("/api/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"


def test_analyze_non_json(client):
    response = client.post("/api/analyze", data="plain text", content_type="text/plain")
    assert response.status_code == 400
    data = response.get_json()
    assert data["status"] == "error"
    assert data["code"] == "UNSUPPORTED_MEDIA_TYPE"


def test_analyze_empty_content(client):
    response = client.post("/api/analyze", json={"mode": "text", "content": "   "})
    assert response.status_code == 400
    data = response.get_json()
    assert data["code"] == "EMPTY_CONTENT"


def test_analyze_invalid_mode(client):
    response = client.post("/api/analyze", json={"mode": "ftp", "content": "Some text"})
    assert response.status_code == 400
    data = response.get_json()
    assert data["code"] == "INVALID_MODE"


def test_analyze_oversized_content(client):
    giant_text = "A" * 30005
    response = client.post("/api/analyze", json={"mode": "text", "content": giant_text})
    assert response.status_code == 400
    data = response.get_json()
    assert data["code"] == "CONTENT_TOO_LONG"


def test_analyze_success_flow(client):
    payload = {
        "mode": "text",
        "content": "Selected for Data Entry. Send security deposit of INR 3000 immediately within 24 hours."
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    result = data["data"]
    assert "threat_score" in result
    assert result["threat_score"] > 0
    assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(result["flags"], list)
    assert len(result["flags"]) > 0
    assert "scanned_at" in result
    assert result["scan_type"] == "text"
