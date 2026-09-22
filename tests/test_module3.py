"""
test_module3.py - Automated Unit & Integration Tests for Module 3: Bento UI Frontend.
Tests HTML template rendering, static asset routing, and responsive markup structure.
"""

import pytest
from Pw_app import create_app

@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    with app.test_client() as client:
        yield client


def test_index_route_serves_html(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    html = response.get_data(as_text=True)

    # Verify critical branding and core elements
    assert "TrueOffer" in html
    assert "Fake Offers" in html
    assert "End Here." in html
    assert "Analyze Text" in html
    assert "Analyze URL" in html
    assert "Analyze for Scam" in html
    assert "Try a Sample Job Offer" in html
    assert "Analysis Result" in html
    assert "Scam Threat Index" in html


def test_static_css_served(client):
    response = client.get("/Pw_static/Pw_css/Pw_style.css")
    assert response.status_code == 200
    css = response.get_data(as_text=True)
    assert "--color-navy: #092634" in css
    assert "--color-blue: #004E72" in css
    assert "--color-orange: #FF6E42" in css
    assert "--color-white: #F9F9F9" in css
    assert ".donut-meter" in css


def test_static_js_served(client):
    response = client.get("/Pw_static/Pw_js/Pw_app.js")
    assert response.status_code == 200
    js = response.get_data(as_text=True)
    assert "DOMContentLoaded" in js
    assert "triggerAnalysis" in js
    assert "renderAnalysisResults" in js
    assert "animateDonutScore" in js
