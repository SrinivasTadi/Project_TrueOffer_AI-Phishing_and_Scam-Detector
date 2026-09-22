"""
Pw_app.py - Main Flask Application Server for Fake Offer Letter & Phishing Inspector.
Provides REST API endpoints for scanning offers and verifying service health.
Prioritizes Efficiency, Security, Testing, and Usability.
"""

import os
from datetime import datetime, timezone
from flask import Flask, request, jsonify, make_response, render_template
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from Pw_services.Pw_analyzer import inspect_offer_text, calculate_threat_score
from Pw_services.Pw_domain_intel import analyze_domain, is_ssrf_safe

def create_app(test_config=None):
    """
    Application factory for the Phishing Inspector Flask app.
    Supports dependency injection for automated testing.
    """
    app = Flask(
        __name__,
        template_folder="PW_templates",
        static_folder="Pw_static",
        static_url_path="/Pw_static"
    )

    # Maximum payload size: 50 KB (Protects against ReDoS and memory bloat)
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024
    app.config["JSON_SORT_KEYS"] = False

    if test_config:
        app.config.update(test_config)

    # Enable CORS for frontend client interactions
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # --- Error Handlers (Security & Usability: Never leak stack traces) ---
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            "status": "error",
            "code": "BAD_REQUEST",
            "message": str(error.description) if hasattr(error, "description") else "Malformed request."
        }), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "status": "error",
            "code": "NOT_FOUND",
            "message": "The requested API endpoint does not exist."
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            "status": "error",
            "code": "METHOD_NOT_ALLOWED",
            "message": "HTTP method not permitted for this endpoint."
        }), 405

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({
            "status": "error",
            "code": "PAYLOAD_TOO_LARGE",
            "message": "Input exceeds the maximum allowed payload size of 50KB."
        }), 413

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            "status": "error",
            "code": "INTERNAL_SERVER_ERROR",
            "message": "An internal server error occurred while processing the analysis."
        }), 500

    # --- Frontend View Route ---
    @app.route("/", methods=["GET"])
    def index():
        """Serves the main single-page Bento UI."""
        return render_template("Pw_index.html")

    # --- API Endpoints ---
    @app.route("/api/health", methods=["GET"])
    def health_check():
        """
        GET /api/health
        Health check endpoint for status, monitoring, and Gemini API key readiness.
        """
        gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
        return jsonify({
            "status": "healthy",
            "service": "Fake Offer Letter & Phishing Inspector API",
            "gemini_configured": bool(gemini_key),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200

    @app.route("/api/analyze", methods=["POST"])
    def analyze_offer():
        """
        POST /api/analyze
        Primary analysis endpoint for job offer text or URLs.

        Expected JSON body:
        {
            "mode": "text" | "url",
            "content": "offer letter string or target URL"
        }
        """
        if not request.is_json:
            return jsonify({
                "status": "error",
                "code": "UNSUPPORTED_MEDIA_TYPE",
                "message": "Request body must be valid JSON with Content-Type: application/json."
            }), 400

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({
                "status": "error",
                "code": "INVALID_JSON",
                "message": "Malformed JSON payload."
            }), 400

        mode = str(data.get("mode", "text")).strip().lower()
        content = data.get("content", "")

        # Input validation
        if mode not in ("text", "url"):
            return jsonify({
                "status": "error",
                "code": "INVALID_MODE",
                "message": "Invalid scan mode. Accepted modes are 'text' or 'url'."
            }), 400

        if not isinstance(content, str) or not content.strip():
            return jsonify({
                "status": "error",
                "code": "EMPTY_CONTENT",
                "message": "Input content cannot be empty. Please provide offer text or a URL."
            }), 400

        cleaned_content = content.strip()

        # Enforce content length ceiling
        if len(cleaned_content) > 30000:
            return jsonify({
                "status": "error",
                "code": "CONTENT_TOO_LONG",
                "message": "Content exceeds maximum length of 30,000 characters."
            }), 400

        # Execute analysis
        try:
            domain_intel_data = None

            if mode == "url":
                # SSRF Protection
                safe, reason = is_ssrf_safe(cleaned_content)
                if not safe:
                    return jsonify({
                        "status": "error",
                        "code": "SECURITY_RESTRICTION",
                        "message": f"Target URL rejected by security policy: {reason}"
                    }), 400

                # Analyze Domain & WHOIS registration
                domain_intel_data = analyze_domain(cleaned_content)
                domain_flags = domain_intel_data.get("flags", [])

                # Run baseline text / structural analysis on the URL string
                text_analysis = inspect_offer_text(cleaned_content)

                # Merge flags deterministically
                merged_flags = list(domain_flags)
                for f in text_analysis.get("flags", []):
                    if not any(mf.get("evidence") == f.get("evidence") for mf in merged_flags):
                        merged_flags.append(f)

                scoring = calculate_threat_score(merged_flags)
                threat_score = scoring["threat_score"]
                risk_level = scoring["risk_level"]

                if domain_intel_data.get("is_new_domain"):
                    summary = f"High-risk URL scan: The domain '{domain_intel_data.get('domain')}' was registered only {domain_intel_data.get('age_days')} days ago."
                    action = "Do not open links, submit credentials, or make payments on newly registered domains."
                elif threat_score >= 50:
                    summary = f"URL scan flagged {len(merged_flags)} suspicious signal(s) associated with recruitment fraud or domain abuse."
                    action = "Verify the organization through their authenticated public website before proceeding."
                else:
                    summary = text_analysis.get("summary") or f"Domain '{domain_intel_data.get('domain')}' analyzed with no critical anomalies."
                    action = text_analysis.get("recommended_action") or "Proceed with normal diligence."

                engine_name = "domain_intel_engine"

            else:
                # Text Analysis Mode
                analysis = inspect_offer_text(cleaned_content)
                threat_score = analysis["threat_score"]
                risk_level = analysis["risk_level"]
                merged_flags = analysis["flags"]
                summary = analysis["summary"]
                action = analysis["recommended_action"]
                engine_name = analysis.get("engine", "heuristic_rule_engine")

            response_data = {
                "threat_score": threat_score,
                "risk_level": risk_level,
                "flags": merged_flags,
                "summary": summary,
                "recommended_action": action,
                "scan_type": mode,
                "domain_intelligence": domain_intel_data,
                "engine": engine_name,
                "scanned_at": datetime.now(timezone.utc).isoformat()
            }

            return jsonify({
                "status": "success",
                "data": response_data
            }), 200

        except Exception as e:
            app.logger.error(f"Analysis processing failure: {e}", exc_info=True)
            return jsonify({
                "status": "error",
                "code": "ANALYSIS_FAILED",
                "message": "An error occurred during threat analysis."
            }), 500

    return app

# Main entrypoint when run directly
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_ENV", "development").lower() == "development"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
