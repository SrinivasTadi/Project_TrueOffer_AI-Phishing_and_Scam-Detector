"""
Pw_analyzer.py - Core AI Signal Extraction and Deterministic Scam Scoring Engine.
Part of the Fake Offer Letter & Phishing Inspector (PromptWars).

Features:
- Google Gemini API integration (Google AI Studio REST API).
- Heuristic fallback pattern matcher for offline/testing/graceful degradation.
- Deterministic Threat Scoring model based on PRD weights.
- Strict structured JSON response parsing.
"""

import os
import re
import json
import logging
from typing import Dict, Any, List, Optional
import requests

logger = logging.getLogger(__name__)

# Deterministic signal weights according to PRD specifications
SIGNAL_WEIGHTS = {
    "upfront_fee": 30,         # Upfront payment / equipment fee (e.g. laptop courier fee)
    "deposit": 25,             # Refundable security deposit demand
    "domain_new": 25,          # Newly registered domain (< 30 days old)
    "urgency": 15,             # Strong urgency / pressure language (e.g. 2 hours to accept)
    "suspicious_channel": 10,  # Suspicious communication (Telegram/WhatsApp only, free mail)
    "sensitive_info": 10,      # Sensitive information request (bank/KYC/credentials)
    "domain_young": 10,        # Young domain (30-90 days old)
    "other": 10                # Other validated red flags (unrealistic salary, no interview)
}

DEFAULT_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")


def calculate_threat_score(flags: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Deterministically computes Scam Threat Index (0-100%) and risk category
    from structured red flags.

    Formula:
    Sum of weights of detected signals, clamped to [0, 100].
    """
    total_score = 0
    accounted_types = set()

    for flag in flags:
        flag_type = flag.get("type", "other").lower()
        weight = SIGNAL_WEIGHTS.get(flag_type, SIGNAL_WEIGHTS["other"])
        
        # Apply primary weight for each unique category, or partial weight if recurring
        if flag_type not in accounted_types:
            total_score += weight
            accounted_types.add(flag_type)
        else:
            total_score += min(5, weight // 3)

    score = max(0, min(100, total_score))

    if score <= 25:
        risk_level = "LOW"
    elif score <= 50:
        risk_level = "MEDIUM"
    elif score <= 75:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "threat_score": score,
        "risk_level": risk_level
    }


def analyze_with_heuristic_rules(text: str) -> Dict[str, Any]:
    """
    Deterministic rule-based heuristic analyzer.
    Used for instant local testing, offline fallback, or when GEMINI_API_KEY is not configured.
    """
    flags: List[Dict[str, Any]] = []

    # 1. Upfront Payment / Equipment Fee (+30)
    fee_match = re.search(
        r"(?:courier fee|equipment charge|laptop charge|pay\s+(?:₹|\$|inr|usd)?\s*\d+|processing fee|training fee|software license fee)",
        text,
        re.IGNORECASE
    )
    if fee_match:
        flags.append({
            "title": "Upfront Equipment / Processing Fee Demanded",
            "severity": "critical",
            "type": "upfront_fee",
            "evidence": fee_match.group(0),
            "explanation": "Legitimate employers provide equipment and training at company expense without requiring upfront fees."
        })

    # 2. Refundable Security Deposit (+25)
    deposit_match = re.search(
        r"(?:security deposit|refundable deposit|caution deposit|commitment deposit|deposit\s+of)",
        text,
        re.IGNORECASE
    )
    if deposit_match:
        flags.append({
            "title": "Refundable Security Deposit Demand",
            "severity": "critical",
            "type": "deposit",
            "evidence": deposit_match.group(0),
            "explanation": "Demanding a 'refundable deposit' to secure an offer is a signature recruitment phishing tactic."
        })

    # 3. High Urgency / Pressure Language (+15)
    urgency_match = re.search(
        r"(?:within\s+(?:\d+\s+hours?|24\s+hours?|immediate(?:ly)?)|offer\s+expires\s+today|urgent\s+requirement|last\s+day\s+to\s+confirm)",
        text,
        re.IGNORECASE
    )
    if urgency_match:
        flags.append({
            "title": "Artificial Urgency & Pressure Tactics",
            "severity": "high",
            "type": "urgency",
            "evidence": urgency_match.group(0),
            "explanation": "Scammers enforce tight deadlines to induce panic and prevent candidates from verifying details."
        })

    # 4. Suspicious Communication Channel (+10)
    channel_match = re.search(
        r"(?:telegram\s*(?:handle|channel|group|@)|whatsapp\s*(?:only|number|\+?\d+)|free\s*email|@gmail\.com|@yahoo\.com|@outlook\.com)",
        text,
        re.IGNORECASE
    )
    if channel_match:
        flags.append({
            "title": "Informal / Suspicious Communication Channel",
            "severity": "medium",
            "type": "suspicious_channel",
            "evidence": channel_match.group(0),
            "explanation": "Official corporate recruitment is conducted via authenticated corporate domains, not anonymous messaging platforms."
        })

    # 5. Sensitive Information Request (+10)
    info_match = re.search(
        r"(?:bank\s+account\s+number|credit\s+card|debit\s+card|cvv|otp|netbanking|aadhaar\s+card\s+photo|ssn|identity\s+password)",
        text,
        re.IGNORECASE
    )
    if info_match:
        flags.append({
            "title": "Early / Sensitive Financial Data Request",
            "severity": "high",
            "type": "sensitive_info",
            "evidence": info_match.group(0),
            "explanation": "Requesting banking credentials, OTPs, or financial secrets prior to genuine onboarding indicates identity/funds theft."
        })

    # 6. Generic other red flags
    if not flags:
        summary = "No obvious high-risk scam indicators detected in the text analysis."
        recommended_action = "The text appears low-risk based on standard indicators, but always confirm recruiter identity via official company portals."
    else:
        summary = f"Detected {len(flags)} distinct security indicator(s) strongly associated with recruitment phishing."
        recommended_action = "Do not send any funds, purchase equipment, or disclose confidential financial details. Independently cross-verify through verified corporate contacts."

    scoring = calculate_threat_score(flags)

    return {
        "threat_score": scoring["threat_score"],
        "risk_level": scoring["risk_level"],
        "flags": flags,
        "summary": summary,
        "recommended_action": recommended_action,
        "engine": "heuristic_rule_engine"
    }


def analyze_with_gemini_api(text: str, api_key: str, model_name: str = DEFAULT_GEMINI_MODEL) -> Optional[Dict[str, Any]]:
    """
    Direct REST API invocation to Google Gemini API (Google AI Studio).
    Enforces structured JSON extraction of red flags, severity, and evidence quotes.
    """
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"

    system_instruction = (
        "You are an expert Cybersecurity & Phishing Inspector specializing in identifying fake job offer letters, "
        "recruitment scams, pay-for-equipment phishing, and deposit traps. "
        "Analyze the provided text objectively. Extract suspicious signals, categorize their type, evaluate severity, "
        "and quote exact evidence from the text.\n\n"
        "Allowed types for flags:\n"
        "- upfront_fee: Any payment, courier, training, or equipment fee demanded before/during joining.\n"
        "- deposit: Refundable security deposit or caution money.\n"
        "- urgency: Artificial pressure, 1-2 hour deadlines, immediate confirmation demands.\n"
        "- suspicious_channel: Telegram, WhatsApp-only interviews, personal Gmail/Yahoo accounts representing big companies.\n"
        "- sensitive_info: Premature requests for bank accounts, cards, OTPs, or passwords.\n"
        "- other: Excessive compensation, missing interview stages, generic non-standard phrasing.\n\n"
        "Return ONLY a valid JSON object matching this schema:\n"
        "{\n"
        '  "flags": [\n'
        '    {\n'
        '      "title": "Short descriptive title",\n'
        '      "severity": "low"|"medium"|"high"|"critical",\n'
        '      "type": "upfront_fee"|"deposit"|"urgency"|"suspicious_channel"|"sensitive_info"|"other",\n'
        '      "evidence": "Verbatim quote from the input text",\n'
        '      "explanation": "Concise 1-2 sentence rationale explaining why this is suspicious"\n'
        "    }\n"
        "  ],\n"
        '  "summary": "Short 2-3 sentence overview of findings.",\n'
        '  "recommended_action": "Clear, practical next steps for the user."\n'
        "}"
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": f"Analyze this job offer/communication:\n\n---\n{text[:10000]}\n---"}
                ]
            }
        ],
        "systemInstruction": {
            "parts": [{"text": system_instruction}]
        },
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1
        }
    }

    models_to_try = [model_name]
    for fallback_m in ["gemini-3.5-flash-lite", "gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]:
        if fallback_m not in models_to_try:
            models_to_try.append(fallback_m)

    headers = {"Content-Type": "application/json"}

    for candidate_model in models_to_try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{candidate_model}:generateContent?key={api_key}"
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=8)
            if response.status_code != 200:
                logger.warning(f"Gemini API model {candidate_model} returned {response.status_code}: {response.text}")
                continue

            result = response.json()
            candidates = result.get("candidates", [])
            if not candidates:
                continue

            content_parts = candidates[0].get("content", {}).get("parts", [])
            if not content_parts:
                continue

            raw_text = content_parts[0].get("text", "").strip()
            parsed_json = json.loads(raw_text)

            flags = parsed_json.get("flags", [])
            scoring = calculate_threat_score(flags)

            return {
                "threat_score": scoring["threat_score"],
                "risk_level": scoring["risk_level"],
                "flags": flags,
                "summary": parsed_json.get("summary", "Analysis completed."),
                "recommended_action": parsed_json.get("recommended_action", "Verify through official corporate channels."),
                "engine": f"gemini_ai_engine ({candidate_model})"
            }

        except Exception as e:
            logger.error(f"Error calling Gemini API on {candidate_model}: {e}", exc_info=False)
            continue

    return None


def inspect_offer_text(text: str) -> Dict[str, Any]:
    """
    Main entrypoint for text analysis.
    Checks for GEMINI_API_KEY. If available, queries Gemini with structured response;
    otherwise falls back gracefully to the heuristic rule engine.
    """
    cleaned_text = text.strip()
    if not cleaned_text:
        return {
            "threat_score": 0,
            "risk_level": "LOW",
            "flags": [],
            "summary": "No text provided for analysis.",
            "recommended_action": "Please supply job offer text or recruitment correspondence to inspect.",
            "engine": "none"
        }

    api_key = os.environ.get("GEMINI_API_KEY", "").strip()

    if api_key:
        ai_result = analyze_with_gemini_api(cleaned_text, api_key)
        if ai_result:
            return ai_result

    # Fallback to deterministic heuristic engine
    return analyze_with_heuristic_rules(cleaned_text)
