from orchestrator.state import IncidentState, MitigationOutput
from typing import Literal

RiskLevel = Literal["Low", "Medium", "High", "Critical"]

# Base severity weight per attack type — you can tune this list as your
# threat coverage grows. Keep it simple and explainable for your demo/viva.
ATTACK_TYPE_BASE_SCORE = {
    "Brute Force": 60,
    "Phishing": 40,
    "Malware": 80,
    "Ransomware": 95,
    "Port Scan": 20,
    "SQL Injection": 75,
    "DDoS": 85,
    "Unknown": 50,   # fallback for attack types we haven't mapped yet
}


def calculate_risk_score(state: IncidentState) -> int:
    """
    Combines multiple signals into a single 0-100 risk score.
    Higher score = more dangerous = more likely to need human approval.
    """
    forensics = state.get("forensics_output")
    threat_hunter = state.get("threat_hunter_output")

    if not forensics or not threat_hunter:
        # Safety default: if we don't have enough info, treat as risky
        # rather than silently under-reacting.
        return 70

    score = 0

    # 1. Base score from attack type
    attack_type = forensics.get("attack_type", "Unknown")
    score += ATTACK_TYPE_BASE_SCORE.get(attack_type, ATTACK_TYPE_BASE_SCORE["Unknown"])

    # 2. Confidence from Threat Hunter (0.0 - 1.0) scaled into points
    confidence = threat_hunter.get("confidence", 0.5)
    score += confidence * 20   # contributes up to 20 points

    # 3. Amount of evidence — more evidence, more certainty
    evidence_count = len(forensics.get("evidence", []))
    score += min(evidence_count * 3, 15)   # cap contribution at 15 points

    # 4. Repeat offender check — seen similar incidents before?
    similar_incidents = forensics.get("similar_past_incidents", [])
    if len(similar_incidents) > 0:
        score += 10   # escalate slightly if this is a recurring pattern

    # Clamp final score between 0 and 100
    return int(max(0, min(score, 100)))


def score_to_risk_level(score: int) -> RiskLevel:
    """Buckets a numeric score into a human-readable risk level."""
    if score >= 85:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 30:
        return "Medium"
    else:
        return "Low"


def requires_human_approval(risk_level: RiskLevel) -> bool:
    """
    Business rule: Medium and above needs a human to sign off.
    Only Low-risk actions can be auto-executed in the prototype,
    matching the synopsis: 'Low-risk actions may be executed
    automatically, high-risk actions require administrator approval.'
    """
    return risk_level in ("Medium", "High", "Critical")