from orchestrator.state import IncidentState
from typing import Literal

RiskLevel = Literal["Low", "Medium", "High", "Critical"]

ATTACK_TYPE_BASE_SCORE = {
    "Brute Force": 60,
    "Phishing": 40,
    "Malware": 80,
    "Ransomware": 95,
    "Port Scan": 20,
    "SQL Injection": 75,
    "DDoS": 85,
    "Suspicious PowerShell": 85,
    "Suspicious Process Access": 80,
    "Suspicious Registry Activity": 65,
    "Unknown": 50,
}


def calculate_risk_score(state: IncidentState) -> int:
    threat = state.get("threat")
    investigation = state.get("investigation")

    if not threat or not investigation:
        return 70   # unchanged safety default

    score = 0

    attack_type = threat.get("attack_type", "Unknown")
    score += ATTACK_TYPE_BASE_SCORE.get(attack_type, ATTACK_TYPE_BASE_SCORE["Unknown"])

    confidence = threat.get("confidence", 0.5)
    score += confidence * 20

    evidence_count = len(investigation.get("evidence", []))
    score += min(evidence_count * 3, 15)

    seen_before = investigation.get("historical_context", {}).get("seen_before", False)
    if seen_before:
        score += 10

    return int(max(0, min(score, 100)))


def score_to_risk_level(score: int) -> RiskLevel:
    if score >= 85:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 30:
        return "Medium"
    else:
        return "Low"


def requires_human_approval(risk_level: RiskLevel, is_reversible: bool = False) -> bool:
    if risk_level == "Low":
        return False
    if risk_level == "Medium" and is_reversible:
        return False
    return True