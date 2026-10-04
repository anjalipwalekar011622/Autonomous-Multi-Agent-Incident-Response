from orchestrator.state import IncidentState
from agents.mitigation.risk_engine import (
    calculate_risk_score,
    score_to_risk_level,
    requires_human_approval,
)

ATTACK_TYPE_ACTION_MAP = {
    "Brute Force": "Block Source IP",
    "Phishing": "Flag and Quarantine Email/User Session",
    "Malware": "Isolate Affected Host",
    "Ransomware": "Isolate Affected Host and Disable Network Share",
    "Port Scan": "Flag Source IP as Suspicious",
    "SQL Injection": "Block Source IP and Alert DB Admin",
    "DDoS": "Rate-limit Source IP",
    "Unknown": "Flag for Manual Review",
}


def run_mitigation_agent(state: IncidentState) -> IncidentState:
    threat = state.get("threat")
    investigation = state.get("investigation")

    if not threat or not investigation:
        state["error"] = "Mitigation Agent ran without threat/investigation data"
        state["incident"]["status"] = "CLOSED"
        return state

    score = calculate_risk_score(state)
    risk_level = score_to_risk_level(score)
    needs_approval = requires_human_approval(risk_level)

    attack_type = threat.get("attack_type", "Unknown")
    action = ATTACK_TYPE_ACTION_MAP.get(attack_type, ATTACK_TYPE_ACTION_MAP["Unknown"])

    justification = (
        f"Attack type '{attack_type}' detected with risk score {score}/100 "
        f"({risk_level}). Evidence: {', '.join(investigation.get('evidence', []))}."
    )

    # Write ONLY to response — everything else (threat, investigation, memory,
    # source, event) is preserved untouched, as required by ownership rules.
    state["response"]["status"] = "COMPLETED"
    state["response"]["risk_score"] = score
    state["response"]["risk_level"] = risk_level
    state["response"]["proposed_action"] = action
    state["response"]["action_type"] = action
    state["response"]["requires_approval"] = needs_approval
    state["response"]["approval_status"] = "PENDING" if needs_approval else "NOT_REQUIRED"
    state["response"]["justification"] = justification

    state["incident"]["status"] = "AWAITING_APPROVAL" if needs_approval else "EXECUTING"

    state["agent_trace"].append("MitigationAgent: risk assessed, action proposed")

    return state