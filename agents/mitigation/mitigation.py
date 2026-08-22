from orchestrator.state import IncidentState, MitigationOutput
from agents.mitigation.risk_engine import (
    calculate_risk_score,
    score_to_risk_level,
    requires_human_approval,
)

# Maps attack type -> proposed containment action.
# These are SAFE, prototype-level actions only (per synopsis: no real
# destructive actions without approval).
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
    """
    The core Mitigation Agent node.
    Reads forensics_output, calculates risk, proposes an action,
    and writes mitigation_output back into shared state.
    """
    forensics = state.get("forensics_output")

    if not forensics:
        # Defensive check: Mitigation should never run before Forensics.
        state["error"] = "Mitigation Agent ran without forensics_output"
        state["status"] = "closed"
        return state

    # 1. Calculate risk using the Risk Engine
    score = calculate_risk_score(state)
    risk_level = score_to_risk_level(score)
    needs_approval = requires_human_approval(risk_level)

    # 2. Decide the proposed action based on attack type
    attack_type = forensics.get("attack_type", "Unknown")
    action = ATTACK_TYPE_ACTION_MAP.get(attack_type, ATTACK_TYPE_ACTION_MAP["Unknown"])

    # 3. Build justification text (useful for dashboard + HITL approval screen)
    justification = (
        f"Attack type '{attack_type}' detected with risk score {score}/100 "
        f"({risk_level}). Evidence: {', '.join(forensics.get('evidence', []))}."
    )

    # 4. Write result into MitigationOutput shape
    mitigation_output: MitigationOutput = {
        "proposed_action": action,
        "risk_level": risk_level,
        "requires_approval": needs_approval,
        "justification": justification,
    }

    state["mitigation_output"] = mitigation_output
    state["approval_status"] = "pending" if needs_approval else "not_required"
    state["status"] = "awaiting_approval" if needs_approval else "executing"

    return state