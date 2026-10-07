from orchestrator.state import IncidentState
from agents.mitigation.risk_engine import (
    calculate_risk_score,
    score_to_risk_level,
    requires_human_approval,
)
from agents.mitigation.attack_type_normalizer import (
    normalize_attack_type,
    normalize_evidence,
)

ATTACK_TYPE_ACTION_MAP = {
    "Brute Force": "Block Source IP",
    "Phishing": "Flag and Quarantine Email/User Session",
    "Malware": "Kill Malicious Process",
    "Ransomware": "Kill Malicious Process",
    "Port Scan": "Block Source IP",
    "SQL Injection": "Block Source IP and Alert DB Admin",
    "DDoS": "Rate-limit Source IP",
    "Suspicious PowerShell": "Kill Malicious Process",
    "Suspicious Process Access": "Kill Malicious Process",
    "Suspicious Registry Activity": "Flag for Manual Review",
    "Unknown": "Flag for Manual Review",
}


def run_mitigation_agent(state: IncidentState) -> IncidentState:
    threat = state.get("threat")
    investigation = state.get("investigation")

    if not threat or not investigation:
        state["error"] = "Mitigation Agent ran without threat/investigation data"
        state["incident"]["status"] = "CLOSED"
        return state

    # Normalize Threat Hunter's raw attack_type into our canonical category
    raw_attack_type = threat.get("attack_type", "Unknown")
    attack_type = normalize_attack_type(raw_attack_type)

    # Normalize Forensics' evidence (splits combined strings into separate items)
    normalized_evidence = normalize_evidence(investigation.get("evidence", []))

    # Build a lightly-patched copy of state for risk scoring, so the Risk
    # Engine sees canonical attack_type + expanded evidence without us
    # mutating the original threat/investigation sections (preserves them
    # exactly as required by the shared-state ownership rules).
    scoring_state = dict(state)
    scoring_state["threat"] = dict(threat)
    scoring_state["threat"]["attack_type"] = attack_type
    scoring_state["investigation"] = dict(investigation)
    scoring_state["investigation"]["evidence"] = normalized_evidence

    score = calculate_risk_score(scoring_state)
    risk_level = score_to_risk_level(score)
    
    action = ATTACK_TYPE_ACTION_MAP.get(attack_type, ATTACK_TYPE_ACTION_MAP["Unknown"])
    is_reversible = action in ["Block Source IP", "Rate-limit Source IP"]
    needs_approval = requires_human_approval(risk_level, is_reversible=is_reversible)


    justification = (
        f"Attack type '{raw_attack_type}' (normalized: '{attack_type}') detected with "
        f"risk score {score}/100 ({risk_level}). "
        f"Evidence: {', '.join(normalized_evidence) if normalized_evidence else 'none recorded'}."
    )

    action_parameters = {}
    source = state.get("source", {})
    if action == "Block Source IP" or action == "Rate-limit Source IP":
        action_parameters = {
            "source_ip": source.get("source_ip"),
            "destination_port": source.get("destination_port")
        }
    elif action == "Kill Malicious Process":
        action_parameters = {
            "pid": source.get("pid"),
            "process_name": source.get("process_name"),
            "process_path": source.get("executable_path")
        }
    elif action == "Flag for Manual Review":
        action_parameters = {
            "registry_path": state.get("event", {}).get("raw_data", {}).get("target_object"),
            "pid": source.get("pid")
        }

    # Write ONLY to response — threat, investigation, memory, source, event
    # remain exactly as Threat Hunter / Forensics wrote them.
    state["response"]["status"] = "COMPLETED"
    state["response"]["risk_score"] = score
    state["response"]["risk_level"] = risk_level
    state["response"]["proposed_action"] = action
    state["response"]["action_type"] = action
    state["response"]["action_parameters"] = action_parameters
    state["response"]["requires_approval"] = needs_approval
    state["response"]["approval_status"] = "PENDING" if needs_approval else "NOT_REQUIRED"
    state["response"]["justification"] = justification

    state["incident"]["status"] = "AWAITING_APPROVAL" if needs_approval else "EXECUTING"

    state["agent_trace"].append("MitigationAgent: risk assessed, action proposed")

    return state