from datetime import datetime, timezone

_now = datetime.now(timezone.utc).isoformat()

MOCK_INCIDENT_STATE = {
    "incident_id": "INC-20260917-0001",

    "incident": {
        "status": "DETECTED",
        "created_at": _now,
        "updated_at": _now,
        "severity": "HIGH",
        "confidence": 0.95,
    },

    "source": {
        "host": "WIN-TEST-01",
        "os": "Windows",
        "source_ip": "192.168.1.105",
        "source_port": None,
        "destination_ip": None,
        "destination_port": None,
        "user": "Administrator",
    },

    "event": {
        "event_id": "4625",
        "event_type": "Failed Logon",
        "channel": "Security",
        "description": "Multiple failed login attempts",
        "raw_data": {},
        "normalized_data": {},
    },

    "threat": {
        "detected": True,
        "category": "Credential Access",
        "attack_type": "Brute Force",
        "severity": "HIGH",
        "confidence": 0.95,
        "mitre": {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
        },
        "indicators": [
            "Multiple failed login attempts",
            "Same source IP",
            "Targeted Administrator account",
        ],
        "details": "3 failed logons detected from the same source IP",
    },

    # Simulates ForensicsAgent's completed output (stub, until real agent is ready)
    "investigation": {
        "agent": "ForensicsAgent",
        "status": "COMPLETED",
        "findings": ["Pattern matches brute-force login attempt."],
        "evidence": ["12 failed logins in 60 seconds", "Same source IP"],
        "mitre_attack": {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "confidence": 0.9,
            "needs_review": False,
        },
        "historical_context": {
            "seen_before": True,
            "matches": ["INC-000"],
            "similarity": 0.87,
        },
        "attack_pattern": "Brute Force",
        "recommended_action": "Block Source IP",
    },

    # Mitigation hasn't run yet
    "response": {
        "agent": "MitigationAgent",
        "status": "NOT_STARTED",
        "risk_score": None,
        "risk_level": None,
        "proposed_action": None,
        "action_type": None,
        "action_parameters": {},
        "requires_approval": False,
        "approval_status": "NOT_REQUIRED",
        "approved_by": None,
        "execution_status": "NOT_STARTED",
        "execution_result": None,
        "justification": None,
    },

    "verification": {
        "status": "PENDING",
        "threat_contained": False,
        "details": [],
    },

    "memory": {
        "stored": False,
        "historical_retrieval_completed": True,
        "vector_id": None,
    },

    "agent_trace": [],
    "error": None,
}


def make_mock_state(**overrides) -> dict:
    """
    Returns a fresh deep-ish copy of the mock state so tests don't
    mutate the shared MOCK_INCIDENT_STATE object. Pass overrides like
    attack_type="Ransomware" or evidence=[...] for scenario testing.
    """
    import copy
    state = copy.deepcopy(MOCK_INCIDENT_STATE)

    if "attack_type" in overrides:
        state["threat"]["attack_type"] = overrides["attack_type"]
        state["investigation"]["attack_pattern"] = overrides["attack_type"]
    if "evidence" in overrides:
        state["investigation"]["evidence"] = overrides["evidence"]
    if "confidence" in overrides:
        state["threat"]["confidence"] = overrides["confidence"]
    if "seen_before" in overrides:
        state["investigation"]["historical_context"]["seen_before"] = overrides["seen_before"]
        if not overrides["seen_before"]:
            state["investigation"]["historical_context"]["matches"] = []

    return state