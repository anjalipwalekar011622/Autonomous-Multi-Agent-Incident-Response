from datetime import datetime

MOCK_INCIDENT_STATE = {
    "incident_id": "INC-001",
    "created_at": datetime.utcnow().isoformat(),
    "raw_event": {"log": "Multiple failed login attempts from 192.168.1.20"},
    "threat_hunter_output": {
        "event": "Multiple Failed Login Attempts",
        "severity": "High",
        "confidence": 0.92,
        "source_ip": "192.168.1.20",
        "detected_at": datetime.utcnow().isoformat(),
    },
    "forensics_output": {
        "attack_type": "Brute Force",
        "evidence": ["12 failed logins in 60 seconds", "Same source IP"],
        "indicators_of_compromise": ["192.168.1.20"],
        "similar_past_incidents": ["INC-000"],
        "investigation_summary": "Pattern matches brute-force login attempt.",
    },
    "mitigation_output": None,
    "approval_status": "not_required",
    "approved_by": None,
    "execution_result": None,
    "status": "investigating",
    "error": None,
}