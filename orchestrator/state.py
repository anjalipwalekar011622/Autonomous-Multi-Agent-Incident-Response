from typing import TypedDict, Optional, Literal, List


class ThreatHunterOutput(TypedDict):
    event: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    confidence: float
    source_ip: Optional[str]
    detected_at: str


class ForensicsOutput(TypedDict):
    attack_type: str
    evidence: List[str]
    indicators_of_compromise: List[str]
    similar_past_incidents: List[str]
    investigation_summary: str


class MitigationOutput(TypedDict):
    proposed_action: str
    risk_level: Literal["Low", "Medium", "High", "Critical"]
    requires_approval: bool
    justification: str


class IncidentState(TypedDict):
    incident_id: str
    created_at: str
    raw_event: dict
    threat_hunter_output: Optional[ThreatHunterOutput]
    forensics_output: Optional[ForensicsOutput]
    mitigation_output: Optional[MitigationOutput]
    approval_status: Literal["not_required", "pending", "approved", "rejected"]
    approved_by: Optional[str]
    execution_result: Optional[str]
    status: Literal[
        "detected", "investigating", "mitigation_planning",
        "awaiting_approval", "executing", "resolved", "closed"
    ]
    error: Optional[str]