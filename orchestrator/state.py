from typing import TypedDict, Optional, Literal, List, Dict, Any


# ---------- incident ----------
class IncidentMeta(TypedDict):
    status: Literal[
        "DETECTED", "INVESTIGATING", "MITIGATION_PLANNING",
        "AWAITING_APPROVAL", "EXECUTING", "RESOLVED", "CLOSED"
    ]
    created_at: str
    updated_at: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float


# ---------- source ----------
class Source(TypedDict):
    host: Optional[str]
    os: Optional[str]
    source_ip: Optional[str]
    source_port: Optional[int]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    user: Optional[str]


# ---------- event ----------
class Event(TypedDict):
    event_id: Optional[str]
    event_type: Optional[str]
    channel: Optional[str]
    description: Optional[str]
    raw_data: Dict[str, Any]
    normalized_data: Dict[str, Any]


# ---------- threat ----------
class MitreInfo(TypedDict):
    tactic: Optional[str]
    technique_id: Optional[str]
    technique_name: Optional[str]


class Threat(TypedDict):
    detected: bool
    category: Optional[str]
    attack_type: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float
    mitre: MitreInfo
    indicators: List[str]
    details: Optional[str]


# ---------- investigation (Forensics owns this) ----------
class MitreAttackReview(TypedDict):
    tactic: Optional[str]
    technique_id: Optional[str]
    technique_name: Optional[str]
    confidence: Optional[float]
    needs_review: bool


class HistoricalContext(TypedDict):
    seen_before: bool
    matches: List[str]
    similarity: Optional[float]


class Investigation(TypedDict):
    agent: str
    status: Literal["NOT_STARTED", "IN_PROGRESS", "COMPLETED"]
    findings: List[str]
    evidence: List[str]
    mitre_attack: MitreAttackReview
    historical_context: HistoricalContext
    attack_pattern: Optional[str]
    recommended_action: Optional[str]


# ---------- response (Mitigation owns this) ----------
class Response(TypedDict):
    agent: str
    status: Literal["NOT_STARTED", "IN_PROGRESS", "COMPLETED"]
    risk_score: Optional[int]
    risk_level: Optional[Literal["Low", "Medium", "High", "Critical"]]
    proposed_action: Optional[str]
    action_type: Optional[str]
    action_parameters: Dict[str, Any]
    requires_approval: bool
    approval_status: Literal["NOT_REQUIRED", "PENDING", "APPROVED", "REJECTED"]
    approved_by: Optional[str]          # kept as extra field — useful for dashboard, not in conflict with canonical spec
    execution_status: Literal["NOT_STARTED", "EXECUTED", "SKIPPED", "FAILED"]
    execution_result: Optional[str]
    justification: Optional[str]        # kept as extra field — dashboard needs a reason string


# ---------- verification (Mitigation owns this) ----------
class Verification(TypedDict):
    status: Literal["PENDING", "VERIFIED", "FAILED"]
    threat_contained: bool
    details: List[str]


# ---------- memory (Forensics owns this) ----------
class Memory(TypedDict):
    stored: bool
    historical_retrieval_completed: bool
    vector_id: Optional[str]


# ---------- top-level canonical state ----------
class IncidentState(TypedDict):
    incident_id: str
    incident: IncidentMeta
    source: Source
    event: Event
    threat: Threat
    investigation: Investigation
    response: Response
    verification: Verification
    memory: Memory
    agent_trace: List[str]
    error: Optional[str]

def empty_incident_state() -> dict:
    """
    Returns a fresh IncidentState with every section initialized to safe
    empty defaults. Use this as the starting point when invoking the
    graph with REAL agents (not mock data) — each node then fills in
    only the sections it owns.
    """
    return {
        "incident_id": None,
        "incident": {
            "status": "DETECTED",
            "created_at": None,
            "updated_at": None,
            "severity": "LOW",
            "confidence": 0.0,
        },
        "source": {},
        "event": {},
        "threat": {},
        "investigation": {
            "agent": "ForensicsAgent",
            "status": "NOT_STARTED",
            "findings": [],
            "evidence": [],
            "mitre_attack": {
                "tactic": None, "technique_id": None, "technique_name": None,
                "confidence": None, "needs_review": False,
            },
            "historical_context": {"seen_before": False, "matches": [], "similarity": None},
            "attack_pattern": None,
            "recommended_action": None,
        },
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
            "historical_retrieval_completed": False,
            "vector_id": None,
        },
        "agent_trace": [],
        "error": None,
    }