from langgraph.graph import StateGraph, END
from orchestrator.state import IncidentState
from orchestrator.mock_data import MOCK_INCIDENT_STATE


# ---- STUB NODES (temporary, until teammates' real agents are ready) ----

def threat_hunter_node(state: IncidentState) -> IncidentState:
    """Placeholder for Srushti's real Threat Hunter Agent."""
    state["threat_hunter_output"] = MOCK_INCIDENT_STATE["threat_hunter_output"]
    state["status"] = "investigating"
    return state


def forensics_node(state: IncidentState) -> IncidentState:
    """Placeholder for Anushree's real Forensics Agent."""
    state["forensics_output"] = MOCK_INCIDENT_STATE["forensics_output"]
    state["status"] = "mitigation_planning"
    return state


# ---- YOUR REAL NODE (we'll build this properly next) ----

def mitigation_node(state: IncidentState) -> IncidentState:
    """Placeholder for now — real Mitigation Agent logic comes in the next step."""
    state["mitigation_output"] = {
        "proposed_action": "Block Source IP",
        "risk_level": "High",
        "requires_approval": True,
        "justification": "Brute force pattern detected with high confidence.",
    }
    state["status"] = "awaiting_approval"
    return state


# ---- BUILD THE GRAPH ----

def build_workflow():
    graph = StateGraph(IncidentState)

    graph.add_node("threat_hunter", threat_hunter_node)
    graph.add_node("forensics", forensics_node)
    graph.add_node("mitigation", mitigation_node)

    graph.set_entry_point("threat_hunter")
    graph.add_edge("threat_hunter", "forensics")
    graph.add_edge("forensics", "mitigation")
    graph.add_edge("mitigation", END)

    return graph.compile()