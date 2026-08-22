from langgraph.graph import StateGraph, END
from orchestrator.state import IncidentState
from orchestrator.mock_data import MOCK_INCIDENT_STATE
from agents.mitigation.mitigation import run_mitigation_agent


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


# ---- BUILD THE GRAPH ----

def build_workflow():
    graph = StateGraph(IncidentState)

    graph.add_node("threat_hunter", threat_hunter_node)
    graph.add_node("forensics", forensics_node)
    graph.add_node("mitigation", run_mitigation_agent)   # <-- real logic now

    graph.set_entry_point("threat_hunter")
    graph.add_edge("threat_hunter", "forensics")
    graph.add_edge("forensics", "mitigation")
    graph.add_edge("mitigation", END)

    return graph.compile()