from langgraph.graph import StateGraph, END
from orchestrator.state import IncidentState
from orchestrator.mock_data import MOCK_INCIDENT_STATE
from orchestrator.router import route_after_mitigation
from agents.mitigation.mitigation import run_mitigation_agent
from agents.mitigation.approval import hitl_approval_node


def threat_hunter_node(state: IncidentState) -> IncidentState:
    state["threat_hunter_output"] = MOCK_INCIDENT_STATE["threat_hunter_output"]
    state["status"] = "investigating"
    return state


def forensics_node(state: IncidentState) -> IncidentState:
    state["forensics_output"] = MOCK_INCIDENT_STATE["forensics_output"]
    state["status"] = "mitigation_planning"
    return state


def build_workflow():
    graph = StateGraph(IncidentState)

    graph.add_node("threat_hunter", threat_hunter_node)
    graph.add_node("forensics", forensics_node)
    graph.add_node("mitigation", run_mitigation_agent)
    graph.add_node("hitl_approval", hitl_approval_node)

    graph.set_entry_point("threat_hunter")
    graph.add_edge("threat_hunter", "forensics")
    graph.add_edge("forensics", "mitigation")

    # CONDITIONAL EDGE: after mitigation, branch based on router's decision
    graph.add_conditional_edges(
        "mitigation",
        route_after_mitigation,
        {
            "needs_approval": "hitl_approval",   # if pending -> go ask human
            "auto_execute": END,                  # if not needed -> finish (for now; becomes action_executor in Part D)
        }
    )

    # After HITL approval, workflow ends for now (Part D adds real execution here)
    graph.add_edge("hitl_approval", END)

    return graph.compile()