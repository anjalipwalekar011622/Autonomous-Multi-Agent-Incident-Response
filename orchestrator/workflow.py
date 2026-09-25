from langgraph.graph import StateGraph, END
from orchestrator.state import IncidentState
from orchestrator.mock_data import MOCK_INCIDENT_STATE
from orchestrator.router import route_after_mitigation
from agents.mitigation.mitigation import run_mitigation_agent
from agents.mitigation.approval import hitl_approval_node
from agents.mitigation.actions import run_action_executor


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
    graph.add_node("action_executor", run_action_executor)   # NEW

    graph.set_entry_point("threat_hunter")
    graph.add_edge("threat_hunter", "forensics")
    graph.add_edge("forensics", "mitigation")

    graph.add_conditional_edges(
        "mitigation",
        route_after_mitigation,
        {
            "needs_approval": "hitl_approval",
            "auto_execute": "action_executor",   # CHANGED from END
        }
    )

    graph.add_edge("hitl_approval", "action_executor")   # CHANGED from END
    graph.add_edge("action_executor", END)                # NEW final edge

    return graph.compile()