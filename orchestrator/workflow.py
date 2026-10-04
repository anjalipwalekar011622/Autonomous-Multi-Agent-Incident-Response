import concurrent.futures

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from orchestrator.state import IncidentState
from orchestrator.router import route_after_mitigation
from agents.mitigation.mitigation import run_mitigation_agent
from agents.mitigation.approval import hitl_approval_node
from agents.mitigation.actions import run_action_executor

# Real agent imports (production)
from agents.threat_hunter.threat_hunter import threat_hunter_node
from agents.forensics.forensics import forensics_node as real_forensics_node

# Global checkpointer for the application
memory_saver = MemorySaver()

def forensics_node_with_timeout(state: dict, timeout_seconds: int = 8) -> dict:
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(real_forensics_node, state)
        try:
            return future.result(timeout=timeout_seconds)
        except concurrent.futures.TimeoutError:
            print(f"[Orchestrator] Forensics node timed out after {timeout_seconds}s - using fallback.")
            state["investigation"] = {
                "agent": "ForensicsAgent", "status": "FAILED", "findings": [], "evidence": [],
                "mitre_attack": {"tactic": None, "technique_id": None, "technique_name": None,
                                  "confidence": None, "needs_review": True},
                "historical_context": {"seen_before": False, "matches": [], "similarity": None},
                "attack_pattern": None, "recommended_action": None,
            }
            state["memory"] = {"stored": False, "historical_retrieval_completed": False, "vector_id": None}
            return state


# ---------- STUB NODES (for mock/unit testing only) ----------

def stub_threat_hunter_node(state: IncidentState) -> IncidentState:
    state["incident"]["status"] = "INVESTIGATING"
    return state


def stub_forensics_node(state: IncidentState) -> IncidentState:
    state["incident"]["status"] = "MITIGATION_PLANNING"
    return state


# ---------- BUILDERS ----------

def build_workflow():
    graph = StateGraph(IncidentState)

    graph.add_node("threat_hunter", threat_hunter_node)
    graph.add_node("forensics", forensics_node_with_timeout)
    graph.add_node("mitigation", run_mitigation_agent)
    graph.add_node("hitl_approval", hitl_approval_node)
    graph.add_node("action_executor", run_action_executor)

    graph.set_entry_point("threat_hunter")
    graph.add_edge("threat_hunter", "forensics")
    graph.add_edge("forensics", "mitigation")

    graph.add_conditional_edges(
        "mitigation",
        route_after_mitigation,
        {"needs_approval": "hitl_approval", "auto_execute": "action_executor"}
    )

    graph.add_edge("hitl_approval", "action_executor")
    graph.add_edge("action_executor", END)

    return graph.compile(checkpointer=memory_saver)


def build_mock_workflow():
    graph = StateGraph(IncidentState)

    graph.add_node("threat_hunter", stub_threat_hunter_node)
    graph.add_node("forensics", stub_forensics_node)
    graph.add_node("mitigation", run_mitigation_agent)
    graph.add_node("hitl_approval", hitl_approval_node)
    graph.add_node("action_executor", run_action_executor)

    graph.set_entry_point("threat_hunter")
    graph.add_edge("threat_hunter", "forensics")
    graph.add_edge("forensics", "mitigation")

    graph.add_conditional_edges(
        "mitigation",
        route_after_mitigation,
        {"needs_approval": "hitl_approval", "auto_execute": "action_executor"}
    )

    graph.add_edge("hitl_approval", "action_executor")
    graph.add_edge("action_executor", END)

    return graph.compile(checkpointer=memory_saver)
    return graph.compile()