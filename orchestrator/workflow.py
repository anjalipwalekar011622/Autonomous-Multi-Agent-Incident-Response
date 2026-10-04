import concurrent.futures

from langgraph.graph import StateGraph, END
from orchestrator.state import IncidentState
from orchestrator.router import route_after_mitigation
from agents.mitigation.mitigation import run_mitigation_agent
from agents.mitigation.approval import hitl_approval_node
from agents.mitigation.actions import run_action_executor

# Real agent imports (replacing old stubs)
from agents.threat_hunter.threat_hunter import threat_hunter_node
from agents.forensics.forensics import forensics_node as real_forensics_node


def forensics_node_with_timeout(state: dict, timeout_seconds: int = 8) -> dict:
    """
    Wraps the real Forensics node with a timeout so a hanging/slow Ollama
    call (up to 30s internally) can't freeze the whole pipeline during a
    live demo. Falls back to a safe empty investigation/memory block if
    the real node doesn't finish in time.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(real_forensics_node, state)
        try:
            return future.result(timeout=timeout_seconds)
        except concurrent.futures.TimeoutError:
            print(f"[Orchestrator] Forensics node timed out after {timeout_seconds}s — using fallback.")
            state["investigation"] = {
                "agent": "ForensicsAgent",
                "status": "FAILED",
                "findings": [],
                "evidence": [],
                "mitre_attack": {
                    "tactic": None, "technique_id": None, "technique_name": None,
                    "confidence": None, "needs_review": True,
                },
                "historical_context": {"seen_before": False, "matches": [], "similarity": None},
                "attack_pattern": None,
                "recommended_action": None,
            }
            state["memory"] = {
                "stored": False,
                "historical_retrieval_completed": False,
                "vector_id": None,
            }
            return state


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
        {
            "needs_approval": "hitl_approval",
            "auto_execute": "action_executor",
        }
    )

    graph.add_edge("hitl_approval", "action_executor")
    graph.add_edge("action_executor", END)

    return graph.compile()