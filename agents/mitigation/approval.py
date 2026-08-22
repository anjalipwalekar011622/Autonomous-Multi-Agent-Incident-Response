from orchestrator.state import IncidentState


def hitl_approval_node(state: IncidentState) -> IncidentState:
    """
    Human-in-the-Loop approval node.

    In the FINAL system, this node's job is to PAUSE the graph and wait
    for a real admin to click Approve/Reject on the React dashboard,
    which calls a FastAPI endpoint that resumes this graph.

    For NOW (since dashboard/API aren't built yet), we simulate an
    admin decision so we can test the full workflow end-to-end.
    This stub will be replaced with a real LangGraph interrupt() call
    once FastAPI + React are ready (see note below).
    """
    print("\n--- HUMAN APPROVAL REQUIRED ---")
    print(f"Proposed Action: {state['mitigation_output']['proposed_action']}")
    print(f"Risk Level: {state['mitigation_output']['risk_level']}")
    print(f"Justification: {state['mitigation_output']['justification']}")

    # SIMULATED admin decision for now — hardcoded to "approved"
    # so we can test the rest of the pipeline (action execution).
    # We'll swap this for real interactive/API-driven input later.
    simulated_decision = "approved"

    state["approval_status"] = simulated_decision
    state["approved_by"] = "SIMULATED_ADMIN"
    state["status"] = "executing" if simulated_decision == "approved" else "closed"

    return state