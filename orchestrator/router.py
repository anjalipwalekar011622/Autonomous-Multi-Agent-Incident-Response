from orchestrator.state import IncidentState


def route_after_mitigation(state: IncidentState) -> str:
    """
    Conditional edge function: decides what happens right after
    the Mitigation Agent runs, based on whether approval is needed.

    LangGraph calls this automatically after the 'mitigation' node.
    Must return a string that matches one of the keys in the
    conditional edge mapping we define in workflow.py.
    """
    approval_status = state.get("approval_status")

    if approval_status == "pending":
        return "needs_approval"
    else:
        return "auto_execute"