from orchestrator.state import IncidentState


def route_after_mitigation(state: IncidentState) -> str:
    if state["response"]["requires_approval"] and state["response"]["approval_status"] == "PENDING":
        return "needs_approval"
    else:
        return "auto_execute"