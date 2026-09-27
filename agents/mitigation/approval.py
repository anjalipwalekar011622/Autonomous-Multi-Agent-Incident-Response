from orchestrator.state import IncidentState


def hitl_approval_node(state: IncidentState) -> IncidentState:
    print("\n--- HUMAN APPROVAL REQUIRED ---")
    print(f"Proposed Action: {state['response']['proposed_action']}")
    print(f"Risk Level: {state['response']['risk_level']}")
    print(f"Justification: {state['response']['justification']}")

    # SIMULATED admin decision — replace with real interrupt()/API call later
    simulated_decision = "APPROVED"

    state["response"]["approval_status"] = simulated_decision
    state["response"]["approved_by"] = "SIMULATED_ADMIN"
    state["incident"]["status"] = "EXECUTING" if simulated_decision == "APPROVED" else "CLOSED"

    state["agent_trace"].append(f"HITL: decision={simulated_decision}")

    return state