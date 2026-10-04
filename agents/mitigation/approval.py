from orchestrator.state import IncidentState
from langgraph.types import interrupt

def hitl_approval_node(state: IncidentState) -> IncidentState:
    print("\n--- HUMAN APPROVAL REQUIRED ---")
    print(f"Proposed Action: {state['response']['proposed_action']}")
    print(f"Risk Level: {state['response']['risk_level']}")
    print(f"Justification: {state['response']['justification']}")

    # Interrupt pauses execution and waits for API / user input
    user_action = interrupt({
        "action": "require_approval",
        "proposed_action": state['response']['proposed_action']
    })

    decision = user_action if user_action else "REJECTED"

    state["response"]["approval_status"] = decision
    state["response"]["approved_by"] = "ADMIN_VIA_API"
    state["incident"]["status"] = "EXECUTING" if decision == "APPROVED" else "CLOSED"

    state["agent_trace"].append(f"HITL: decision={decision}")

    return state
    return state