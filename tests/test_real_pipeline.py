from orchestrator.workflow import build_workflow
from orchestrator.state import empty_incident_state


def test_real_pipeline():
    app = build_workflow()

    initial_state = empty_incident_state()   # CHANGED — was a bare {"incident_id": None, "agent_trace": []}

    result = app.invoke(initial_state)

    print("\n=== FINAL STATE (REAL AGENTS) ===")
    print("Incident ID:", result.get("incident_id"))
    print("Threat Detected:", result.get("threat", {}).get("detected"))
    print("Attack Type (raw):", result.get("threat", {}).get("attack_type"))
    print("Risk Level:", result.get("response", {}).get("risk_level"))
    print("Approval Status:", result.get("response", {}).get("approval_status"))
    print("Execution Result:", result.get("response", {}).get("execution_result"))
    print("Final Status:", result.get("incident", {}).get("status"))

    return result


if __name__ == "__main__":
    test_real_pipeline()