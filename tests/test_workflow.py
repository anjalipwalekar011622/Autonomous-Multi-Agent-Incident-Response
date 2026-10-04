import copy
from orchestrator.workflow import build_workflow
from orchestrator.mock_data import make_mock_state


def run(state):
    app = build_workflow()
    return app.invoke(state)


def test_scenario_A_high_risk_approved():
    """High/Critical incident + approval + approved action."""
    state = make_mock_state(attack_type="Brute Force")
    result = run(state)

    assert result["incident_id"] == "INC-20260917-0001"
    assert result["response"]["risk_level"] in ("High", "Critical")
    assert result["response"]["approval_status"] == "APPROVED"
    assert result["response"]["execution_status"] == "EXECUTED"
    assert result["incident"]["status"] == "RESOLVED"
    print("Scenario A passed:", result["response"]["execution_result"])


def test_scenario_B_high_risk_rejected():
    """High/Critical incident + approval + rejected action."""
    from agents.mitigation import approval as approval_module

    # Temporarily force rejection for this test only
    original_fn = approval_module.hitl_approval_node

    def rejecting_hitl(state):
        state["response"]["approval_status"] = "REJECTED"
        state["response"]["approved_by"] = "SIMULATED_ADMIN"
        state["incident"]["status"] = "CLOSED"
        return state

    approval_module.hitl_approval_node = rejecting_hitl

    try:
        # Rebuild workflow so it picks up the patched function
        import importlib
        import orchestrator.workflow as workflow_module
        importlib.reload(workflow_module)

        state = make_mock_state(attack_type="Ransomware")
        app = workflow_module.build_workflow()
        result = app.invoke(state)

        assert result["response"]["approval_status"] == "REJECTED"
        assert result["response"]["execution_status"] == "SKIPPED"
        assert result["incident"]["status"] == "CLOSED"
        print("Scenario B passed:", result["response"]["execution_result"])
    finally:
        approval_module.hitl_approval_node = original_fn
        importlib.reload(workflow_module)


def test_scenario_C_low_risk_no_hitl():
    """Low-risk incident skips HITL entirely."""
    state = make_mock_state(
        attack_type="Port Scan",
        evidence=["Single scan attempt"],
        confidence=0.3,
        seen_before=False,
    )
    result = run(state)

    assert result["response"]["risk_level"] in ("Low", "Medium")
    if result["response"]["risk_level"] == "Low":
        assert result["response"]["approval_status"] == "NOT_REQUIRED"
    assert result["response"]["execution_status"] == "EXECUTED"
    print("Scenario C passed: risk_level =", result["response"]["risk_level"])


def test_scenario_D_state_preservation():
    """Ensure Mitigation preserves threat/investigation/memory untouched."""
    from agents.mitigation.mitigation import run_mitigation_agent

    state = make_mock_state(attack_type="Brute Force")
    original_threat = copy.deepcopy(state["threat"])
    original_investigation = copy.deepcopy(state["investigation"])
    original_memory = copy.deepcopy(state["memory"])
    original_id = state["incident_id"]

    result = run_mitigation_agent(state)

    assert result["incident_id"] == original_id
    assert result["threat"] == original_threat
    assert result["investigation"] == original_investigation
    assert result["memory"] == original_memory
    assert result["response"]["status"] == "COMPLETED"
    assert result["verification"] is not None
    print("Scenario D passed: all sections preserved correctly")


if __name__ == "__main__":
    test_scenario_A_high_risk_approved()
    test_scenario_B_high_risk_rejected()
    test_scenario_C_low_risk_no_hitl()
    test_scenario_D_state_preservation()
    print("\nAll scenarios passed.")