import copy
from orchestrator.workflow import build_mock_workflow
from orchestrator.mock_data import make_mock_state


def run(state):
    app = build_mock_workflow()
    return app.invoke(state, config={"configurable": {"thread_id": "test_thread"}})


def test_scenario_A_high_risk_approved():
    """High/Critical incident + approval + approved action."""
    from langgraph.types import Command
    app = build_mock_workflow()
    config = {"configurable": {"thread_id": "test_thread_a"}}
    
    state = make_mock_state(attack_type="Brute Force")
    result = app.invoke(state, config=config)
    if result is None:
        result = app.get_state(config).values

    assert result["incident_id"] == "INC-20260917-0001"
    assert result["response"]["risk_level"] in ("High", "Critical")
    assert result["incident"]["status"] == "AWAITING_APPROVAL"
    
    resume_result = app.invoke(Command(resume="APPROVED"), config=config)
    if resume_result is None:
        resume_result = app.get_state(config).values

    assert resume_result["incident_id"] == "INC-20260917-0001"
    assert resume_result["response"]["approval_status"] == "APPROVED"
    assert resume_result["response"]["execution_status"] in ["EXECUTED", "FAILED"]
    assert "Failed to block IP 192.168.1.105" in resume_result["response"]["execution_result"] or "Successfully executed" in resume_result["response"]["execution_result"]
    assert resume_result["incident"]["status"] in ["RESOLVED", "FAILED"]
    print("Scenario A passed:", resume_result["response"]["execution_result"])


def test_scenario_B_high_risk_rejected():
    """High/Critical incident + approval + rejected action."""
    from langgraph.types import Command
    app = build_mock_workflow()
    config = {"configurable": {"thread_id": "test_thread_b"}}

    state = make_mock_state(attack_type="Ransomware")
    result = app.invoke(state, config=config)
    if result is None:
        result = app.get_state(config).values
        
    assert result["incident"]["status"] == "AWAITING_APPROVAL"
    
    resume_result = app.invoke(Command(resume="REJECTED"), config=config)
    if resume_result is None:
        resume_result = app.get_state(config).values
        
    assert resume_result["response"]["approval_status"] == "REJECTED"
    assert resume_result["response"]["execution_status"] == "SKIPPED"
    assert resume_result["incident"]["status"] == "CLOSED"
    print("Scenario B passed:", resume_result["response"]["execution_result"])


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
    assert result["response"]["execution_status"] in ["EXECUTED", "FAILED"]
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