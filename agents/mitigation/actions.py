from orchestrator.state import IncidentState
from datetime import datetime


# Each function simulates one containment action.
# In a real system, these would call actual APIs (firewall, EDR, etc.)
# For the prototype, they just log what WOULD happen.

def block_source_ip(state: IncidentState) -> str:
    ip = state["threat_hunter_output"].get("source_ip", "unknown")
    return f"[SIMULATED] Source IP {ip} has been blocked at the firewall."


def isolate_affected_host(state: IncidentState) -> str:
    ip = state["threat_hunter_output"].get("source_ip", "unknown")
    return f"[SIMULATED] Host associated with {ip} has been isolated from the network."


def quarantine_email_session(state: IncidentState) -> str:
    return "[SIMULATED] Suspicious email/session has been flagged and quarantined."


def rate_limit_source_ip(state: IncidentState) -> str:
    ip = state["threat_hunter_output"].get("source_ip", "unknown")
    return f"[SIMULATED] Traffic from {ip} has been rate-limited."


def flag_for_manual_review(state: IncidentState) -> str:
    return "[SIMULATED] Incident flagged for manual analyst review — no automated action taken."


# Maps the exact action strings from mitigation.py's ATTACK_TYPE_ACTION_MAP
# to the function that simulates them.
ACTION_EXECUTORS = {
    "Block Source IP": block_source_ip,
    "Isolate Affected Host": isolate_affected_host,
    "Isolate Affected Host and Disable Network Share": isolate_affected_host,
    "Flag and Quarantine Email/User Session": quarantine_email_session,
    "Rate-limit Source IP": rate_limit_source_ip,
    "Flag Source IP as Suspicious": rate_limit_source_ip,
    "Block Source IP and Alert DB Admin": block_source_ip,
    "Flag for Manual Review": flag_for_manual_review,
}


def run_action_executor(state: IncidentState) -> IncidentState:
    """
    Executes the approved mitigation action (simulated) and
    finalizes the incident's outcome in shared state.
    """
    # Safety check: don't execute if rejected
    if state.get("approval_status") == "rejected":
        state["execution_result"] = "Action was rejected by administrator. No action taken."
        state["status"] = "closed"
        return state

    mitigation = state.get("mitigation_output")
    if not mitigation:
        state["error"] = "Action Executor ran without mitigation_output"
        state["status"] = "closed"
        return state

    action = mitigation["proposed_action"]
    executor_fn = ACTION_EXECUTORS.get(action, flag_for_manual_review)

    result = executor_fn(state)

    state["execution_result"] = result
    state["status"] = "resolved"

    print(f"\n--- ACTION EXECUTED ---\n{result}\n")

    return state