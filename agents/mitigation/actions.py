from orchestrator.state import IncidentState


def block_source_ip(state: IncidentState) -> str:
    ip = state["source"].get("source_ip", "unknown")
    return f"[SIMULATED] Source IP {ip} has been blocked at the firewall."


def isolate_affected_host(state: IncidentState) -> str:
    ip = state["source"].get("source_ip", "unknown")
    return f"[SIMULATED] Host associated with {ip} has been isolated from the network."


def quarantine_email_session(state: IncidentState) -> str:
    return "[SIMULATED] Suspicious email/session has been flagged and quarantined."


def rate_limit_source_ip(state: IncidentState) -> str:
    ip = state["source"].get("source_ip", "unknown")
    return f"[SIMULATED] Traffic from {ip} has been rate-limited."


def flag_for_manual_review(state: IncidentState) -> str:
    return "[SIMULATED] Incident flagged for manual analyst review — no automated action taken."


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
    if state["response"]["approval_status"] == "REJECTED":
        state["response"]["execution_status"] = "SKIPPED"
        state["response"]["execution_result"] = "Action was rejected by administrator. No action taken."
        state["verification"]["status"] = "VERIFIED"
        state["verification"]["threat_contained"] = False
        state["verification"]["details"].append("No mitigation executed — administrator rejected the action.")
        state["incident"]["status"] = "CLOSED"
        state["agent_trace"].append("ActionExecutor: skipped (rejected)")
        return state

    action = state["response"].get("proposed_action")
    if not action:
        state["error"] = "Action Executor ran without proposed_action"
        state["incident"]["status"] = "CLOSED"
        return state

    executor_fn = ACTION_EXECUTORS.get(action, flag_for_manual_review)
    result = executor_fn(state)

    state["response"]["execution_status"] = "EXECUTED"
    state["response"]["execution_result"] = result

    state["verification"]["status"] = "VERIFIED"
    state["verification"]["threat_contained"] = True
    state["verification"]["details"].append(result)

    state["incident"]["status"] = "RESOLVED"
    state["agent_trace"].append("ActionExecutor: action executed")

    print(f"\n--- ACTION EXECUTED ---\n{result}\n")

    return state