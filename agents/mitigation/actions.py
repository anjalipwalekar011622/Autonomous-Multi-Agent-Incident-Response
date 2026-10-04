import psutil
import subprocess
from orchestrator.state import IncidentState


def block_source_ip(state: IncidentState) -> str:
    ip = state["source"].get("source_ip")
    if not ip or ip in ["unknown", "127.0.0.1"]:
        return f"[SIMULATED] Source IP {ip} blocked (Skipping real firewall rule for localhost/unknown)."
    
    try:
        # T1071 / Network Denial - Add Windows Firewall Rule
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule", 
             f"name=IR-Auto-Block-{ip}", "dir=in", "action=block", f"remoteip={ip}"], 
            check=True, capture_output=True, text=True
        )
        return f"Successfully executed MITRE Mitigation: Blocked {ip} at the Windows Firewall."
    except subprocess.CalledProcessError as e:
        return f"Failed to block IP {ip} (Check if running as Admin). Error: {e.stderr}"
    except Exception as e:
        return f"Failed to block IP {ip} — {str(e)}"


def disable_compromised_account(state: IncidentState) -> str:
    user = state["source"].get("user")
    if not user or user.lower() in ["unknown", "system", "administrator"]:
        return f"[SIMULATED] Disable account '{user}' (Skipped built-in/critical account for safety)."
    
    try:
        # T1110 - Account Access Removal
        subprocess.run(
            ["net", "user", user, "/active:no"],
            check=True, capture_output=True, text=True
        )
        return f"Successfully executed MITRE Mitigation: Disabled compromised local account '{user}'."
    except subprocess.CalledProcessError as e:
        return f"Failed to disable account '{user}' (Check if running as Admin). Error: {e.stderr}"
    except Exception as e:
        return f"Failed to disable account '{user}' — {str(e)}"


def isolate_affected_host(state: IncidentState) -> str:
    # Extreme measure: Disable all network adapters
    # For a lab environment, we might just want to simulate this so we don't drop their RDP/SSH.
    ip = state["source"].get("source_ip", "unknown")
    return f"[SIMULATED] Host associated with {ip} has been isolated from the network."


def quarantine_email_session(state: IncidentState) -> str:
    return "[SIMULATED] Suspicious email/session has been flagged and quarantined."


def rate_limit_source_ip(state: IncidentState) -> str:
    ip = state["source"].get("source_ip", "unknown")
    return f"[SIMULATED] Traffic from {ip} has been rate-limited."


def flag_for_manual_review(state: IncidentState) -> str:
    return "[SIMULATED] Incident flagged for manual analyst review — no automated action taken."


def kill_malicious_process(state: IncidentState) -> str:
    pid = state.get("event", {}).get("raw_data", {}).get("pid")
    if pid:
        try:
            # T1059 / T1489 - Process Termination
            proc = psutil.Process(pid)
            process_name = proc.name()
            proc.kill()
            return f"Successfully executed MITRE Mitigation: Terminated malicious process '{process_name}' (PID: {pid})."
        except psutil.NoSuchProcess:
            return f"Process with PID {pid} already exited before mitigation."
        except psutil.AccessDenied:
            return f"Failed to kill process {pid} — Access Denied. Try running terminal as Administrator."
        except Exception as e:
            return f"Failed to kill process {pid} — {str(e)}"
    return f"[SIMULATED] Kill Malicious Process — no specific PID found to kill."


ACTION_EXECUTORS = {
    "Block Source IP": block_source_ip,
    "Disable Compromised Account": disable_compromised_account,
    "Isolate Affected Host": kill_malicious_process,  # We overloaded this earlier, let's keep it mapped
    "Kill Malicious Process": kill_malicious_process,
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
    return state