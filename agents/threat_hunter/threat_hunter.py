import os
import json
import psutil
from datetime import datetime, timezone
from agents.threat_hunter.log_parser import LogParser
from agents.threat_hunter.anomaly_detector import MultiVectorAnomalyDetector

class ThreatHunterAgent:
    def __init__(self):
        self.parser = LogParser()
        self.detector = MultiVectorAnomalyDetector()

    def run_detection(self):
        """Internal telemetry sweep and multi-vector detection logic."""
        events = self.parser.read_live_windows_events()
        processes = self.parser.get_process_telemetry()
        connections = self.parser.get_network_sockets()

        alerts = []
        alerts.extend(self.detector.analyze_event_logs(events))
        alerts.extend(self.detector.analyze_processes(processes))
        alerts.extend(self.detector.analyze_network_connections(connections))
        return alerts


def threat_hunter_node(state: dict) -> dict:
    """
    LangGraph Node Function for Threat Hunter.
    - Accepts existing shared IncidentState.
    - Preserves or initializes incident_id.
    - Populates incident, source, event, and threat blocks.
    - Normalizes confidence (0 to 1 scale) and attack types.
    """
    agent = ThreatHunterAgent()
    alerts = agent.run_detection()

    # 1. Preserve existing incident_id if present, else generate one
    incident_id = state.get("incident_id")
    if not incident_id:
        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    current_time = datetime.now(timezone.utc).isoformat()

    if alerts:
        top_alert = alerts[0]
        # Align attack type naming with team standards
        attack_type = top_alert.get("attack_type", "Brute Force Authentication")
        severity = top_alert.get("severity", "High").upper()
        confidence = float(top_alert.get("confidence", 95)) / 100.0

        incident_update = {
            "status": "DETECTED",
            "created_at": state.get("incident", {}).get("created_at", current_time),
            "updated_at": current_time,
            "severity": severity,
            "confidence": confidence
        }
        source_update = {
            "host": "WIN-TEST-01",
            "os": "Windows",
            "source_ip": top_alert.get("source_ip", "127.0.0.1"),
            "source_port": top_alert.get("destination_port"),
            "destination_ip": top_alert.get("destination_ip"),
            "destination_port": top_alert.get("destination_port"),
            "user": top_alert.get("target_user", "System")
        }
        event_update = {
            "event_id": str(top_alert.get("mitre_id", "4625")),
            "event_type": attack_type,
            "channel": "Security",
            "description": top_alert.get("details", ""),
            "raw_data": top_alert,
            "normalized_data": {}
        }
        threat_update = {
            "detected": True,
            "category": top_alert.get("threat_category", "Credential Access"),
            "attack_type": attack_type,
            "severity": severity,
            "confidence": confidence,
            "mitre": {
                "tactic": top_alert.get("threat_category", "Credential Access"),
                "technique_id": top_alert.get("mitre_id", "T1110"),
                "technique_name": attack_type
            },
            "indicators": [top_alert.get("details", "Anomaly flagged")],
            "details": top_alert.get("details", "")
        }
    else:
        incident_update = {
            "status": "CLEAN", 
            "created_at": current_time, 
            "updated_at": current_time, 
            "severity": "NONE", 
            "confidence": 1.0
        }
        source_update = {}
        event_update = {}
        threat_update = {"detected": False}

    # Append to agent trace safely
    trace = state.get("agent_trace", [])
    trace.append("ThreatHunterAgent completed telemetry sweep and detection.")

    return {
        "incident_id": incident_id,
        "incident": incident_update,
        "source": source_update,
        "event": event_update,
        "threat": threat_update,
        "agent_trace": trace
    }

if __name__ == "__main__":
    # Local test stub mimicking an incoming empty LangGraph state
    test_state = {"incident_id": "INC-TEST-999", "agent_trace": []}
    result = threat_hunter_node(test_state)
    print(json.dumps(result, indent=2))