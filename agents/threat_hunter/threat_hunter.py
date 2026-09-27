import json
from datetime import datetime, timezone
from agents.threat_hunter.log_parser import LogParser
from agents.threat_hunter.anomaly_detector import MultiVectorAnomalyDetector

class ThreatHunterAgent:
    def __init__(self):
        self.parser = LogParser()
        self.detector = MultiVectorAnomalyDetector()

    def run(self):
        """Executes full multi-vector telemetry collection and threat analysis."""
        # 1. Collect telemetry across all vectors
        events = self.parser.read_live_windows_events()
        processes = self.parser.get_process_telemetry()
        connections = self.parser.get_network_sockets()

        # 2. Run multi-vector detection algorithms
        alerts = []
        alerts.extend(self.detector.analyze_event_logs(events))
        alerts.extend(self.detector.analyze_processes(processes))
        alerts.extend(self.detector.analyze_network_connections(connections))

        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        current_time = datetime.now(timezone.utc).isoformat()

        if alerts:
            top_alert = alerts[0]
            return {
                "incident_id": incident_id,
                "incident": {
                    "status": "DETECTED",
                    "created_at": current_time,
                    "updated_at": current_time,
                    "severity": top_alert.get("severity", "High").upper(),
                    "confidence": float(top_alert.get("confidence", 95)) / 100.0
                },
                "source": {
                    "host": "WIN-TEST-01",
                    "os": "Windows",
                    "source_ip": top_alert.get("source_ip", "127.0.0.1"),
                    "source_port": top_alert.get("destination_port"),
                    "destination_ip": top_alert.get("destination_ip"),
                    "destination_port": top_alert.get("destination_port"),
                    "user": top_alert.get("target_user", "System")
                },
                "event": {
                    "event_id": str(top_alert.get("mitre_id", "4625")),
                    "event_type": top_alert.get("attack_type", "Security Event"),
                    "channel": "Security",
                    "description": top_alert.get("details", ""),
                    "raw_data": top_alert,
                    "normalized_data": {}
                },
                "threat": {
                    "detected": True,
                    "category": top_alert.get("threat_category", "Execution"),
                    "attack_type": top_alert.get("attack_type", "Suspicious Activity"),
                    "severity": top_alert.get("severity", "High").upper(),
                    "confidence": float(top_alert.get("confidence", 95)) / 100.0,
                    "mitre": {
                        "tactic": top_alert.get("threat_category", "Execution"),
                        "technique_id": top_alert.get("mitre_id", "T1059"),
                        "technique_name": top_alert.get("attack_type", "Suspicious Activity")
                    },
                    "indicators": [top_alert.get("details", "Anomaly flagged")],
                    "details": top_alert.get("details", "")
                }
            }

        # Clean state payload
        return {
            "incident_id": incident_id,
            "incident": {"status": "CLEAN", "created_at": current_time, "updated_at": current_time, "severity": "NONE", "confidence": 1.0},
            "source": {},
            "event": {},
            "threat": {"detected": False}
        }

if __name__ == "__main__":
    agent = ThreatHunterAgent()
    print(json.dumps(agent.run(), indent=2))