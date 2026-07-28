import uuid
from datetime import datetime
from typing import Dict, Any

class ForensicsReportGenerator:
    # Quick lookup mapping Windows Event IDs & Process anomalies to MITRE ATT&CK
    MITRE_MAPPING = {
        "4625": {"tactic": "Credential Access", "technique_id": "T1110", "name": "Brute Force"},
        "4688": {"tactic": "Execution", "technique_id": "T1059", "name": "Command and Scripting Interpreter"},
        "1102": {"tactic": "Defense Evasion", "technique_id": "T1070", "name": "Indicator Removal"},
        "SUSPICIOUS_PORT": {"tactic": "Discovery", "technique_id": "T1046", "name": "Network Service Discovery"}
    }

    @staticmethod
    def generate_report(raw_alert: Dict[str, Any], memory_matches: Dict[str, Any]) -> Dict[str, Any]:
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        event_key = str(raw_alert.get("event_id", raw_alert.get("event", "UNKNOWN")))

        # Fetch MITRE mapping or default to Anomaly
        mitre_info = ForensicsReportGenerator.MITRE_MAPPING.get(
            event_key, 
            {"tactic": "Initial Access / Execution", "technique_id": "T1204", "name": "User Execution / Anomaly"}
        )

        has_history = False
        if memory_matches and memory_matches.get("documents") and len(memory_matches["documents"][0]) > 0:
            has_history = True

        report = {
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "mitre_attack": mitre_info,
            "raw_evidence": raw_alert,
            "historical_context": {
                "seen_before": has_history,
                "matches": memory_matches.get("documents", [[]])[0] if has_history else []
            },
            "investigation_status": "COMPLETED",
            "recommended_action": "CONTAIN_AND_ISOLATE"
        }

        return report