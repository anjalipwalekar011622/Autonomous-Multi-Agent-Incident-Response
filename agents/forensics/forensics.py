from agents.forensics.memory import IncidentMemory
from agents.forensics.report_generator import ForensicsReportGenerator
from typing import Dict, Any

class ForensicsAgent:
    def __init__(self):
        self.memory = IncidentMemory()

    def analyze_incident(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for LangGraph Orchestrator to trigger Forensics Analysis.
        """
        print(f"\n[Forensics Agent] Investigating alert: {raw_alert.get('event', 'Unknown Event')}")

        # 1. Summarize alert for vector search
        event_summary = f"{raw_alert.get('event')} from source {raw_alert.get('source_ip', 'local')} user {raw_alert.get('user', 'unknown')}"

        # 2. Query ChromaDB for past incidents
        memory_results = self.memory.query_similar_incidents(event_summary)

        # 3. Generate enriched Forensic Report with MITRE mapping
        final_report = ForensicsReportGenerator.generate_report(raw_alert, memory_results)

        # 4. Save this new incident into ChromaDB for future memory
        self.memory.store_incident(
            incident_id=final_report["incident_id"],
            summary=event_summary,
            metadata={
                "severity": raw_alert.get("severity", "Medium"),
                "technique_id": final_report["mitre_attack"]["technique_id"]
            }
        )

        return final_report

# Simple direct test block when running this file directly
if __name__ == "__main__":
    agent = ForensicsAgent()
    sample_alert = {
        "event": "Multiple Failed Logins",
        "event_id": "4625",
        "source_ip": "192.168.1.50",
        "user": "Admin",
        "severity": "High"
    }
    result = agent.analyze_incident(sample_alert)
    print("\n--- FORENSICS OUTPUT REPORT ---")
    print(result)