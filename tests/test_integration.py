import sys
import os
import json
from datetime import datetime

# Add root directory to path so python can find local modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.threat_hunter.threat_hunter import ThreatHunterAgent

def simulate_langgraph_workflow():
    print("=" * 70)
    print("🔗 STARTING MOCK LANGGRAPH INTEGRATION TEST")
    print("=" * 70)

    # 1. Initialize State (The Shared State Schema Anjali is building)
    incident_state = {
        "raw_logs": [],
        "active_alerts": [],
        "forensics_data": None,
        "mitigation_plan": None,
        "workflow_status": "INITIALIZED"
    }
    print(f"\n[LangGraph State] Initialized empty state: {incident_state['workflow_status']}")

    # 2. Execute Member 1's Module (Threat Hunter Agent)
    print("\n[Node 1: Threat Hunter] Running telemetry sweep...")
    threat_hunter = ThreatHunterAgent()
    threat_report = threat_hunter.run()
    
    # 3. Update LangGraph State with Threat Hunter Output
    incident_state["raw_logs"] = threat_report.get("alerts", [])
    incident_state["workflow_status"] = threat_report.get("status", "UNKNOWN")
    
    print(f"[Node 1: Threat Hunter] Completed with status: {incident_state['workflow_status']}")
    print(f"📦 Payload passed to State -> Total Alerts: {len(incident_state['raw_logs'])}")

    # 4. Conditional Routing Check (Simulating LangGraph's router.py)
    if incident_state["workflow_status"] == "ALERT_TRIGGERED":
        print("\n[Router] Threat detected! Routing state to Node 2 (Forensics Agent)...")
        
        # Simulate passing data to Member 2's Forensics Agent module
        mock_forensics_output = {
            "attack_classification": "Brute Force Attack",
            "ioc_extracted": incident_state["raw_logs"][0].get("source_ip", "192.168.1.105"),
            "historical_match": "Similar attack recorded 3 days ago in ChromaDB.",
            "recommended_action": "Block source IP and notify SOC admin."
        }
        incident_state["forensics_data"] = mock_forensics_output
        incident_state["workflow_status"] = "FORENSICS_COMPLETE"
        
        print("[Node 2: Forensics] Enriched state with historical ChromaDB context.")
    else:
        print("\n[Router] System clean. Workflow ending normal execution.")

    # 5. Final State Snapshot
    print("\n" + "=" * 70)
    print("🏁 FINAL LANGGRAPH WORKFLOW STATE SNAPSHOT")
    print("=" * 70)
    print(json.dumps(incident_state, indent=2))
    print("=" * 70)

if __name__ == "__main__":
    simulate_langgraph_workflow()