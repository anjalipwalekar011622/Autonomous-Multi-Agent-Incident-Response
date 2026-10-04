import json
import requests
from agents.forensics.memory import IncidentMemory
from agents.forensics.report_generator import ForensicsReportGenerator
from typing import Dict, Any

class ForensicsAgent:
    def __init__(self, ollama_model: str = "llama3"):
        self.memory = IncidentMemory()
        self.ollama_model = ollama_model
        self.ollama_url = "http://localhost:11434/api/generate"

    def analyze_incident(self, raw_alert: Dict[str, Any], incident_id: str = None) -> Dict[str, Any]:
        """
        Main entry point for LangGraph Orchestrator to trigger Forensics Analysis.
        """
        print(f"\n[Forensics Agent] Investigating alert: {raw_alert.get('event', 'Unknown Event')}")

        # 1. Summarize alert for vector search
        event_summary = f"{raw_alert.get('event')} from source {raw_alert.get('source_ip', 'local')} user {raw_alert.get('user', 'unknown')}"

        # 2. Query ChromaDB for past incidents
        memory_results = self.memory.query_similar_incidents(event_summary)

        # 3. Generate baseline Forensic Report
        final_report = ForensicsReportGenerator.generate_report(raw_alert, memory_results)

        # 4. Dynamic AI Mapping: Query Ollama LLM for real-time MITRE ATT&CK reasoning
        print("[Forensics Agent] Querying Ollama LLM for dynamic MITRE ATT&CK mapping...")
        llm_mitre = self._query_ollama_for_mitre(raw_alert)
        if llm_mitre:
            final_report["mitre_attack"] = llm_mitre
        else:
            print("[Forensics Agent] Reverting to static dictionary / default mapping.")

        # 5. Save this incident into ChromaDB memory for future detection.
        #    Prefer the orchestrator-assigned incident_id so the memory record
        #    stays aligned with the canonical state; fall back to the
        #    report-generated UUID only when called standalone.
        memory_id = incident_id or final_report["incident_id"]
        self.memory.store_incident(
            incident_id=memory_id,
            summary=event_summary,
            metadata={
                "severity": raw_alert.get("severity", "Medium"),
                "technique_id": final_report["mitre_attack"].get("technique_id", "UNKNOWN")
            }
        )

        # 6. Build canonical output shape (investigation + memory).
        #    evidence must be List[str] to match Investigation TypedDict.
        mitre = final_report.get("mitre_attack", {})
        historical = final_report.get("historical_context", {})
        matches = historical.get("matches", [])
        if isinstance(matches, list):
            matches = list(dict.fromkeys(matches))  # deduplicate, preserve order

        common_report = {
            "investigation": {
                "agent": "ForensicsAgent",
                "status": "COMPLETED",
                "findings": [],
                "evidence": [
                    f"event={raw_alert.get('event')} "
                    f"event_id={raw_alert.get('event_id')} "
                    f"source_ip={raw_alert.get('source_ip')} "
                    f"user={raw_alert.get('user')} "
                    f"severity={raw_alert.get('severity')}"
                ],
                "mitre_attack": {
                    "tactic": mitre.get("tactic"),
                    "technique_id": mitre.get("technique_id"),
                    "technique_name": mitre.get("name"),
                    "confidence": mitre.get("confidence"),
                    "needs_review": mitre.get("confidence") is None
                },
                "historical_context": {
                    "seen_before": historical.get("seen_before", len(matches) > 0),
                    "matches": matches,
                    "similarity": historical.get("similarity")
                },
                "attack_pattern": None,
                "recommended_action": final_report.get("recommended_action")
            },
            "memory": {
                "stored": True,
                "historical_retrieval_completed": True,
                "vector_id": None
            }
        }

        return common_report

    def _query_ollama_for_mitre(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Queries local Ollama instance to dynamically extract MITRE Tactic and Technique.
        """
        prompt = f"""
        You are a cybersecurity Digital Forensics AI.
        Analyze this raw alert: {json.dumps(raw_alert)}
        Return ONLY a JSON object mapping it to official MITRE ATT&CK in this exact format:
        {{"tactic": "<Tactic>", "technique_id": "<Technique_ID>", "name": "<Technique_Name>"}}
        """
        try:
            response = requests.post(
                self.ollama_url,
                json={"model": self.ollama_model, "prompt": prompt, "stream": False, "format": "json"},
                timeout=30
            )
            if response.status_code == 200:
                result_text = response.json().get("response", "")
                return json.loads(result_text)
        except Exception as e:
            print(f"[Forensics Agent] Ollama query bypassed or failed: {e}")
        return None

# --- LANGGRAPH NODE WRAPPER ---
def forensics_node(state: dict) -> dict:
    """
    LangGraph Node Wrapper Function.
    Reads from and writes to the canonical IncidentState contract:
      - reads:  state["event"]["raw_data"]  and  state["incident_id"]
      - writes: state["investigation"]       and  state["memory"]
    All other state keys are left untouched.
    """
    agent = ForensicsAgent()

    # Read raw event from the canonical state location
    raw_alert = state.get("event", {}).get("raw_data", {})

    # Run forensic investigation, preserving the orchestrator's incident_id
    forensic_report = agent.analyze_incident(
        raw_alert,
        incident_id=state.get("incident_id")
    )

    # Write ONLY the two keys Forensics owns in the canonical IncidentState
    state["investigation"] = forensic_report["investigation"]
    state["memory"]        = forensic_report["memory"]
    return state


if __name__ == "__main__":
    agent = ForensicsAgent()
    
    sample_alert = {
        "event": "Custom Obfuscated Encoded PowerShell Execution",
        "event_id": "9999",
        "source_ip": "10.0.0.88",
        "user": "System_Service",
        "severity": "Critical"
    }

    print("--- RUNNING FORENSICS AGENT DIRECT TEST ---")
    res = agent.analyze_incident(sample_alert)
    
    print("\n--- COMPLETE ENRICHED FORENSIC REPORT ---")
    print(json.dumps(res, indent=2))  # Pretty prints the complete JSON output!