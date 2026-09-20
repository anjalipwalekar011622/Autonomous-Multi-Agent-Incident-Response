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

    def analyze_incident(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    
        print(
            f"\n[Forensics Agent] Investigating alert: "
            f"{raw_alert.get('event', 'Unknown Event')}"
        )

        # ---------------------------------------------------------
        # 1. Summarize alert for vector search
        # ---------------------------------------------------------
        event_summary = (
            f"{raw_alert.get('event')} "
            f"from source {raw_alert.get('source_ip', 'local')} "
            f"user {raw_alert.get('user', 'unknown')}"
        )

        # ---------------------------------------------------------
        # 2. Query ChromaDB for past incidents
        # ---------------------------------------------------------
        memory_results = self.memory.query_similar_incidents(event_summary)

        # ---------------------------------------------------------
        # 3. Generate existing forensic report
        # ---------------------------------------------------------
        final_report = ForensicsReportGenerator.generate_report(
            raw_alert,
            memory_results
        )

        # ---------------------------------------------------------
        # 4. Dynamic AI Mapping using Ollama
        # ---------------------------------------------------------
        print(
            "[Forensics Agent] Querying Ollama LLM "
            "for dynamic MITRE ATT&CK mapping..."
        )

        llm_mitre = self._query_ollama_for_mitre(raw_alert)

        if llm_mitre:
            final_report["mitre_attack"] = llm_mitre
        else:
            print(
             "[Forensics Agent] Reverting to static dictionary / default mapping."
            )

        # ---------------------------------------------------------
        # 5. Store incident in ChromaDB
        # ---------------------------------------------------------
        self.memory.store_incident(
            incident_id=final_report["incident_id"],
            summary=event_summary,
            metadata={
                "severity": raw_alert.get("severity", "Medium"),
                "technique_id": final_report["mitre_attack"].get(
                    "technique_id",
                    "UNKNOWN"
                )
            }
        )

        # ---------------------------------------------------------
        # 6. Remove duplicate historical matches
        # ---------------------------------------------------------
        historical_context = final_report.get(
            "historical_context",
            {}
        )

        matches = historical_context.get("matches", [])

        # Remove exact duplicate matches while preserving order
        if isinstance(matches, list):
            matches = list(dict.fromkeys(matches))

        # ---------------------------------------------------------
        # 7. Build COMMON INCIDENT JSON
        # ---------------------------------------------------------
        mitre = final_report.get("mitre_attack", {})

        common_report = {
            "incident_id": final_report["incident_id"],

            "investigation": {
                "agent": "ForensicsAgent",
                "status": "COMPLETED",

                "findings": [],

                "evidence": [
                    {
                        "event": raw_alert.get("event"),
                        "event_id": raw_alert.get("event_id"),
                        "source_ip": raw_alert.get("source_ip"),
                        "user": raw_alert.get("user"),
                        "severity": raw_alert.get("severity")
                    }
                ],

                "mitre_attack": {
                    "tactic": mitre.get("tactic"),
                    "technique_id": mitre.get("technique_id"),
                    "technique_name": mitre.get("name"),
                    "confidence": mitre.get("confidence"),
                    "needs_review": mitre.get("confidence") is None
                },

                "historical_context": {
                    "seen_before": historical_context.get(
                        "seen_before",
                        len(matches) > 0
                    ),
                    "matches": matches,
                    "similarity": historical_context.get("similarity")
                },

                "attack_pattern": None,

                "recommended_action": final_report.get(
                    "recommended_action"
                )
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
    Anjali's Orchestrator will call this function inside the StateGraph.
    """
    agent = ForensicsAgent()
    raw_alert = state.get("raw_alert", {})
    
    # Run forensic investigation
    forensic_report = agent.analyze_incident(raw_alert)
    
    # Update state for LangGraph routing
    state["forensic_report"] = forensic_report
    state["current_step"] = "FORENSICS_COMPLETED"
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