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

        # 4. Fallback / Enhancement: If MITRE mapping is defaulted, ask Ollama LLM dynamically
        if final_report["mitre_attack"]["technique_id"] == "T1204":
            print("[Forensics Agent] Standard dictionary match missing. Querying Ollama LLM for dynamic MITRE reasoning...")
            llm_mitre = self._query_ollama_for_mitre(raw_alert)
            if llm_mitre:
                final_report["mitre_attack"] = llm_mitre

        # 5. Save this incident into ChromaDB memory for future detection
        self.memory.store_incident(
            incident_id=final_report["incident_id"],
            summary=event_summary,
            metadata={
                "severity": raw_alert.get("severity", "Medium"),
                "technique_id": final_report["mitre_attack"]["technique_id"]
            }
        )

        return final_report

    def _query_ollama_for_mitre(self, raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Queries local Ollama instance to dynamically extract MITRE Tactic and Technique.
        """
        prompt = f"""
        You are a cybersecurity Digital Forensics AI.
        Analyze this raw alert: {json.dumps(raw_alert)}
        Return ONLY a JSON object mapping it to MITRE ATT&CK in this format:
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

if __name__ == "__main__":
    agent = ForensicsAgent()
    
    # Test 1: Standard event (uses hardcoded fast-path)
    sample_alert_known = {
        "event": "Multiple Failed Logins",
        "event_id": "4625",
        "source_ip": "192.168.1.50",
        "user": "Admin",
        "severity": "High"
    }
    
    # Test 2: Custom/Unknown event (triggers Ollama LLM reasoning)
    sample_alert_unknown = {
        "event": "Custom Obfuscated Encoded PowerShell Execution",
        "event_id": "9999",
        "source_ip": "10.0.0.88",
        "user": "System_Service",
        "severity": "Critical"
    }

    print("--- RUNNING TEST 1 (Standard Dictionary Match) ---")
    res1 = agent.analyze_incident(sample_alert_known)
    print(res1["mitre_attack"])

    print("\n--- RUNNING TEST 2 (Dynamic Ollama AI Reasoning) ---")
    res2 = agent.analyze_incident(sample_alert_unknown)
    print(res2["mitre_attack"])