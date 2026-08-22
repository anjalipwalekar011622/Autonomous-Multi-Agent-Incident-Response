from agents.threat_hunter.log_parser import LogParser
from agents.threat_hunter.anomaly_detector import AnomalyDetector

class ThreatHunterAgent:
    def __init__(self):
        self.parser = LogParser()
        self.detector = AnomalyDetector()

    def run(self):
        """Runs log ingestion and rule evaluation, returning an alert payload."""
        logs = self.parser.load_mock_logs()
        alerts = self.detector.detect_brute_force(logs)

        if alerts:
            return {
                "status": "ALERT_TRIGGERED",
                "alert": alerts[0]
            }
        return {"status": "CLEAN", "alert": None}

if __name__ == "__main__":
    agent = ThreatHunterAgent()
    result = agent.run()
    print("Threat Hunter Execution Result:")
    print(result)