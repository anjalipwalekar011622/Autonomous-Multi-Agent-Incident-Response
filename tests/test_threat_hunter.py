import unittest
from agents.threat_hunter.anomaly_detector import MultiVectorAnomalyDetector

class TestMultiVectorAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.detector = MultiVectorAnomalyDetector()

    def test_brute_force_detection(self):
        # Simulate 3 failed logon events (Event ID 4625)
        mock_events = [
            {"event_id": 4625, "source_ip": "192.168.1.105", "target_user": "Administrator"},
            {"event_id": 4625, "source_ip": "192.168.1.105", "target_user": "Administrator"},
            {"event_id": 4625, "source_ip": "192.168.1.105", "target_user": "Administrator"}
        ]
        alerts = self.detector.analyze_event_logs(mock_events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["mitre_id"], "T1110")
        self.assertEqual(alerts[0]["severity"], "High")

    def test_malicious_process_detection(self):
        # Simulate a high-risk binary execution
        mock_processes = [
            {"pid": 1234, "name": "mimikatz.exe", "cmdline": ["mimikatz.exe"], "username": "SYSTEM"}
        ]
        alerts = self.detector.analyze_processes(mock_processes)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["mitre_id"], "T1059")

    def test_clean_system_behavior(self):
        # Simulate normal, clean activity
        mock_events = [{"event_id": 4624, "source_ip": "127.0.0.1", "target_user": "User"}]
        alerts = self.detector.analyze_event_logs(mock_events)
        self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()