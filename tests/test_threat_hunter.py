import unittest
from agents.threat_hunter.threat_hunter import ThreatHunterAgent

class TestThreatHunter(unittest.TestCase):
    def setUp(self):
        self.agent = ThreatHunterAgent()

    def test_detection(self):
        result = self.agent.run()
        self.assertEqual(result["status"], "ALERT_TRIGGERED")
        self.assertEqual(result["alert"]["attack_type"], "Brute Force")
        self.assertEqual(result["alert"]["source_ip"], "192.168.1.105")

if __name__ == "__main__":
    unittest.main()