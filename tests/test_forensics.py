import unittest
from agents.forensics.forensics import ForensicsAgent
from agents.forensics.report_generator import ForensicsReportGenerator

class TestForensicsModule(unittest.TestCase):
    def setUp(self):
        """Runs before each test to initialize a fresh agent instance."""
        self.agent = ForensicsAgent()

    def test_report_generator_mitre_mapping(self):
        """Test if Windows Event ID 4625 maps correctly to MITRE T1110."""
        sample_alert = {"event_id": "4625", "event": "Failed Logon"}
        mock_memory = {"documents": [[]]}
        
        report = ForensicsReportGenerator.generate_report(sample_alert, mock_memory)
        
        self.assertEqual(report["mitre_attack"]["technique_id"], "T1110")
        self.assertEqual(report["mitre_attack"]["tactic"], "Credential Access")

    def test_forensics_agent_execution(self):
        """Test the end-to-end analyze_incident function."""

        sample_alert = {
            "event": "Suspicious PowerShell Execution",
            "event_id": "4688",
            "source_ip": "10.0.0.15",
            "user": "System_Account",
            "severity": "Critical"
        }

        report = self.agent.analyze_incident(sample_alert)

        # Common incident structure
        self.assertIn("incident_id", report)
        self.assertIn("investigation", report)
        self.assertIn("memory", report)

        # ForensicsAgent section
        self.assertEqual(
            report["investigation"]["agent"],
            "ForensicsAgent"
        )

        self.assertEqual(
            report["investigation"]["status"],
            "COMPLETED"
        )

        # MITRE section
        self.assertIn(
            "mitre_attack",
            report["investigation"]
        )

        # Historical context
        self.assertIn(
            "historical_context",
            report["investigation"]
        )

        # Recommended action
        self.assertIn(
            "recommended_action",
            report["investigation"]
        )

if __name__ == "__main__":
    unittest.main()