class AnomalyDetector:
    def __init__(self, failed_login_threshold=3):
        self.threshold = failed_login_threshold

    def detect_brute_force(self, events):
        """Identifies brute-force authentication attempts."""
        failed_counts = {}
        alerts = []

        for event in events:
            # Event ID 4625 indicates a failed logon attempt in Windows Event Logs
            if event.get("event_id") == 4625 or event.get("status") == "FAILED":
                ip = event.get("source_ip", "0.0.0.0")
                user = event.get("target_user", "Unknown")
                key = (ip, user)

                failed_counts[key] = failed_counts.get(key, 0) + 1

                if failed_counts[key] >= self.threshold:
                    alerts.append({
                        "event": "Multiple Failed Login",
                        "attack_type": "Brute Force",
                        "severity": "High",
                        "confidence": 92,
                        "source_ip": ip,
                        "target_user": user,
                        "attempt_count": failed_counts[key]
                    })
        return alerts