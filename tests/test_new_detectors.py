from agents.threat_hunter.anomaly_detector import MultiVectorAnomalyDetector

def test_ddos_network_flooding_fixture():
    """Test DDoS detection (safe synthetic fixture)"""
    detector = MultiVectorAnomalyDetector()
    connections = []
    # Simulate 101 connections from the same IP
    for i in range(101):
        connections.append({"raddr": "192.168.1.50:80", "is_new": True})
    
    alerts = detector.analyze_network_connections(connections)
    assert any(a["attack_type"] == "DDoS / Network Flooding" for a in alerts)

def test_privilege_escalation_fixture():
    """Test Privilege Escalation detection (safe synthetic fixture)"""
    detector = MultiVectorAnomalyDetector()
    events = [
        {"event_id": 4672, "target_user": "hacker_bob"}
    ]
    alerts = detector.analyze_event_logs(events)
    assert any(a["attack_type"] == "Admin/Special Privilege Logon" for a in alerts)

def test_persistence_scheduled_task_fixture():
    """Test Scheduled Task creation detection (safe synthetic fixture)"""
    detector = MultiVectorAnomalyDetector()
    events = [
        {"event_id": 4698, "target_user": "system_updater"}
    ]
    alerts = detector.analyze_event_logs(events)
    assert any(a["attack_type"] == "Scheduled Task Creation" for a in alerts)

def test_telemetry_unavailable_phishing_sqli():
    """Verify phishing and SQLi are marked as telemetry unavailable"""
    detector = MultiVectorAnomalyDetector()
    assert detector.analyze_phishing() == []
    assert detector.analyze_sql_injection() == []

if __name__ == "__main__":
    test_ddos_network_flooding_fixture()
    test_privilege_escalation_fixture()
    test_persistence_scheduled_task_fixture()
    test_telemetry_unavailable_phishing_sqli()
    print("New detectors synthetic fixtures passed.")
