import json
import os
import psutil

class LogParser:
    def __init__(self, sample_log_path="tests/sample_logs.json"):
        self.sample_log_path = sample_log_path

    def load_mock_logs(self):
        """Loads events from mock JSON data or returns fallback events."""
        if os.path.exists(self.sample_log_path):
            with open(self.sample_log_path, "r", encoding="utf-8") as f:
                return json.load(f)
        
        # In-memory fallback if no test file exists yet
        return [
            {"event_id": 4625, "status": "FAILED", "target_user": "Administrator", "source_ip": "192.168.1.105"},
            {"event_id": 4625, "status": "FAILED", "target_user": "Administrator", "source_ip": "192.168.1.105"},
            {"event_id": 4625, "status": "FAILED", "target_user": "Administrator", "source_ip": "192.168.1.105"},
            {"event_id": 4624, "status": "SUCCESS", "target_user": "Administrator", "source_ip": "192.168.1.105"}
        ]

    def get_running_processes(self):
        """Collects running system processes."""
        process_list = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                process_list.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return process_list