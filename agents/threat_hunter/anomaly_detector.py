import os
import math
import numpy as np
from datetime import datetime, timezone

class MultiVectorAnomalyDetector:
    def __init__(self, failed_login_threshold=3):
        self.failed_login_threshold = failed_login_threshold

        # High-risk utility binaries (MITRE ATT&CK Discovery / Execution)
        self.high_risk_binaries = {
            "mimikatz.exe", "nc.exe", "netcat.exe", "nmap.exe", "whoami.exe",
            "vssadmin.exe", "certutil.exe", "psexec.exe", "procdump.exe", 
            "lazagne.exe", "bloodhound.exe", "sharphound.exe"
        }

        # Common C2 / Reverse Shell Ports
        self.suspicious_ports = {4444, 1337, 6667, 8888, 9001, 31337, 8080}

        # Malicious CLI heuristics
        self.attack_patterns = [
            "downloadstring", "invoke-expression", "iex", "-enc", "-encodedcommand",
            "bypass", "vssadmin delete shadows", "wbadmin delete catalog",
            "net user /add", "net localgroup administrators"
        ]

    def _now_iso(self):
        return datetime.now(timezone.utc).isoformat()

    def calculate_entropy(self, data: bytes) -> float:
        """Calculates Shannon Entropy to detect encrypted or packed payloads."""
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def analyze_event_logs(self, events):
        """Evaluates authentication and event telemetry."""
        alerts = []
        failed_logins = {}

        for event in events:
            eid = event.get("event_id")
            if eid == 4625 or event.get("status") == "FAILED":
                ip = event.get("source_ip", "127.0.0.1")
                user = event.get("target_user", "Unknown")
                key = (ip, user)
                failed_logins[key] = failed_logins.get(key, 0) + 1

                if failed_logins[key] >= self.failed_login_threshold:
                    alerts.append({
                        "mitre_id": "T1110",
                        "threat_category": "Credential Access",
                        "attack_type": "Brute Force Authentication",
                        "severity": "High",
                        "confidence": 95,
                        "source_ip": ip,
                        "target_user": user,
                        "timestamp": self._now_iso(),
                        "details": f"{failed_logins[key]} failed logons detected for '{user}' from {ip}."
                    })
        return alerts

    def analyze_processes(self, processes):
        """Evaluates active processes for malicious tooling, flags, and resource spikes."""
        alerts = []
        cpu_metrics = []

        for proc in processes:
            name = (proc.get("name") or "").lower()
            exe_path = (proc.get("exe") or "").lower()
            cmdline = " ".join(proc.get("cmdline") or []).lower()
            pid = proc.get("pid")
            user = proc.get("username", "System")
            cpu = proc.get("cpu_percent", 0.0)
            cpu_metrics.append(cpu)

            # Check 1: Known adversary tools
            if name in self.high_risk_binaries:
                alerts.append({
                    "mitre_id": "T1059",
                    "threat_category": "Execution",
                    "attack_type": f"Unauthorized Binary ({name})",
                    "severity": "High",
                    "confidence": 94,
                    "pid": pid,
                    "process_name": name,
                    "target_user": user,
                    "timestamp": self._now_iso(),
                    "details": f"High-risk utility '{name}' executed."
                })

            # Check 2: Obfuscated or bypass arguments
            elif any(pat in cmdline for pat in self.attack_patterns):
                alerts.append({
                    "mitre_id": "T1059.001",
                    "threat_category": "Defense Evasion",
                    "attack_type": "Obfuscated Command Execution",
                    "severity": "Critical",
                    "confidence": 92,
                    "pid": pid,
                    "process_name": name,
                    "cmdline": cmdline,
                    "target_user": user,
                    "timestamp": self._now_iso(),
                    "details": f"Suspicious script execution: {cmdline}"
                })

        # Check 3: Statistical CPU Baseline Anomaly (Cryptomining / Ransomware Spikes)
        if len(cpu_metrics) > 5:
            mean = np.mean(cpu_metrics)
            std = np.std(cpu_metrics)
            for proc in processes:
                if std > 0 and (proc.get("cpu_percent", 0.0) - mean) / std > 3.0:
                    alerts.append({
                        "mitre_id": "T1496",
                        "threat_category": "Impact",
                        "attack_type": "Resource Hijacking (CPU Anomaly)",
                        "severity": "Medium",
                        "confidence": 80,
                        "pid": proc.get("pid"),
                        "process_name": proc.get("name"),
                        "timestamp": self._now_iso(),
                        "details": f"Process consuming anomalous CPU ({proc.get('cpu_percent')}% vs baseline {mean:.1f}%)."
                    })

        return alerts

    def analyze_network_connections(self, connections):
        """Scans network sockets for C2 and reverse shells."""
        alerts = []

        for conn in connections:
            raddr = conn.get("raddr")
            if raddr:
                try:
                    ip, port_str = raddr.rsplit(":", 1)
                    port = int(port_str)

                    if port in self.suspicious_ports:
                        alerts.append({
                            "mitre_id": "T1071",
                            "threat_category": "Command and Control",
                            "attack_type": "Suspicious Port Activity",
                            "severity": "Critical",
                            "confidence": 96,
                            "pid": conn.get("pid"),
                            "destination_ip": ip,
                            "destination_port": port,
                            "timestamp": self._now_iso(),
                            "details": f"Connection established to suspicious port {port} on {ip}."
                        })
                except (ValueError, IndexError):
                    continue

        return alerts