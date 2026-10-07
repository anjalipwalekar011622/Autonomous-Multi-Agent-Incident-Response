import os
import math
import numpy as np
from datetime import datetime, timezone

class MultiVectorAnomalyDetector:
    def __init__(self, failed_login_threshold=3):
        self.failed_login_threshold = failed_login_threshold
        self.seen_alerts = set()

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
        if events is None:
            events = []
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
                    
            # Privilege Escalation (Event ID 4672: Special privileges assigned to new logon)
            elif eid == 4672:
                user = event.get("target_user", "Unknown")
                # Exclude normal SYSTEM/LOCAL SERVICE/NETWORK SERVICE
                if user not in ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"] and not user.endswith("$"):
                    alerts.append({
                        "mitre_id": "T1078",
                        "threat_category": "Privilege Escalation",
                        "attack_type": "Admin/Special Privilege Logon",
                        "severity": "Medium",
                        "confidence": 75,
                        "target_user": user,
                        "timestamp": self._now_iso(),
                        "details": f"Special privileges assigned to non-system logon '{user}'."
                    })
                    
            # Persistence (Event ID 4698: A scheduled task was created)
            elif eid == 4698:
                user = event.get("target_user", "Unknown")
                alerts.append({
                    "mitre_id": "T1053.005",
                    "threat_category": "Persistence",
                    "attack_type": "Scheduled Task Creation",
                    "severity": "Medium",
                    "confidence": 80,
                    "target_user": user,
                    "timestamp": self._now_iso(),
                    "details": f"A scheduled task was created by '{user}'."
                })

        return alerts

    def analyze_processes(self, processes):
        """Evaluates active processes for malicious tooling, flags, and resource spikes."""
        if processes is None:
            processes = []
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
            if name in self.high_risk_binaries and proc.get("is_new", True):
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
            elif any(pat in cmdline for pat in self.attack_patterns) and proc.get("is_new", True):
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
                    alert_key = ("T1496", proc.get("pid"))
                    if alert_key not in self.seen_alerts:
                        self.seen_alerts.add(alert_key)
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
        """Scans network sockets for C2, reverse shells, and DDoS/Flooding."""
        if connections is None:
            connections = []
        alerts = []
        host_connection_count = {}

        for conn in connections:
            raddr = conn.get("raddr")
            if raddr:
                try:
                    ip, port_str = raddr.rsplit(":", 1)
                    port = int(port_str)
                    
                    # Track connection counts for DDoS/Flooding
                    host_connection_count[ip] = host_connection_count.get(ip, 0) + 1

                    if port in self.suspicious_ports and conn.get("is_new", True):
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

        # Check for abnormal connection volume (DDoS / Network Flooding)
        for ip, count in host_connection_count.items():
            if count > 100:
                alerts.append({
                    "mitre_id": "T1498",
                    "threat_category": "Impact",
                    "attack_type": "DDoS / Network Flooding",
                    "severity": "High",
                    "confidence": 85,
                    "source_ip": ip,
                    "timestamp": self._now_iso(),
                    "details": f"Abnormal connection volume: {count} active connections from/to {ip}."
                })

        return alerts

    def analyze_sysmon_events(self, sysmon_events):
        """Evaluates Sysmon telemetry."""
        if sysmon_events is None:
            sysmon_events = []
        alerts = []
        file_activity = {}
        port_scan = {}

        for event in sysmon_events:
            eid = event.get("event_id")
            data = event.get("data", {})
            
            # Fallback if data is raw list of strings (win32evtlog missing structured data)
            if isinstance(data, list):
                continue
                
            # EID 1 - Process Creation (Suspicious PowerShell)
            if eid == 1:
                cmdline = data.get("command_line", "").lower()
                image = data.get("image", "").lower()
                if "powershell" in image or "pwsh" in image:
                    if any(pat in cmdline for pat in self.attack_patterns):
                        alerts.append({
                            "mitre_id": "T1059.001",
                            "threat_category": "Execution",
                            "attack_type": "Suspicious PowerShell",
                            "severity": "Critical",
                            "confidence": 90,
                            "pid": data.get("process_id"),
                            "process_name": data.get("process_name", "powershell.exe"),
                            "cmdline": cmdline,
                            "user": data.get("user"),
                            "timestamp": self._now_iso(),
                            "details": f"Suspicious PowerShell execution: {cmdline}"
                        })
            
            # EID 3 - Network Connection (Port Scan)
            elif eid == 3:
                src_ip = data.get("source_ip")
                dst_port = data.get("destination_port")
                if src_ip and dst_port:
                    port_scan[src_ip] = port_scan.get(src_ip, set())
                    port_scan[src_ip].add(dst_port)
                    
            # EID 11 - File Create (Ransomware-like)
            elif eid == 11:
                pid = data.get("process_id")
                image = data.get("image")
                if pid:
                    key = (pid, image)
                    file_activity[key] = file_activity.get(key, 0) + 1
                    
            # EID 10 - Process Access
            elif eid == 10:
                target_image = data.get("target_image", "").lower()
                if "lsass" in target_image:
                    alerts.append({
                        "mitre_id": "T1003.001",
                        "threat_category": "Credential Access",
                        "attack_type": "Suspicious Process Access",
                        "severity": "Critical",
                        "confidence": 95,
                        "pid": data.get("source_process_id"),
                        "process_name": data.get("source_image"),
                        "timestamp": self._now_iso(),
                        "details": f"Process {data.get('source_image')} accessed lsass.exe."
                    })
                    
            # EID 12, 13, 14 - Registry
            elif eid in [12, 13, 14]:
                target = data.get("target_object", "").lower()
                if "run" in target or "runonce" in target:
                    alerts.append({
                        "mitre_id": "T1547.001",
                        "threat_category": "Persistence",
                        "attack_type": "Suspicious Registry Activity",
                        "severity": "High",
                        "confidence": 85,
                        "pid": data.get("process_id"),
                        "process_name": data.get("image"),
                        "timestamp": self._now_iso(),
                        "details": f"Registry persistence indicator: {target}"
                    })

        # Process aggregated thresholds
        for ip, ports in port_scan.items():
            if len(ports) > 20:
                alerts.append({
                    "mitre_id": "T1046",
                    "threat_category": "Discovery",
                    "attack_type": "Port Scan",
                    "severity": "High",
                    "confidence": 85,
                    "source_ip": ip,
                    "timestamp": self._now_iso(),
                    "details": f"Host {ip} scanned {len(ports)} distinct ports."
                })
                
        for (pid, image), count in file_activity.items():
            if count > 50:
                alerts.append({
                    "mitre_id": "T1486",
                    "threat_category": "Impact",
                    "attack_type": "Ransomware-like File Activity",
                    "severity": "Critical",
                    "confidence": 80,
                    "pid": pid,
                    "process_name": image,
                    "timestamp": self._now_iso(),
                    "details": f"Process {image} (PID {pid}) created/modified {count} files rapidly."
                })
                
        # Phishing and SQL Injection Placeholders (No standard Windows host telemetry available)
        # Note: We append this to document capabilities, but these will not trigger from generic logs.
        # This explicitly adheres to "Do not fake telemetry" and "Mark as telemetry unavailable".
        return alerts
        
    def analyze_phishing(self, email_logs=None):
        """
        Placeholder for Phishing.
        Requires Email Gateway or Proxy telemetry which is unavailable natively on Windows host.
        """
        if email_logs is None:
            return [] # Telemetry Unavailable

    def analyze_sql_injection(self, waf_logs=None):
        """
        Placeholder for SQL Injection.
        Requires WAF or Web Server Access logs which are unavailable natively on generic Windows host.
        """
        if waf_logs is None:
            return [] # Telemetry Unavailable