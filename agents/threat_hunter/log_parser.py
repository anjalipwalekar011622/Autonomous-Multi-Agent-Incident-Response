import os
import json
import psutil
from datetime import datetime

# Graceful import for non-Windows environments
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    WINDOWS_LOGS_AVAILABLE = True
except ImportError:
    WINDOWS_LOGS_AVAILABLE = False


class LogParser:
    def __init__(self, sample_log_path="tests/sample_logs.json"):
        self.sample_log_path = sample_log_path
        self.server = 'localhost'
        self.log_type = 'Security'

    def read_live_windows_events(self, max_records=25):
        """Reads live Windows Security Event logs via pywin32."""
        events = []
        if not WINDOWS_LOGS_AVAILABLE:
            return self.load_mock_logs()

        try:
            hand = win32evtlog.OpenEventLog(self.server, self.log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for record in records[:max_records]:
                event_id = record.EventID & 0x1FFFFFFF
                events.append({
                    "event_id": event_id,
                    "timestamp": record.TimeGenerated.Format(),
                    "source_name": record.SourceName,
                    "event_type": record.EventType,
                    "data": record.StringInserts or []
                })
            win32evtlog.CloseEventLog(hand)
        except Exception:
            return self.load_mock_logs()

        return events

    def load_mock_logs(self):
        """Fallback mock log stream."""
        if os.path.exists(self.sample_log_path):
            with open(self.sample_log_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def get_process_telemetry(self):
        """Deep scan on all active running processes."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                info = proc.info
                # Add CPU & Memory usage context
                info['cpu_percent'] = proc.cpu_percent(interval=None)
                info['memory_mb'] = proc.memory_info().rss / (1024 * 1024)
                processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return processes

    def get_network_sockets(self):
        """Captures active inbound and outbound network connections."""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                    connections.append({
                        "fd": conn.fd,
                        "family": conn.family,
                        "type": conn.type,
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status,
                        "pid": conn.pid
                    })
        except (psutil.AccessDenied, Exception):
            pass
        return connections