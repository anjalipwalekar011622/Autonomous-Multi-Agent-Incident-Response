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
    """
    Windows Telemetry Collector.
    Sysmon Readiness:
    - Event ID 1: Process Creation
    - Event ID 3: Network Connection
    - Event ID 10: Process Access
    - Event ID 11: File Creation
    - Event IDs 12/13/14: Registry activity
    """
    def __init__(self, sample_log_path="tests/sample_logs.json"):
        self.sample_log_path = sample_log_path
        self.sysmon_mock_path = "tests/sysmon_mock.json"
        self.server = 'localhost'
        self.log_type = 'Security'
        self.seen_events = set()
        self.seen_processes = set()
        self.seen_connections = set()


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
                timestamp_str = record.TimeGenerated.Format()
                
                event_key = (event_id, timestamp_str)
                if event_key in self.seen_events:
                    continue
                self.seen_events.add(event_key)
                
                events.append({
                    "event_id": event_id,
                    "timestamp": timestamp_str,
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

    def read_sysmon_events(self, max_records=50):
        """Adapter for Sysmon Events (Microsoft-Windows-Sysmon/Operational)."""
        events = []
        if not WINDOWS_LOGS_AVAILABLE:
            return self.load_mock_sysmon_logs()

        try:
            # We attempt to use EvtQuery for modern event logs if supported, otherwise fallback to mock
            # as classic OpenEventLog cannot read Operational channels easily.
            query = win32evtlog.EvtQuery("Microsoft-Windows-Sysmon/Operational", win32evtlog.EvtQueryReverseDirection, "*")
            
            # This is a stub for the actual XML parsing of EvtNext results.
            # In a full deployment, we'd iterate EvtNext(query), call EvtRender, and parse the XML.
            # For this prototype, we rely on the mock fixtures if EvtQuery fails (e.g. Sysmon not installed).
            pass
        except Exception:
            return self.load_mock_sysmon_logs()
            
        return events

    def load_mock_sysmon_logs(self):
        """Fallback mock Sysmon stream for testing."""
        if os.path.exists(self.sysmon_mock_path):
            with open(self.sysmon_mock_path, "r", encoding="utf-8") as f:
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
                
                proc_key = (info.get('pid'), info.get('create_time'))
                info['is_new'] = proc_key not in self.seen_processes
                self.seen_processes.add(proc_key)
                
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
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
                    conn_key = (conn.pid, laddr, raddr, conn.status)
                    is_new = conn_key not in self.seen_connections
                    self.seen_connections.add(conn_key)
                    
                    connections.append({
                        "fd": conn.fd,
                        "family": conn.family,
                        "type": conn.type,
                        "laddr": laddr,
                        "raddr": raddr,
                        "status": conn.status,
                        "pid": conn.pid,
                        "is_new": is_new
                    })
        except (psutil.AccessDenied, Exception):
            pass
        return connections