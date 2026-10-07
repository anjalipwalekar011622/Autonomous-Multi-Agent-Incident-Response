"""
Future Telemetry Architecture Adapters
This file documents the interfaces and expected data sources for future detection capabilities.
Do NOT fabricate these events in the current implementation.

1. PHISHING
Expected future source:
- Email gateway logs
- URL/proxy telemetry
- Identity/login telemetry
"""

class PhishingTelemetryAdapter:
    def fetch_email_logs(self):
        """Connects to email gateway (e.g. Exchange, Proofpoint)."""
        pass

    def fetch_url_telemetry(self):
        """Connects to proxy logs to check clicked links."""
        pass


"""
2. SQL INJECTION
Expected future source:
- Web server logs (IIS, Nginx)
- Application logs
- Database query logs
"""

class SQLInjectionTelemetryAdapter:
    def fetch_web_logs(self):
        """Connects to WAF or web server logs."""
        pass


"""
3. DDOS
Expected future source:
- Network flow (NetFlow/sFlow)
- Packet/traffic volume metrics
- Firewall/edge telemetry
"""

class DDoSTelemetryAdapter:
    def fetch_network_flow(self):
        """Ingests high-volume network flow metrics."""
        pass


"""
4. CREDENTIAL THEFT
Expected future source:
- Process access (Sysmon Event ID 10 on lsass.exe)
- Endpoint telemetry
- Memory/security telemetry
"""

class CredentialTheftAdapter:
    def fetch_lsass_access_events(self):
        """Monitors advanced process access patterns against LSASS."""
        pass


"""
5. PERSISTENCE
Expected future source:
- Sysmon registry events (Run keys, services)
- Scheduled task telemetry (Event ID 4698)
- Service creation telemetry (Event ID 7045)
"""

class PersistenceTelemetryAdapter:
    def fetch_scheduled_tasks(self):
        """Monitors creation of malicious scheduled tasks."""
        pass


"""
6. PRIVILEGE ESCALATION
Expected future source:
- Windows security events (Token manipulation)
- Token/elevation telemetry
- Process/security context
"""

class PrivilegeEscalationAdapter:
    def fetch_token_manipulation_events(self):
        """Monitors for token stealing or unexpected privilege elevation."""
        pass
