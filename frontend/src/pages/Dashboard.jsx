import React, { useCallback, useState } from 'react';
import ThreatCard from '../components/ThreatCard';
import {
  Activity,
  Search,
  Database,
  GitBranch,
  ShieldAlert,
  Play,
  Trash2,
  Loader2,
  Fingerprint,
} from 'lucide-react';

import AgentLogs from '../components/AgentLogs';
import { triggerIncident } from '../services/api';
import '../styles/app.css';

// ---------------------------------------------------------------------------
// Static config — agent identities are colour-coded once here and reused
// everywhere (agent cards + log lines) so an operator can trace a log entry
// back to the agent that produced it at a glance.
// ---------------------------------------------------------------------------
const AGENTS = [
  {
    id: 'threat_hunter',
    name: 'Threat Hunter',
    description: 'Scans telemetry and flags indicators of compromise.',
    icon: Search,
    color: '#f2a93b',
  },
  {
    id: 'forensics',
    name: 'Forensics Engine',
    description: 'Correlates findings against the ChromaDB memory store.',
    icon: Database,
    color: '#35d0ba',
  },
  {
    id: 'orchestrator',
    name: 'LangGraph Orchestrator',
    description: 'Routes state between agents and decides next actions.',
    icon: GitBranch,
    color: '#8b7fd6',
  },
  {
    id: 'mitigation',
    name: 'Mitigation Engine',
    description: 'Executes containment and remediation actions.',
    icon: ShieldAlert,
    color: '#ff6b6b',
  },
];

const now = () => new Date().toLocaleTimeString('en-US', { hour12: false });
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let idCounter = 0;
const nextId = () => `log-${Date.now()}-${idCounter++}`;

export default function Dashboard() {
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState([]);
  const [agents, setAgents] = useState(
    AGENTS.map((a) => ({ ...a, status: 'idle', lastUpdated: null }))
  );
  const [stats, setStats] = useState({
    totalIncidents: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  });

  // Fetch incidents periodically to update stats
  React.useEffect(() => {
    let statTimer;
    async function fetchStats() {
      try {
        const response = await fetch('http://127.0.0.1:8000/api/incidents');
        const data = await response.json();
        if (data.incidents) {
          const threats = data.incidents.filter(i => i.threat?.detected);
          setStats({
            totalIncidents: data.incidents.length,
            critical: threats.filter(i => i.response?.risk_level === 'Critical').length,
            high: threats.filter(i => i.response?.risk_level === 'High').length,
            medium: threats.filter(i => i.response?.risk_level === 'Medium').length,
            low: threats.filter(i => i.response?.risk_level === 'Low').length,
          });
          
          // Check for pending approvals if not already handling one
          const pending = threats.find(i => i.response?.approval_status === 'PENDING');
          if (pending && !pendingIncidentId) {
            setPendingIncidentId(pending.incident_id);
            setPendingAction(pending.response.proposed_action);
            addLog('WARN', 'MITIGATION', `Human approval required for action: ${pending.response.proposed_action}`);
          }
        }
      } catch (e) {
        // Ignore fetch errors in background
      }
    }
    fetchStats();
    statTimer = setInterval(fetchStats, 5000);
    return () => clearInterval(statTimer);
  }, []);

  const addLog = useCallback((level, agent, message) => {
    setLogs((prev) => [...prev, { id: nextId(), timestamp: now(), level, agent, message }]);
  }, []);

  const setAgentStatus = useCallback((id, status) => {
    setAgents((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status, lastUpdated: now() } : a))
    );
  }, []);

  const [pendingIncidentId, setPendingIncidentId] = useState(null);
  const [pendingAction, setPendingAction] = useState(null);
  const [monitoring, setMonitoring] = useState(false);

  const handleTrigger = useCallback(async (isAuto = false) => {
    if (loading) return;
    setLoading(true);
    
    if (!isAuto) {
      setLogs([]);
      addLog('INFO', 'ORCHESTRATOR', 'Manual incident trigger received — dispatching workflow.');
    }
    setAgentStatus('orchestrator', 'running');
    
    try {
      const data = await triggerIncident({ type: 'Manual Trigger', target: 'Host-01' });
      const state = data.state;
      if (!state) throw new Error("No state returned");

      if (state.threat?.detected) {
        if (isAuto) {
           addLog('WARN', 'ORCHESTRATOR', 'Auto-monitor detected a threat! Pausing for human approval.');
        }
        addLog('INFO', 'API', `Backend processed trigger — ${data.incident_id}.`);
        setAgentStatus('threat_hunter', 'completed');
        addLog('SUCCESS', 'THREAT_HUNTER', `Suspicious indicator identified: ${state.threat.attack_type}`);

        setAgentStatus('forensics', 'completed');
        addLog('INFO', 'FORENSICS', 'Cross-referenced against memory store.');

        setAgentStatus('mitigation', 'running');
        if (state.response?.approval_status === 'PENDING') {
          addLog('WARN', 'MITIGATION', `Human approval required for action: ${state.response.proposed_action}`);
          setPendingIncidentId(data.incident_id);
          setPendingAction(state.response.proposed_action);
        } else {
          setAgentStatus('mitigation', 'completed');
          addLog('SUCCESS', 'MITIGATION', `Executed: ${state.response?.execution_result}`);
        }
      } else {
        // Clean scan, just quietly reset
        setAgentStatus('orchestrator', 'idle');
        setAgentStatus('threat_hunter', 'idle');
        setAgentStatus('forensics', 'idle');
        setAgentStatus('mitigation', 'idle');
        if (!isAuto) addLog('INFO', 'THREAT_HUNTER', 'Scan completed. Host is clean.');
      }
      
    } catch (err) {
      if (!isAuto) addLog('ERROR', 'API', `Backend failed: ${err.message}`);
      setMonitoring(false);
    }
    setLoading(false);
  }, [loading, addLog, setAgentStatus]);



  const handleApprove = async () => {
    if (!pendingIncidentId) return;
    addLog('INFO', 'API', `Approving action for ${pendingIncidentId}...`);
    try {
      const response = await fetch(`http://127.0.0.1:8000/api/incidents/${pendingIncidentId}/approve`, { method: 'POST' });
      const data = await response.json();
      addLog('SUCCESS', 'MITIGATION', `Action executed: ${data.state?.response?.execution_result}`);
      setAgentStatus('mitigation', 'completed');
      setPendingIncidentId(null);
    } catch (err) {
      addLog('ERROR', 'API', `Approval failed: ${err.message}`);
    }
  };

  const handleReject = async () => {
    if (!pendingIncidentId) return;
    addLog('INFO', 'API', `Rejecting action for ${pendingIncidentId}...`);
    try {
      const response = await fetch(`http://127.0.0.1:8000/api/incidents/${pendingIncidentId}/reject`, { method: 'POST' });
      const data = await response.json();
      addLog('WARN', 'MITIGATION', `Action skipped: ${data.state?.response?.execution_result}`);
      setAgentStatus('mitigation', 'completed');
      setPendingIncidentId(null);
    } catch (err) {
      addLog('ERROR', 'API', `Rejection failed: ${err.message}`);
    }
  };

  const handleClearLogs = useCallback(() => setLogs([]), []);

  const mitigationLabel =
    stats.mitigationPending > 0
      ? `${stats.mitigationExecuted} executed / ${stats.mitigationPending} pending`
      : stats.mitigationExecuted > 0
      ? 'All executed'
      : 'No actions yet';

  return (
    <div>
      <div className="pageHead">
        <div>
          <h1 className="pageTitle">Overview</h1>
          <p className="pageSubtitle">live agent pipeline — Host-01 monitoring</p>
        </div>
        <div className="actions" style={{ display: 'flex', gap: '10px' }}>
          {pendingIncidentId && (
            <div style={{ display: 'flex', gap: '5px', alignItems: 'center', backgroundColor: '#334155', padding: '5px 10px', borderRadius: '5px' }}>
              <span style={{ fontSize: '12px', color: '#f8fafc' }}>Action: {pendingAction}</span>
              <button className="btnPrimary" style={{ backgroundColor: '#10b981' }} onClick={handleApprove}>Approve</button>
              <button className="btnGhost" style={{ color: '#ef4444' }} onClick={handleReject}>Reject</button>
            </div>
          )}
          <button className="btnGhost" onClick={handleClearLogs} disabled={logs.length === 0}>
            <Trash2 size={14} />
            Clear Logs
          </button>
          
          <button 
            className="btnGhost" 
            style={{ 
              borderColor: monitoring ? '#ef4444' : '#10b981', 
              color: monitoring ? '#ef4444' : '#10b981' 
            }}
            onClick={async () => {
              const newState = !monitoring;
              setMonitoring(newState);
              try {
                if (newState) {
                  await fetch('http://127.0.0.1:8000/api/monitoring/start', { method: 'POST' });
                  addLog('INFO', 'API', 'Started background telemetry monitoring');
                } else {
                  await fetch('http://127.0.0.1:8000/api/monitoring/stop', { method: 'POST' });
                  addLog('INFO', 'API', 'Stopped background telemetry monitoring');
                }
              } catch (e) {
                console.error('Monitoring toggle failed', e);
              }
            }}
            disabled={pendingIncidentId !== null}
          >
            {monitoring ? 'Stop Monitoring' : 'Start Auto-Monitor'}
          </button>

          <button className="btnPrimary" onClick={() => handleTrigger(false)} disabled={loading || pendingIncidentId || monitoring}>
            {loading && !monitoring ? <Loader2 size={14} className="spin" /> : <Play size={14} />}
            {loading && !monitoring ? 'Investigating...' : 'Trigger Scan'}
          </button>
        </div>
      </div>

      {/* Stats overview */}
      <div className="statsGrid">
        <StatTile
          icon={Activity}
          label="Monitoring Status"
          value={monitoring ? 'RUNNING' : 'STOPPED'}
          sublabel="auto-monitor service"
          color={monitoring ? '#10b981' : '#64748b'}
        />
        <StatTile
          icon={Activity}
          label="Total Incidents"
          value={stats.totalIncidents}
          sublabel="all time"
          color="#5b9dd9"
        />
        <StatTile
          icon={Search}
          label="Critical / High"
          value={`${stats.critical} / ${stats.high}`}
          sublabel="severe incidents"
          color="#ef4444"
        />
        <StatTile
          icon={ShieldAlert}
          label="Medium / Low"
          value={`${stats.medium} / ${stats.low}`}
          sublabel="minor incidents"
          color="#facc15"
        />
      </div>

      {/* Agent status panel */}
      <div className="sectionHead">
        <h2 className="sectionTitle">Agent Status</h2>
        <span className="sectionHint">4 agents · live pipeline</span>
      </div>
      <div className="agentGrid">
        {agents.map((agent) => (
          <ThreatCard key={agent.id} agent={agent} />
        ))}
      </div>

      {/* Live log terminal */}
      <div className="sectionHead">
        <h2 className="sectionTitle">Real-Time Live Logs</h2>
        <span className="sectionHint">{logs.length} entries</span>
      </div>
      <AgentLogs logs={logs} />
    </div>
  );
}

// Small inline stat tile — kept local since no separate StatsCard file
// exists in this project's component structure.
function StatTile({ icon: Icon, label, value, sublabel, color }) {
  return (
    <div className="statCard">
      <div className="statIconWrap" style={{ background: `${color}1f`, color }}>
        <Icon size={16} strokeWidth={2.25} />
      </div>
      <div className="statValue">{value}</div>
      <div className="statLabel">{label}</div>
      {sublabel && <div className="statSub">{sublabel}</div>}
    </div>
  );
}