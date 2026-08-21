import React, { useCallback, useState } from 'react';
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

import ThreatCard from '../components/ThreatCard';
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
    activeAlerts: 0,
    forensicsHits: 0,
    mitigationExecuted: 0,
    mitigationPending: 0,
  });

  const addLog = useCallback((level, agent, message) => {
    setLogs((prev) => [...prev, { id: nextId(), timestamp: now(), level, agent, message }]);
  }, []);

  const setAgentStatus = useCallback((id, status) => {
    setAgents((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status, lastUpdated: now() } : a))
    );
  }, []);

  // -------------------------------------------------------------------------
  // Client-side simulation of the orchestration sequence so the dashboard is
  // fully demoable before the LangGraph workflow streams real events. Swap
  // the body of this function for a WebSocket/SSE subscription once
  // orchestrator/workflow.py exposes live agent state — setAgentStatus/addLog
  // can stay exactly as-is.
  // -------------------------------------------------------------------------
  const runPipeline = useCallback(async () => {
    setAgentStatus('orchestrator', 'running');
    addLog('INFO', 'ORCHESTRATOR', 'Incident trigger received — dispatching workflow.');
    await delay(500);

    setAgentStatus('threat_hunter', 'running');
    addLog('INFO', 'THREAT_HUNTER', 'Scanning host telemetry for indicators of compromise.');
    await delay(1100);

    const iocCount = 2 + Math.floor(Math.random() * 3);
    setAgentStatus('threat_hunter', 'completed');
    addLog('SUCCESS', 'THREAT_HUNTER', `${iocCount} suspicious indicators identified on Host-01.`);
    setStats((s) => ({ ...s, activeAlerts: s.activeAlerts + iocCount }));
    await delay(400);

    setAgentStatus('forensics', 'running');
    addLog('INFO', 'FORENSICS', 'Cross-referencing indicators against memory store.');
    await delay(1000);

    const memoryHits = Math.floor(Math.random() * 3);
    setAgentStatus('forensics', 'completed');
    if (memoryHits > 0) {
      addLog('SUCCESS', 'FORENSICS', `Matched ${memoryHits} historical incident fingerprint(s).`);
    } else {
      addLog('WARN', 'FORENSICS', 'No historical match found — treating as novel pattern.');
    }
    setStats((s) => ({ ...s, forensicsHits: s.forensicsHits + memoryHits }));
    await delay(400);

    addLog('INFO', 'ORCHESTRATOR', 'Root cause correlated — routing to mitigation.');
    setAgentStatus('orchestrator', 'completed');
    await delay(400);

    setAgentStatus('mitigation', 'running');
    addLog('INFO', 'MITIGATION', 'Preparing containment actions for Host-01.');
    await delay(1100);

    const mitigationSucceeded = Math.random() > 0.15;
    if (mitigationSucceeded) {
      setAgentStatus('mitigation', 'completed');
      addLog('SUCCESS', 'MITIGATION', 'Isolation policy executed — threat contained.');
      setStats((s) => ({ ...s, mitigationExecuted: s.mitigationExecuted + 1 }));
    } else {
      setAgentStatus('mitigation', 'failed');
      addLog('ERROR', 'MITIGATION', 'Automated containment failed — flagged for manual review.');
      setStats((s) => ({ ...s, mitigationPending: s.mitigationPending + 1 }));
    }

    setStats((s) => ({ ...s, totalIncidents: s.totalIncidents + 1 }));
  }, [addLog, setAgentStatus]);

  const handleTrigger = useCallback(async () => {
    if (loading) return;
    setLoading(true);
    try {
      const data = await triggerIncident({ type: 'Manual Trigger', target: 'Host-01' });
      addLog('INFO', 'API', `Backend accepted trigger — ${data.incident_id}.`);
    } catch (err) {
      addLog('WARN', 'API', 'Backend unreachable — continuing in offline simulation mode.');
    }
    await runPipeline();
    setLoading(false);
  }, [loading, addLog, runPipeline]);

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
          <p className="pageSubtitle">live agent pipeline · Host-01 monitoring</p>
        </div>
        <div className="actions">
          <button className="btnGhost" onClick={handleClearLogs} disabled={logs.length === 0}>
            <Trash2 size={14} />
            Clear Logs
          </button>
          <button className="btnPrimary" onClick={handleTrigger} disabled={loading}>
            {loading ? <Loader2 size={14} className="spin" /> : <Play size={14} />}
            {loading ? 'Investigating…' : 'Trigger Incident Simulation'}
          </button>
        </div>
      </div>

      {/* Stats overview */}
      <div className="statsGrid">
        <StatTile
          icon={Activity}
          label="Total Incidents Analyzed"
          value={stats.totalIncidents}
          sublabel="since session start"
          color="#5b9dd9"
        />
        <StatTile
          icon={Search}
          label="Active Threat Hunter Alerts"
          value={stats.activeAlerts}
          sublabel="indicators of compromise"
          color="#f2a93b"
        />
        <StatTile
          icon={Fingerprint}
          label="Forensics Memory Hits"
          value={stats.forensicsHits}
          sublabel="matched past incidents"
          color="#35d0ba"
        />
        <StatTile
          icon={ShieldAlert}
          label="Mitigation Status"
          value={stats.mitigationPending > 0 ? 'Pending' : stats.mitigationExecuted > 0 ? 'Executed' : '—'}
          sublabel={mitigationLabel}
          color="#ff6b6b"
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