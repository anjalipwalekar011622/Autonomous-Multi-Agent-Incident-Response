import React, { useEffect, useState } from 'react';
import { History, ShieldAlert, GitBranch, Database, Target, Loader2 } from 'lucide-react';
import { getIncidents } from '../services/api';
import '../styles/app.css';

export default function Timeline() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchHistory() {
      try {
        const data = await getIncidents();
        setIncidents(data.incidents || []);
      } catch (err) {
        console.error("Failed to load timeline:", err);
      } finally {
        setLoading(false);
      }
    }
    fetchHistory();
  }, []);

  return (
    <div>
      <div className="pageHead">
        <div>
          <h1 className="pageTitle">Incident Timeline</h1>
          <p className="pageSubtitle">chronological view of agent activity</p>
        </div>
      </div>

      {loading ? (
        <div className="placeholder">
          <Loader2 size={24} className="spin" />
        </div>
      ) : (
        <div style={{ padding: '20px', maxWidth: '800px', margin: '0 auto' }}>
          {incidents.length === 0 ? (
            <div className="placeholder" style={{ color: '#64748b' }}>No activity recorded yet.</div>
          ) : (
            <div style={{ borderLeft: '2px solid #334155', paddingLeft: '30px', position: 'relative' }}>
              {incidents.map((state, idx) => {
                const isThreat = state.threat?.detected;
                const dateObj = new Date(state.incident?.updated_at || Date.now());
                const timeStr = dateObj.toLocaleTimeString();
                
                return (
                  <div key={state.incident_id || idx} style={{ marginBottom: '40px', position: 'relative' }}>
                    {/* Timeline Dot */}
                    <div style={{
                      position: 'absolute',
                      left: '-38px',
                      top: '0',
                      width: '14px',
                      height: '14px',
                      borderRadius: '50%',
                      backgroundColor: isThreat ? '#ef4444' : '#10b981',
                      border: '2px solid #1e293b'
                    }} />

                    {/* Content Box */}
                    <div style={{
                      backgroundColor: 'var(--surface)',
                      borderRadius: '8px',
                      padding: '15px',
                      border: `1px solid ${isThreat ? '#ef444455' : 'var(--border)'}`
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                        <h4 style={{ margin: 0, color: 'var(--text)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {isThreat ? <ShieldAlert size={16} color="#ef4444" /> : <Target size={16} color="#10b981" />}
                          {state.incident_id}
                        </h4>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{timeStr}</span>
                      </div>

                      <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                        {isThreat ? (
                          <>
                            <p style={{ margin: '0 0 5px 0' }}><strong>Detected:</strong> {state.threat?.attack_type} ({state.response?.risk_level} Risk)</p>
                            <p style={{ margin: '0 0 5px 0' }}><strong>Target:</strong> {state.source?.host} ({state.source?.source_ip})</p>
                            {state.response?.execution_status === 'EXECUTED' && (
                              <p style={{ margin: '5px 0 0 0', color: '#10b981' }}>
                                ✓ {state.response.action_type} executed.
                              </p>
                            )}
                            {state.response?.execution_status === 'SKIPPED' && (
                              <p style={{ margin: '5px 0 0 0', color: '#f59e0b' }}>
                                ⚠ {state.response.action_type} skipped by human admin.
                              </p>
                            )}
                          </>
                        ) : (
                          <p style={{ margin: 0, color: '#64748b' }}>Routine telemetry sweep completed. No threats detected.</p>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}