import React, { useEffect, useState } from 'react';
import { FileBarChart, Loader2, Download, Search } from 'lucide-react';
import { getIncidents } from '../services/api';
import '../styles/app.css';

export default function Reports() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState(null);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    async function fetchHistory() {
      try {
        const data = await getIncidents();
        setIncidents(data.incidents || []);
      } catch (err) {
        console.error("Failed to load reports:", err);
      } finally {
        setLoading(false);
      }
    }
    fetchHistory();
  }, []);

  const filteredIncidents = incidents.filter(state => 
    state.incident?.status?.toLowerCase().includes(filter.toLowerCase()) ||
    state.incident_id?.toLowerCase().includes(filter.toLowerCase()) ||
    state.threat?.attack_type?.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <div className="pageHead">
        <div>
          <h1 className="pageTitle">Incident Reports</h1>
          <p className="pageSubtitle">historical forensics & mitigation data</p>
        </div>
        <div className="actions" style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 8, top: 10, color: '#64748b' }} />
            <input 
              type="text" 
              placeholder="Search incidents..." 
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              style={{ padding: '8px 8px 8px 28px', borderRadius: '4px', border: '1px solid #334155', background: '#1e293b', color: '#fff' }}
            />
          </div>
          <button className="btnGhost">
            <Download size={14} /> Export CSV
          </button>
        </div>
      </div>

      {loading ? (
        <div className="placeholder">
          <Loader2 size={24} className="spin" />
        </div>
      ) : (
        <div style={{ backgroundColor: 'var(--surface)', borderRadius: '8px', border: '1px solid var(--border)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ backgroundColor: 'var(--surface-raised)', borderBottom: '1px solid var(--border)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '12px 16px' }}>Incident ID</th>
                <th style={{ padding: '12px 16px' }}>Status</th>
                <th style={{ padding: '12px 16px' }}>Threat Type</th>
                <th style={{ padding: '12px 16px' }}>Risk Score</th>
                <th style={{ padding: '12px 16px' }}>Action Taken</th>
              </tr>
            </thead>
            <tbody>
              {filteredIncidents.map((state, idx) => (
                <React.Fragment key={state.incident_id || idx}>
                  <tr 
                    style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer', backgroundColor: expandedId === state.incident_id ? 'var(--surface-raised)' : 'transparent' }}
                    onClick={() => setExpandedId(expandedId === state.incident_id ? null : state.incident_id)}
                  >
                    <td style={{ padding: '12px 16px', color: 'var(--text)', fontWeight: '500' }}>{state.incident_id}</td>
                    <td style={{ padding: '12px 16px' }}>{state.incident?.status}</td>
                    <td style={{ padding: '12px 16px', color: state.threat?.detected ? '#ef4444' : '#10b981' }}>
                      {state.threat?.attack_type || 'None'}
                    </td>
                    <td style={{ padding: '12px 16px' }}>{state.response?.risk_score ?? '-'}</td>
                    <td style={{ padding: '12px 16px' }}>{state.response?.action_type || '-'}</td>
                  </tr>
                  
                  {expandedId === state.incident_id && (
                    <tr style={{ backgroundColor: 'var(--surface-raised)' }}>
                      <td colSpan="5" style={{ padding: '20px' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                          
                          {/* Forensics Output */}
                          <div style={{ backgroundColor: 'var(--surface)', padding: '15px', borderRadius: '6px', border: '1px solid var(--border)' }}>
                            <h4 style={{ margin: '0 0 10px 0', color: 'var(--text)' }}>Forensics Investigation</h4>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}><strong>Evidence:</strong> {state.investigation?.evidence?.join(', ') || 'No evidence collected'}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}><strong>Historical Hits:</strong> {state.investigation?.historical_context?.related_incidents?.length || 0}</p>
                            <pre style={{ padding: '10px', borderRadius: '4px', fontSize: '0.75rem', overflowX: 'auto', border: '1px solid var(--border)' }}>
                              {JSON.stringify(state.memory, null, 2)}
                            </pre>
                          </div>

                          {/* Mitigation Output */}
                          <div style={{ backgroundColor: 'var(--surface)', padding: '15px', borderRadius: '6px', border: '1px solid var(--border)' }}>
                            <h4 style={{ margin: '0 0 10px 0', color: 'var(--text)' }}>Risk Justification</h4>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', fontStyle: 'italic' }}>
                              "{state.response?.justification || 'No justification provided'}"
                            </p>
                            <h4 style={{ margin: '15px 0 10px 0', color: 'var(--text)' }}>Execution Result</h4>
                            <p style={{ color: '#10b981', fontSize: '0.8rem' }}>
                              {state.response?.execution_result || 'Pending / Skipped'}
                            </p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: '10px' }}>
                              <strong>Approved By:</strong> {state.response?.approved_by || '-'}
                            </p>
                          </div>
                          
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
              {filteredIncidents.length === 0 && (
                <tr>
                  <td colSpan="5" style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)' }}>No incidents found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}