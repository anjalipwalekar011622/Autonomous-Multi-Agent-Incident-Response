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
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '20px' }}>
                          
                          {/* INCIDENT & THREAT */}
                          <div style={{ backgroundColor: 'var(--surface)', padding: '15px', borderRadius: '6px', border: '1px solid var(--border)' }}>
                            <h4 style={{ margin: '0 0 10px 0', color: 'var(--text)' }}>Incident & Threat</h4>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Status:</strong> {state.incident?.status}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Created:</strong> {state.incident?.created_at}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Updated:</strong> {state.incident?.updated_at}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Severity:</strong> {state.incident?.severity}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Confidence:</strong> {state.incident?.confidence}</p>
                            
                            <h5 style={{ margin: '10px 0 5px 0', color: 'var(--text)' }}>Threat Details</h5>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Category:</strong> {state.threat?.category}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>MITRE Tactic:</strong> {state.threat?.mitre?.tactic}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>MITRE Technique:</strong> {state.threat?.mitre?.technique_id} ({state.threat?.mitre?.technique_name})</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Indicators:</strong> {state.threat?.indicators?.join(', ')}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Details:</strong> {state.threat?.details}</p>
                          </div>

                          {/* SOURCE & FORENSICS */}
                          <div style={{ backgroundColor: 'var(--surface)', padding: '15px', borderRadius: '6px', border: '1px solid var(--border)' }}>
                            <h4 style={{ margin: '0 0 10px 0', color: 'var(--text)' }}>Source Telemetry</h4>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Host:</strong> {state.source?.host} ({state.source?.os})</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Source IP/Port:</strong> {state.source?.source_ip}:{state.source?.source_port}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Dest IP/Port:</strong> {state.source?.destination_ip}:{state.source?.destination_port}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>User:</strong> {state.source?.user}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>PID:</strong> {state.source?.pid}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Process Name:</strong> {state.source?.process_name}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Path:</strong> {state.source?.executable_path}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Command Line:</strong> {state.source?.command_line}</p>
                            
                            <h5 style={{ margin: '10px 0 5px 0', color: 'var(--text)' }}>Forensics Investigation</h5>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Evidence:</strong> {state.investigation?.evidence?.join(', ')}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Seen Before:</strong> {state.investigation?.historical_context?.seen_before ? 'Yes' : 'No'}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Recommended Action:</strong> {state.investigation?.recommended_action}</p>
                          </div>

                          {/* RESPONSE & VERIFICATION */}
                          <div style={{ backgroundColor: 'var(--surface)', padding: '15px', borderRadius: '6px', border: '1px solid var(--border)' }}>
                            <h4 style={{ margin: '0 0 10px 0', color: 'var(--text)' }}>Response & Verification</h4>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Risk Level:</strong> {state.response?.risk_level} (Score: {state.response?.risk_score})</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Proposed Action:</strong> {state.response?.proposed_action}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Action Type:</strong> {state.response?.action_type}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Parameters:</strong> {JSON.stringify(state.response?.action_parameters)}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Approval Status:</strong> {state.response?.approval_status}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Execution Status:</strong> {state.response?.execution_status}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Execution Result:</strong> {state.response?.execution_result}</p>
                            
                            <h5 style={{ margin: '10px 0 5px 0', color: 'var(--text)' }}>Verification</h5>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Status:</strong> {state.verification?.status}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Threat Contained:</strong> {state.verification?.threat_contained ? 'Yes' : 'No'}</p>
                            <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', margin: '2px 0' }}><strong>Details:</strong> {state.verification?.details?.join(', ')}</p>
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