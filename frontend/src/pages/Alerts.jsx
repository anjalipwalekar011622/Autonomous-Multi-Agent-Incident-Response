import React, { useEffect, useState } from 'react';
import { Siren, Loader2, AlertTriangle, ShieldCheck } from 'lucide-react';
import { getIncidents } from '../services/api';
import '../styles/app.css';

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchAlerts() {
      try {
        const data = await getIncidents();
        // Filter ONLY incidents where a threat was detected
        const onlyThreats = (data.incidents || []).filter(state => state.threat?.detected === true);
        setAlerts(onlyThreats);
      } catch (err) {
        console.error("Failed to load alerts:", err);
      } finally {
        setLoading(false);
      }
    }
    fetchAlerts();
  }, []);

  return (
    <div>
      <div className="pageHead">
        <div>
          <h1 className="pageTitle">Active Alerts</h1>
          <p className="pageSubtitle">high-priority security events</p>
        </div>
      </div>

      {loading ? (
        <div className="placeholder">
          <Loader2 size={24} className="spin" />
        </div>
      ) : (
        <div style={{ display: 'grid', gap: '15px' }}>
          {alerts.length === 0 ? (
            <div className="placeholder" style={{ color: '#64748b' }}>No active alerts. System is secure.</div>
          ) : (
            alerts.map((state, idx) => {
              const riskLevel = state.response?.risk_level || 'Unknown';
              let riskColor = '#3b82f6';
              if (riskLevel === 'Critical') riskColor = '#ef4444';
              else if (riskLevel === 'High') riskColor = '#f97316';
              else if (riskLevel === 'Medium') riskColor = '#facc15';

              return (
                <div key={state.incident_id || idx} style={{
                  backgroundColor: 'var(--surface)',
                  borderLeft: `4px solid ${riskColor}`,
                  borderRadius: '6px',
                  padding: '15px 20px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  border: '1px solid var(--border)'
                }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <AlertTriangle size={16} color={riskColor} />
                      <strong style={{ color: 'var(--text)', fontSize: '1.05rem' }}>{state.threat?.attack_type}</strong>
                      <span style={{ 
                        fontSize: '0.7rem', 
                        backgroundColor: 'var(--surface-raised)', 
                        padding: '2px 8px', 
                        borderRadius: '12px',
                        color: 'var(--text-muted)',
                        border: '1px solid var(--border)'
                      }}>{state.incident_id}</span>
                    </div>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                      Target: {state.source?.host} ({state.source?.source_ip}) • Confidence: {Math.round((state.threat?.confidence || 0) * 100)}%
                    </div>
                    <div style={{ color: 'var(--text-faint)', fontSize: '0.8rem', fontStyle: 'italic', marginTop: '4px' }}>
                      {state.threat?.details}
                    </div>
                  </div>
                  
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '5px' }}>
                    <span style={{ 
                      color: riskColor, 
                      fontWeight: 'bold', 
                      fontSize: '0.85rem',
                      textTransform: 'uppercase'
                    }}>
                      {riskLevel} RISK
                    </span>
                    {state.incident?.status === 'RESOLVED' || state.response?.execution_status === 'EXECUTED' ? (
                      <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#10b981', fontSize: '0.75rem' }}>
                        <ShieldCheck size={14} /> MITIGATED
                      </span>
                    ) : (
                      <span style={{ color: '#ef4444', fontSize: '0.75rem' }}>{state.incident?.status}</span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}
    </div>
  );
}