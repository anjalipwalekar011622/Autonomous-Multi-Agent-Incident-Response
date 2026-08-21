import React from 'react';

export default function AgentLogs({ logs = [] }) {
  return (
    <div style={{
      backgroundColor: '#1e293b',
      padding: '1rem',
      borderRadius: '8px',
      marginTop: '1rem',
      border: '1px solid #334155'
    }}>
      <h3 style={{ color: '#38bdf8', marginBottom: '0.5rem', fontSize: '1.1rem' }}>
        Agent Execution Stream
      </h3>
      <div style={{
        maxHeight: '250px',
        overflowY: 'auto',
        fontFamily: 'monospace',
        fontSize: '0.9rem',
        backgroundColor: '#0f172a',
        padding: '0.75rem',
        borderRadius: '4px'
      }}>
        {logs.length === 0 ? (
          <p style={{ color: '#64748b' }}>No active logs. Click trigger to start simulation.</p>
        ) : (
          logs.map((log, index) => (
            <div key={index} style={{ marginBottom: '0.25rem', color: '#e2e8f0' }}>
              <span style={{ color: '#94a3b8' }}>[{new Date().toLocaleTimeString()}]</span>{' '}
              <strong style={{ color: '#a855f7' }}>[{log.agent || 'SYSTEM'}]</strong>:{' '}
              <span style={{ color: log.level === 'ERROR' ? '#f87171' : log.level === 'SUCCESS' ? '#4ade80' : '#facc15' }}>
                {log.message || log}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}