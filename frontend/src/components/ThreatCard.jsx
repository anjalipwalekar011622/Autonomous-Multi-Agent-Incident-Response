import React from 'react';

const STATUS_COLORS = {
  idle: '#64748b',
  running: '#f59e0b',
  completed: '#10b981',
  failed: '#ef4444',
};

export default function ThreatCard({ agent }) {
  if (!agent) return null;
  const { name, description, icon: Icon, color, status, lastUpdated } = agent;

  return (
    <div className="agentCard" style={{
      backgroundColor: '#1e293b',
      padding: '1.25rem',
      borderRadius: '8px',
      border: '1px solid #334155',
      display: 'flex',
      flexDirection: 'column',
      gap: '0.75rem'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color }}>
          {Icon && <Icon size={20} />}
          <h3 style={{ fontSize: '1rem', fontWeight: '600', color: '#f8fafc', margin: 0 }}>{name}</h3>
        </div>
        <span style={{
          fontSize: '0.75rem',
          padding: '0.2rem 0.5rem',
          borderRadius: '4px',
          textTransform: 'uppercase',
          fontWeight: 'bold',
          backgroundColor: `${STATUS_COLORS[status] || '#64748b'}22`,
          color: STATUS_COLORS[status] || '#64748b',
          border: `1px solid ${STATUS_COLORS[status] || '#64748b'}`
        }}>
          {status}
        </span>
      </div>

      <p style={{ fontSize: '0.85rem', color: '#94a3b8', margin: 0, flex: 1 }}>
        {description}
      </p>

      {lastUpdated && (
        <span style={{ fontSize: '0.75rem', color: '#64748b' }}>
          Updated: {lastUpdated}
        </span>
      )}
    </div>
  );
}