import React from 'react';

const StatusCard = ({ title, status, details = [] }) => {
  const isHealthy = status === 'online' || status === 'healthy' || status === true;

  return (
    <div className="glass-panel" style={{ padding: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>{title}</h3>
        <span className={isHealthy ? 'system-badge' : 'badge-critical'}>
          <span className="badge-dot"></span>
          {isHealthy ? 'ONLINE / HEALTHY' : 'DEGRADED / INACTIVE'}
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
        {details.map((item, idx) => (
          <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.9rem' }}>
            <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
            <span className="font-mono" style={{ fontWeight: 600, color: item.color || '#fff' }}>
              {item.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default StatusCard;
