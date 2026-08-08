import React from 'react';

const KPICard = ({ title, value, subtext, icon, accentColor = 'var(--accent-cyan)' }) => {
  return (
    <div className="glass-panel kpi-card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div className="kpi-title">{title}</div>
        {icon && <span style={{ fontSize: '1.25rem' }}>{icon}</span>}
      </div>
      <div className="kpi-value" style={{ color: accentColor }}>
        {value !== undefined && value !== null ? value : '—'}
      </div>
      {subtext && <div className="kpi-subtext">{subtext}</div>}
    </div>
  );
};

export default KPICard;
