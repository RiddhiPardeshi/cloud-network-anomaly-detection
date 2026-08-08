import React from 'react';

const ThreatTable = ({ predictions = [], alerts = [], blockedIps = [] }) => {
  const getBadgeClass = (category) => {
    switch (category) {
      case 'Safe': return 'badge-safe';
      case 'Low': return 'badge-low';
      case 'Medium': return 'badge-medium';
      case 'Critical': return 'badge-critical';
      default: return 'badge-low';
    }
  };

  const isBlocked = (ip) => {
    return blockedIps.some((b) => b.ip_address === ip && b.is_active);
  };

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
      <div className="chart-title">
        <span>🛡️ Live Security Threat Feed</span>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Auto-refreshing every 5s</span>
      </div>

      <div className="table-container">
        <table className="cyber-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Attack Type</th>
              <th>Risk Score</th>
              <th>Risk Category</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {predictions.length > 0 ? (
              predictions.slice(0, 10).map((item) => {
                const blocked = isBlocked(item['Source IP'] || item.source_ip);
                return (
                  <tr key={item.id || item.prediction_id}>
                    <td className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      {item.Timestamp || item.timestamp ? new Date(item.Timestamp || item.timestamp).toLocaleTimeString() : 'N/A'}
                    </td>
                    <td className="font-mono" style={{ fontWeight: 600 }}>
                      {item['Source IP'] || item.source_ip}
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, color: item.is_attack ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                        {item['Attack Type'] || item.attack_type}
                      </span>
                    </td>
                    <td className="font-mono" style={{ fontWeight: 700 }}>
                      {item.risk_score !== undefined ? item.risk_score : '—'}
                    </td>
                    <td>
                      <span className={getBadgeClass(item.risk_category)}>
                        {item.risk_category || 'Safe'}
                      </span>
                    </td>
                    <td>
                      {blocked ? (
                        <span className="badge-critical">🔒 Blocked</span>
                      ) : (
                        <span className="badge-safe">👁️ Monitored</span>
                      )}
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                  No threats detected yet. Start the Attack Simulator to generate live security telemetry.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ThreatTable;
