import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import { Doughnut, Bar, Line } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
);

const chartOptionsBase = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      labels: {
        color: '#94a3b8',
        font: { family: 'Inter', size: 12 },
      },
    },
  },
  scales: {
    x: {
      ticks: { color: '#64748b' },
      grid: { color: 'rgba(255, 255, 255, 0.05)' },
    },
    y: {
      ticks: { color: '#64748b' },
      grid: { color: 'rgba(255, 255, 255, 0.05)' },
    },
  },
};

export const AttackDistributionChart = ({ data }) => {
  const chartData = {
    labels: data?.labels || ['Normal', 'DDoS', 'Port Scan', 'Brute Force', 'Payload'],
    datasets: [
      {
        data: data?.data || [0, 0, 0, 0, 0],
        backgroundColor: [
          '#10b981',
          '#ef4444',
          '#f59e0b',
          '#8b5cf6',
          '#ec4899',
        ],
        borderWidth: 0,
      },
    ],
  };

  return (
    <div className="glass-panel chart-card">
      <div className="chart-title">🎯 Attack Vector Distribution</div>
      <div style={{ height: '260px' }}>
        <Doughnut
          data={chartData}
          options={{
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'right', labels: { color: '#94a3b8' } } },
          }}
        />
      </div>
    </div>
  );
};

export const RiskDistributionChart = ({ data }) => {
  const chartData = {
    labels: data?.labels || ['Safe', 'Low', 'Medium', 'Critical'],
    datasets: [
      {
        label: 'Threat Count',
        data: data?.data || [0, 0, 0, 0],
        backgroundColor: [
          'rgba(16, 185, 129, 0.7)',
          'rgba(59, 130, 246, 0.7)',
          'rgba(245, 158, 11, 0.7)',
          'rgba(239, 68, 68, 0.8)',
        ],
        borderRadius: 6,
      },
    ],
  };

  return (
    <div className="glass-panel chart-card">
      <div className="chart-title">⚖️ Risk Severity Breakdown</div>
      <div style={{ height: '260px' }}>
        <Bar data={chartData} options={chartOptionsBase} />
      </div>
    </div>
  );
};

export const RequestTimelineChart = ({ data }) => {
  const chartData = {
    labels: data?.labels || ['12:00', '13:00', '14:00', '15:00', '16:00'],
    datasets: [
      {
        label: 'Total Requests',
        data: data?.total_requests || [0, 0, 0, 0, 0],
        borderColor: '#00f2fe',
        backgroundColor: 'rgba(0, 242, 254, 0.1)',
        tension: 0.4,
        fill: true,
      },
      {
        label: 'Attack Requests',
        data: data?.attack_requests || [0, 0, 0, 0, 0],
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        tension: 0.4,
        fill: true,
      },
    ],
  };

  return (
    <div className="glass-panel chart-card" style={{ gridColumn: 'span 2' }}>
      <div className="chart-title">📈 Real-Time Traffic & Attack Timeline</div>
      <div style={{ height: '280px' }}>
        <Line data={chartData} options={chartOptionsBase} />
      </div>
    </div>
  );
};

export const TopMaliciousIPsCard = ({ topIps = [] }) => {
  return (
    <div className="glass-panel chart-card">
      <div className="chart-title">🚨 Top Malicious Source IPs</div>
      <div className="table-container">
        <table className="cyber-table">
          <thead>
            <tr>
              <th>Source IP</th>
              <th>Attack Count</th>
              <th>Max Risk</th>
            </tr>
          </thead>
          <tbody>
            {topIps.length > 0 ? (
              topIps.map((ip, idx) => (
                <tr key={idx}>
                  <td className="font-mono" style={{ color: 'var(--accent-red)', fontWeight: 600 }}>
                    {ip.source_ip}
                  </td>
                  <td className="font-mono">{ip.attack_count} attacks</td>
                  <td className="font-mono" style={{ color: 'var(--accent-amber)', fontWeight: 700 }}>
                    {ip.max_risk_score}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="3" style={{ color: 'var(--text-muted)', textAlign: 'center' }}>
                  No malicious IPs recorded.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
