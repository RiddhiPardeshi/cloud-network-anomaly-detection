import React, { useState, useEffect } from 'react';
import apiClient from '../api/axios';
import KPICard from '../components/KPICard';
import ThreatTable from '../components/ThreatTable';
import {
  AttackDistributionChart,
  RiskDistributionChart,
  RequestTimelineChart,
  TopMaliciousIPsCard,
} from '../components/Charts';

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [charts, setCharts] = useState(null);
  const [threats, setThreats] = useState({ predictions: [], alerts: [], blocked_ips: [] });
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = async () => {
    try {
      const [resStats, resCharts, resThreats] = await Promise.all([
        apiClient.get('/api/dashboard/stats'),
        apiClient.get('/api/dashboard/charts'),
        apiClient.get('/api/dashboard/recent-threats?limit=20'),
      ]);

      if (resStats.status === 200) setStats(resStats.data);
      if (resCharts.status === 200) setCharts(resCharts.data);
      if (resThreats.status === 200) setThreats(resThreats.data);
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div>
      <div className="header-bar">
        <div>
          <h1 className="page-title">SOC Security Command Center</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.2rem' }}>
            Real-Time Multi-Source Cloud Telemetry & ML Anomaly Detection Engine
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <span className="system-badge">
            <span className="badge-dot"></span> LIVE TELEMETRY STREAM
          </span>
          <button className="btn-cyber" onClick={fetchDashboardData} style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}>
            🔄 Refresh
          </button>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="kpi-grid">
        <KPICard
          title="Total Requests"
          value={stats?.total_requests?.toLocaleString()}
          subtext="Processed Telemetry Logs"
          icon="📡"
          accentColor="var(--accent-cyan)"
        />
        <KPICard
          title="Normal Traffic"
          value={stats?.normal_requests?.toLocaleString()}
          subtext="Baseline Verified"
          icon="✅"
          accentColor="var(--accent-green)"
        />
        <KPICard
          title="Attack Requests"
          value={stats?.attack_requests?.toLocaleString()}
          subtext="Anomalies Flagged"
          icon="⚠️"
          accentColor="var(--accent-red)"
        />
        <KPICard
          title="Active Blocked IPs"
          value={stats?.active_blocked_ips}
          subtext="Auto Firewall Enforced"
          icon="🔒"
          accentColor="var(--accent-red)"
        />
        <KPICard
          title="Critical Alerts"
          value={stats?.critical_alerts}
          subtext="Incidents Logged"
          icon="🚨"
          accentColor="var(--accent-amber)"
        />
        <KPICard
          title="Average Risk Score"
          value={stats?.average_risk_score !== undefined ? `${stats.average_risk_score} / 100` : '—'}
          subtext="Deterministic Score"
          icon="⚖️"
          accentColor="var(--accent-purple)"
        />
        <KPICard
          title="Live CPU Usage"
          value={stats?.live_cpu_usage !== undefined ? `${stats.live_cpu_usage}%` : '—'}
          subtext="Host System Hardware"
          icon="💻"
          accentColor="var(--accent-blue)"
        />
        <KPICard
          title="Live Memory Usage"
          value={stats?.live_memory_usage !== undefined ? `${stats.live_memory_usage}%` : '—'}
          subtext="Virtual Memory Allocated"
          icon="🧠"
          accentColor="var(--accent-cyan)"
        />
      </div>

      {/* Visual Analytics Charts Grid */}
      <div className="charts-grid">
        <RequestTimelineChart data={charts?.request_timeline} />
        <AttackDistributionChart data={charts?.attack_distribution} />
        <RiskDistributionChart data={charts?.risk_distribution} />
        <TopMaliciousIPsCard topIps={charts?.top_malicious_ips} />
      </div>

      {/* Live Threat Feed Table */}
      <ThreatTable
        predictions={threats?.predictions}
        alerts={threats?.alerts}
        blockedIps={threats?.blocked_ips}
      />
    </div>
  );
};

export default Dashboard;
