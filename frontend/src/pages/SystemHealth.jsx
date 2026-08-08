import React, { useState, useEffect } from 'react';
import apiClient from '../api/axios';
import StatusCard from '../components/StatusCard';

const SystemHealth = () => {
  const [systemStatus, setSystemStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await apiClient.get('/api/system/status');
        if (res.status === 200) {
          setSystemStatus(res.data);
        }
      } catch (err) {
        console.error('Error fetching system health status:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const dbInfo = systemStatus?.database || {};
  const mlInfo = systemStatus?.ml_engine || {};
  const simInfo = systemStatus?.simulator || {};
  const secInfo = systemStatus?.security_config || {};

  return (
    <div>
      <div className="header-bar">
        <div>
          <h1 className="page-title">System Health & Gateway Router</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.2rem' }}>
            Infrastructure Diagnostics, Database Connectivity & Security Parameters
          </p>
        </div>
        <div>
          <span className={systemStatus?.system_status === 'healthy' ? 'system-badge' : 'badge-critical'}>
            <span className="badge-dot"></span>
            SYSTEM {systemStatus?.system_status ? systemStatus.system_status.toUpperCase() : 'ONLINE'}
          </span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1.5rem', marginBottom: '2rem' }}>
        {/* Database Status Card */}
        <StatusCard
          title="🗄️ Database Architecture (MySQL / ORM)"
          status={dbInfo.status}
          details={[
            { label: 'Connection Status', value: dbInfo.status ? dbInfo.status.toUpperCase() : 'ONLINE', color: 'var(--accent-green)' },
            { label: 'Registered Users', value: dbInfo.counts?.users || 0 },
            { label: 'Telemetry Logs Table', value: (dbInfo.counts?.telemetry_logs || 0).toLocaleString() },
            { label: 'Prediction Logs Table', value: (dbInfo.counts?.prediction_logs || 0).toLocaleString() },
            { label: 'Active Blocked IPs Table', value: dbInfo.counts?.active_blocked_ips || 0, color: 'var(--accent-red)' },
            { label: 'Security Incident Alerts Table', value: dbInfo.counts?.attack_alerts || 0, color: 'var(--accent-amber)' },
          ]}
        />

        {/* ML Engine Status Card */}
        <StatusCard
          title="🧠 Machine Learning Engine & Predictor"
          status={mlInfo.status}
          details={[
            { label: 'Engine Status', value: mlInfo.status ? mlInfo.status.toUpperCase() : 'ONLINE', color: 'var(--accent-green)' },
            { label: 'Champion Model Loaded', value: mlInfo.champion_model || 'RandomForestClassifier', color: 'var(--accent-cyan)' },
            { label: 'Feature Vector Dimension', value: `${mlInfo.feature_count || 9} Columns` },
            { label: 'Explainable AI Engine', value: 'ENABLED (Tree Feature Importance)', color: 'var(--accent-purple)' },
            { label: 'Scikit-Learn Standard Scaling', value: 'ACTIVE (scaler.pkl)' },
          ]}
        />

        {/* Simulator Status Card */}
        <StatusCard
          title="🚀 Background Traffic & Attack Simulator"
          status={simInfo.is_running}
          details={[
            { label: 'Runner Thread Status', value: simInfo.is_running ? 'ACTIVE (RUNNING)' : 'STOPPED (IDLE)', color: simInfo.is_running ? 'var(--accent-green)' : 'var(--text-muted)' },
            { label: 'Current Scenario', value: simInfo.scenario || 'Mixed' },
            { label: 'Target Emission Rate', value: `${simInfo.rate_per_sec || 2.0} req/sec` },
            { label: 'Total Generated Stream', value: (simInfo.total_generated || 0).toLocaleString() },
            { label: 'Attacks Detected Stream', value: (simInfo.attacks_generated || 0).toLocaleString(), color: 'var(--accent-red)' },
          ]}
        />

        {/* Security Configuration Card */}
        <StatusCard
          title="🛡️ Security Thresholds & SMTP Alerting"
          status={true}
          details={[
            { label: 'High Risk Threshold', value: `Score >= ${secInfo.risk_threshold_high || 70}`, color: 'var(--accent-amber)' },
            { label: 'Critical Auto-Block Threshold', value: `Score >= ${secInfo.risk_threshold_critical || 81}`, color: 'var(--accent-red)' },
            { label: 'Alert Email Sender', value: secInfo.alert_email_sender || 'alerts@cloudsecurity.io' },
            { label: 'Alert Email Recipient', value: secInfo.alert_email_recipient || 'admin@cloudsecurity.io' },
            { label: 'SMTP Server Transport', value: secInfo.smtp_configured ? 'ENABLED (Gmail SMTP)' : 'LOGGING / SIMULATION MODE', color: 'var(--accent-cyan)' },
          ]}
        />
      </div>
    </div>
  );
};

export default SystemHealth;
