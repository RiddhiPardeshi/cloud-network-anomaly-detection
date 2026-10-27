import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '../api/axios';
import KPICard from '../components/KPICard';

const AdminPanel = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  
  // Data states
  const [dashboardStats, setDashboardStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [blockedIps, setBlockedIps] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [predictions, setPredictions] = useState([]);
  const [systemStats, setSystemStats] = useState(null);

  // UI states
  const [selectedUserId, setSelectedUserId] = useState(null);
  const [newRole, setNewRole] = useState('user');
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);

  // Check admin access and fetch initial data
  useEffect(() => {
    fetchAdminData();
  }, []);

  const fetchAdminData = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.get('/api/admin/dashboard');
      if (response.status === 200) {
        setDashboardStats(response.data);
      }
    } catch (err) {
      console.error('Admin access error:', err);
      if (err.response?.status === 401) {
        setError('Session expired. Please log in again.');
        setTimeout(() => {
          localStorage.removeItem('user');
          navigate('/admin-login');
        }, 2000);
      } else if (err.response?.status === 403) {
        setError('Access denied. Admin privileges required.');
        setTimeout(() => {
          navigate('/dashboard');
        }, 2000);
      } else {
        setError('Failed to load admin data. ' + (err.response?.data?.error || err.message));
      }
    } finally {
      setLoading(false);
    }
  };

  const fetchUsers = async () => {
    try {
      const response = await apiClient.get('/api/admin/users');
      if (response.status === 200) {
        setUsers(response.data.users || []);
      }
    } catch (err) {
      console.error('Failed to fetch users:', err);
      handleApiError(err);
    }
  };

  const fetchBlockedIps = async () => {
    try {
      const response = await apiClient.get('/api/admin/blocked-ips');
      if (response.status === 200) {
        setBlockedIps(response.data.blocked_ips || []);
      }
    } catch (err) {
      console.error('Failed to fetch blocked IPs:', err);
      handleApiError(err);
    }
  };

  const fetchAlerts = async () => {
    try {
      const response = await apiClient.get('/api/admin/alerts');
      if (response.status === 200) {
        setAlerts(response.data.alerts || []);
      }
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
      handleApiError(err);
    }
  };

  const fetchPredictions = async () => {
    try {
      const response = await apiClient.get('/api/admin/predictions');
      if (response.status === 200) {
        setPredictions(response.data.predictions || []);
      }
    } catch (err) {
      console.error('Failed to fetch predictions:', err);
      handleApiError(err);
    }
  };

  const fetchSystemStats = async () => {
    try {
      const response = await apiClient.get('/api/admin/system/stats');
      if (response.status === 200) {
        setSystemStats(response.data);
      }
    } catch (err) {
      console.error('Failed to fetch system stats:', err);
      handleApiError(err);
    }
  };

  const handleApiError = (err) => {
    if (err.response?.status === 401) {
      setError('Session expired. Please log in again.');
      setTimeout(() => {
        localStorage.removeItem('user');
        navigate('/admin-login');
      }, 2000);
    } else if (err.response?.status === 403) {
      setError('Access denied. Admin privileges required.');
      setTimeout(() => {
        navigate('/dashboard');
      }, 2000);
    }
  };

  const handleChangeUserRole = async (userId, role) => {
    setActionLoading(true);
    setActionMessage(null);
    try {
      const response = await apiClient.post('/api/admin/users/role', {
        user_id: userId,
        role: role
      });
      if (response.status === 200) {
        setActionMessage({ type: 'success', text: `User role updated to ${role}` });
        fetchUsers(); // Refresh user list
      }
    } catch (err) {
      console.error('Failed to change user role:', err);
      setActionMessage({ 
        type: 'error', 
        text: err.response?.data?.error || 'Failed to update user role' 
      });
      handleApiError(err);
    } finally {
      setActionLoading(false);
      setTimeout(() => setActionMessage(null), 3000);
    }
  };

  const handleUnblockIp = async (ipId) => {
    setActionLoading(true);
    setActionMessage(null);
    try {
      const response = await apiClient.post('/api/admin/blocked-ips/unblock', {
        ip_id: ipId
      });
      if (response.status === 200) {
        setActionMessage({ type: 'success', text: 'IP address unblocked successfully' });
        fetchBlockedIps(); // Refresh blocked IPs list
      }
    } catch (err) {
      console.error('Failed to unblock IP:', err);
      setActionMessage({ 
        type: 'error', 
        text: err.response?.data?.error || 'Failed to unblock IP' 
      });
      handleApiError(err);
    } finally {
      setActionLoading(false);
      setTimeout(() => setActionMessage(null), 3000);
    }
  };

  // Fetch data when tab changes
  useEffect(() => {
    if (loading || error) return;
    
    switch (activeTab) {
      case 'users':
        if (users.length === 0) fetchUsers();
        break;
      case 'blocked-ips':
        if (blockedIps.length === 0) fetchBlockedIps();
        break;
      case 'alerts':
        if (alerts.length === 0) fetchAlerts();
        break;
      case 'predictions':
        if (predictions.length === 0) fetchPredictions();
        break;
      case 'system':
        if (!systemStats) fetchSystemStats();
        break;
    }
  }, [activeTab, loading, error]);

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '3rem' }}>
        <div className="loading-spinner" style={{ fontSize: '2rem', marginBottom: '1rem' }}>⏳</div>
        <p style={{ color: 'var(--text-secondary)' }}>Loading admin panel...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: '2rem' }}>
        <div className="glass-panel" style={{ padding: '2rem', textAlign: 'center' }}>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🚫</div>
          <h2 style={{ color: 'var(--accent-red)', marginBottom: '0.5rem' }}>Access Denied</h2>
          <p style={{ color: 'var(--text-secondary)' }}>{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="header-bar">
        <div>
          <h1 className="page-title">🔐 Admin Control Panel</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.2rem' }}>
            System Administration & User Management Console
          </p>
        </div>
        <button 
          className="btn-cyber" 
          onClick={fetchAdminData}
          style={{ fontSize: '0.8rem', padding: '0.4rem 0.8rem' }}
        >
          🔄 Refresh
        </button>
      </div>

      {/* Action Message */}
      {actionMessage && (
        <div style={{
          background: actionMessage.type === 'success' 
            ? 'rgba(16, 185, 129, 0.15)' 
            : 'rgba(239, 68, 68, 0.15)',
          border: `1px solid ${actionMessage.type === 'success' ? 'var(--accent-green)' : 'var(--accent-red)'}`,
          color: actionMessage.type === 'success' ? 'var(--accent-green)' : 'var(--accent-red)',
          padding: '0.75rem',
          borderRadius: '8px',
          marginBottom: '1.5rem',
          fontSize: '0.9rem'
        }}>
          {actionMessage.type === 'success' ? '✅' : '⚠️'} {actionMessage.text}
        </div>
      )}

      {/* Tab Navigation */}
      <div style={{ 
        display: 'flex', 
        gap: '0.5rem', 
        marginBottom: '1.5rem',
        borderBottom: '1px solid var(--border-color)',
        paddingBottom: '0'
      }}>
        {[
          { id: 'overview', label: '📊 Overview', icon: '📊' },
          { id: 'users', label: '👥 Users', icon: '👥' },
          { id: 'blocked-ips', label: '🔒 Blocked IPs', icon: '🔒' },
          { id: 'alerts', label: '🚨 Alerts', icon: '🚨' },
          { id: 'predictions', label: '🎯 Predictions', icon: '🎯' },
          { id: 'system', label: '⚙️ System', icon: '⚙️' }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              background: activeTab === tab.id ? 'var(--bg-card)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === tab.id ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              color: activeTab === tab.id ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              padding: '0.75rem 1.25rem',
              cursor: 'pointer',
              fontSize: '0.9rem',
              fontWeight: activeTab === tab.id ? 600 : 400,
              transition: 'all 0.2s ease'
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div>
          <div className="kpi-grid">
            <KPICard
              title="Total Users"
              value={dashboardStats?.total_users}
              subtext="Registered Accounts"
              icon="👥"
              accentColor="var(--accent-cyan)"
            />
            <KPICard
              title="Admin Users"
              value={dashboardStats?.admin_users}
              subtext="Administrator Accounts"
              icon="🔐"
              accentColor="var(--accent-purple)"
            />
            <KPICard
              title="Total Predictions"
              value={dashboardStats?.total_predictions?.toLocaleString()}
              subtext="ML Model Predictions"
              icon="🎯"
              accentColor="var(--accent-blue)"
            />
            <KPICard
              title="Total Alerts"
              value={dashboardStats?.total_alerts?.toLocaleString()}
              subtext="Security Alerts Generated"
              icon="🚨"
              accentColor="var(--accent-amber)"
            />
            <KPICard
              title="Blocked IPs"
              value={dashboardStats?.blocked_ips}
              subtext="Active IP Blocks"
              icon="🔒"
              accentColor="var(--accent-red)"
            />
            <KPICard
              title="Attack Detection Rate"
              value={dashboardStats?.attack_detection_rate !== undefined 
                ? `${dashboardStats.attack_detection_rate}%` 
                : '—'}
              subtext="Model Accuracy"
              icon="✅"
              accentColor="var(--accent-green)"
            />
          </div>
        </div>
      )}

      {activeTab === 'users' && (
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem', color: 'var(--accent-cyan)' }}>
            User Management
          </h3>
          {users.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '2rem' }}>
              No users found
            </p>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>ID</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Username</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Email</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Role</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Created</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem' }}>{user.id}</td>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem' }}>{user.username}</td>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>{user.email}</td>
                      <td style={{ padding: '0.75rem' }}>
                        <span style={{
                          background: user.role === 'admin' ? 'rgba(139, 92, 246, 0.2)' : 'rgba(100, 116, 139, 0.2)',
                          color: user.role === 'admin' ? 'var(--accent-purple)' : 'var(--text-secondary)',
                          padding: '0.25rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.8rem',
                          fontWeight: 600
                        }}>
                          {user.role}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        {user.created_at ? new Date(user.created_at).toLocaleDateString() : '—'}
                      </td>
                      <td style={{ padding: '0.75rem' }}>
                        <select
                          value={user.role}
                          onChange={(e) => handleChangeUserRole(user.id, e.target.value)}
                          disabled={actionLoading}
                          style={{
                            background: 'var(--bg-dark)',
                            border: '1px solid var(--border-color)',
                            color: 'var(--text-primary)',
                            padding: '0.4rem',
                            borderRadius: '4px',
                            fontSize: '0.85rem',
                            cursor: 'pointer'
                          }}
                        >
                          <option value="user">User</option>
                          <option value="admin">Admin</option>
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'blocked-ips' && (
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem', color: 'var(--accent-cyan)' }}>
            Blocked IP Addresses
          </h3>
          {blockedIps.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '2rem' }}>
              No blocked IPs found
            </p>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>IP Address</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Risk Score</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Reason</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Blocked At</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Status</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {blockedIps.map((ip) => (
                    <tr key={ip.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem', fontFamily: 'monospace' }}>
                        {ip.ip_address}
                      </td>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem' }}>
                        <span style={{ color: ip.risk_score >= 80 ? 'var(--accent-red)' : 'var(--accent-amber)' }}>
                          {ip.risk_score}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        {ip.reason || '—'}
                      </td>
                      <td style={{ padding: '0.75rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        {ip.blocked_at ? new Date(ip.blocked_at).toLocaleString() : '—'}
                      </td>
                      <td style={{ padding: '0.75rem' }}>
                        <span style={{
                          background: ip.is_active ? 'rgba(239, 68, 68, 0.2)' : 'rgba(100, 116, 139, 0.2)',
                          color: ip.is_active ? 'var(--accent-red)' : 'var(--text-secondary)',
                          padding: '0.25rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.8rem',
                          fontWeight: 600
                        }}>
                          {ip.is_active ? 'Blocked' : 'Unblocked'}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem' }}>
                        {ip.is_active && (
                          <button
                            onClick={() => handleUnblockIp(ip.id)}
                            disabled={actionLoading}
                            style={{
                              background: 'rgba(16, 185, 129, 0.2)',
                              border: '1px solid var(--accent-green)',
                              color: 'var(--accent-green)',
                              padding: '0.4rem 0.75rem',
                              borderRadius: '4px',
                              fontSize: '0.8rem',
                              cursor: 'pointer',
                              fontWeight: 600
                            }}
                          >
                            Unblock
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'alerts' && (
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem', color: 'var(--accent-cyan)' }}>
            Security Alerts (Latest 50)
          </h3>
          {alerts.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '2rem' }}>
              No alerts found
            </p>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>ID</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Timestamp</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Source IP</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Attack Type</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Risk Score</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Alert Level</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert) => (
                    <tr key={alert.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem' }}>{alert.id}</td>
                      <td style={{ padding: '0.75rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '—'}
                      </td>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem', fontFamily: 'monospace' }}>
                        {alert.source_ip}
                      </td>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem' }}>
                        <span style={{
                          background: 'rgba(239, 68, 68, 0.2)',
                          color: 'var(--accent-red)',
                          padding: '0.25rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.8rem'
                        }}>
                          {alert.attack_type}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem', color: 'var(--accent-red)' }}>
                        {alert.risk_score}
                      </td>
                      <td style={{ padding: '0.75rem' }}>
                        <span style={{
                          background: alert.alert_level === 'Critical' 
                            ? 'rgba(239, 68, 68, 0.2)' 
                            : 'rgba(245, 158, 11, 0.2)',
                          color: alert.alert_level === 'Critical' 
                            ? 'var(--accent-red)' 
                            : 'var(--accent-amber)',
                          padding: '0.25rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.8rem',
                          fontWeight: 600
                        }}>
                          {alert.alert_level}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'predictions' && (
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem', color: 'var(--accent-cyan)' }}>
            ML Model Predictions (Latest 50)
          </h3>
          {predictions.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '2rem' }}>
              No predictions found
            </p>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>ID</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Timestamp</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Attack</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Type</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Risk Score</th>
                    <th style={{ padding: '0.75rem', textAlign: 'left', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {predictions.map((pred) => (
                    <tr key={pred.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem' }}>{pred.id}</td>
                      <td style={{ padding: '0.75rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                        {pred.timestamp ? new Date(pred.timestamp).toLocaleString() : '—'}
                      </td>
                      <td style={{ padding: '0.75rem' }}>
                        <span style={{
                          background: pred.is_attack 
                            ? 'rgba(239, 68, 68, 0.2)' 
                            : 'rgba(16, 185, 129, 0.2)',
                          color: pred.is_attack 
                            ? 'var(--accent-red)' 
                            : 'var(--accent-green)',
                          padding: '0.25rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.8rem',
                          fontWeight: 600
                        }}>
                          {pred.is_attack ? 'Attack' : 'Normal'}
                        </span>
                      </td>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem' }}>
                        {pred.attack_type || '—'}
                      </td>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem' }}>
                        {pred.risk_score !== undefined ? pred.risk_score : '—'}
                      </td>
                      <td style={{ padding: '0.75rem', fontSize: '0.9rem' }}>
                        {pred.confidence !== undefined 
                          ? `${(pred.confidence * 100).toFixed(1)}%` 
                          : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'system' && (
        <div>
          <div className="kpi-grid">
            <KPICard
              title="Database Size"
              value={systemStats?.database_size || '—'}
              subtext="PostgreSQL Storage"
              icon="💾"
              accentColor="var(--accent-cyan)"
            />
            <KPICard
              title="Total Telemetry Logs"
              value={systemStats?.total_telemetry_logs?.toLocaleString() || '—'}
              subtext="Raw Log Entries"
              icon="📡"
              accentColor="var(--accent-blue)"
            />
            <KPICard
              title="Model Version"
              value={systemStats?.model_version || '—'}
              subtext="ML Model Build"
              icon="🧠"
              accentColor="var(--accent-purple)"
            />
            <KPICard
              title="Uptime"
              value={systemStats?.uptime || '—'}
              subtext="System Runtime"
              icon="⏱️"
              accentColor="var(--accent-green)"
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminPanel;
