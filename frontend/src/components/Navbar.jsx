import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import apiClient from '../api/axios';

const Navbar = ({ user, onLogout }) => {
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await apiClient.post('/api/auth/logout');
    } catch (err) {
      console.warn('Logout API error:', err);
    }
    localStorage.removeItem('user');
    if (onLogout) onLogout();
    navigate('/login');
  };

  const displayName = user?.name || user?.username || 'User';

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">⚡</div>
        <div>
          <div>CLOUD ANOMALY</div>
          <div style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
            SOC SECURITY ENGINE
          </div>
        </div>
      </div>

      <ul className="nav-menu">
        <li className="nav-item">
          <NavLink to="/dashboard" className={({ isActive }) => (isActive ? 'active' : '')}>
            📊 Dashboard
          </NavLink>
        </li>
        <li className="nav-item">
          <NavLink to="/simulator" className={({ isActive }) => (isActive ? 'active' : '')}>
            🚀 Attack Simulator
          </NavLink>
        </li>
        <li className="nav-item">
          <NavLink to="/model-metrics" className={({ isActive }) => (isActive ? 'active' : '')}>
            🧠 Model Metrics
          </NavLink>
        </li>
        <li className="nav-item">
          <NavLink to="/system-health" className={({ isActive }) => (isActive ? 'active' : '')}>
            💻 System Health
          </NavLink>
        </li>
      </ul>

      <div style={{ marginTop: 'auto', paddingTop: '1.5rem', borderTop: '1px solid var(--border-color)' }}>
        <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
          User: <span style={{ color: '#fff', fontWeight: 600 }}>{displayName}</span>
        </div>
        <button
          onClick={handleLogout}
          className="btn-danger"
          style={{ width: '100%', padding: '0.5rem', fontSize: '0.85rem' }}
        >
          Logout
        </button>
      </div>
    </aside>
  );
};

export default Navbar;
