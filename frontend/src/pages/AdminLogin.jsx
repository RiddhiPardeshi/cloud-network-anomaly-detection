import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import apiClient from '../api/axios';

const AdminLogin = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await apiClient.post('/api/auth/admin-login', {
        username,
        password,
      });

      if (response.status === 200 && response.data?.user) {
        const userData = response.data.user;
        
        // Verify admin role
        if (userData.role !== 'admin') {
          setError('Access denied. Admin privileges required.');
          setLoading(false);
          return;
        }
        
        localStorage.setItem('user', JSON.stringify(userData));
        if (onLoginSuccess) {
          onLoginSuccess(userData);
        }
        navigate('/dashboard');
      } else {
        setError(response.data?.error || 'Admin login failed.');
      }
    } catch (err) {
      console.error('Admin login error:', err);
      setError(err.response?.data?.error || 'Invalid admin credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="glass-panel login-box">
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div
            style={{
              width: '54px',
              height: '54px',
              background: 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)',
              borderRadius: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 1rem',
              fontSize: '1.75rem',
              color: '#fff',
              fontWeight: 800,
              boxShadow: '0 0 20px rgba(220, 38, 38, 0.4)',
            }}
          >
            🛡️
          </div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--accent-red)' }}>
            ADMIN ACCESS PORTAL
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '0.25rem' }}>
            Security Operations Center Administrative Console
          </p>
        </div>

        {error && (
          <div
            style={{
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid var(--accent-red)',
              color: 'var(--accent-red)',
              padding: '0.75rem',
              borderRadius: '8px',
              fontSize: '0.85rem',
              marginBottom: '1.25rem',
            }}
          >
            🚫 {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>
              ADMIN USERNAME
            </label>
            <input
              type="text"
              className="cyber-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter admin username"
              required
              autoComplete="username"
              style={{
                borderColor: 'var(--accent-red)',
                boxShadow: '0 0 10px rgba(220, 38, 38, 0.1)',
              }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>
              ADMIN PASSWORD
            </label>
            <input
              type="password"
              className="cyber-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
              autoComplete="current-password"
              style={{
                borderColor: 'var(--accent-red)',
                boxShadow: '0 0 10px rgba(220, 38, 38, 0.1)',
              }}
            />
          </div>

          <button
            type="submit"
            className="btn-cyber"
            disabled={loading}
            style={{
              width: '100%',
              marginTop: '0.5rem',
              padding: '0.85rem',
              background: 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)',
              border: '1px solid var(--accent-red)',
              boxShadow: '0 0 20px rgba(220, 38, 38, 0.3)',
            }}
          >
            {loading ? 'AUTHENTICATING...' : '🔐 ADMIN LOGIN'}
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: '1.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          <Link to="/login" style={{ color: 'var(--accent-cyan)', textDecoration: 'none', fontWeight: 600 }}>
            ← Back to User Login
          </Link>
        </div>

        <div
          style={{
            marginTop: '1.5rem',
            padding: '0.75rem',
            background: 'rgba(220, 38, 38, 0.1)',
            border: '1px solid rgba(220, 38, 38, 0.3)',
            borderRadius: '8px',
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
            textAlign: 'center',
          }}
        >
          ⚠️ Authorized Personnel Only • All Access Attempts Logged
        </div>
      </div>
    </div>
  );
};

export default AdminLogin;
