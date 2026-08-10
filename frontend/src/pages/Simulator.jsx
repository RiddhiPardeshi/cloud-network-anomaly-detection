import React, { useState, useEffect } from 'react';
import apiClient from '../api/axios';
import KPICard from '../components/KPICard';

const Simulator = () => {
  const [status, setStatus] = useState(null);
  const [scenario, setScenario] = useState('Mixed');
  const [rate, setRate] = useState(2.0);
  const [duration, setDuration] = useState(60);
  const [selectedInject, setSelectedInject] = useState('DDoS');
  const [injectionResult, setInjectionResult] = useState(null);
  
  // Separate status messages & error messages for continuous simulation vs instant injection
  const [continuousMessage, setContinuousMessage] = useState('');
  const [continuousError, setContinuousError] = useState('');
  const [injectionMessage, setInjectionMessage] = useState('');
  const [injectionError, setInjectionError] = useState('');

  const fetchSimulatorStatus = async () => {
    try {
      const res = await apiClient.get('/api/simulator/status');
      if (res.status === 200) {
        setStatus(res.data);
      }
    } catch (err) {
      console.error('Error fetching simulator status:', err);
    }
  };

  useEffect(() => {
    fetchSimulatorStatus();
    const interval = setInterval(fetchSimulatorStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleStart = async () => {
    setContinuousMessage('');
    setContinuousError('');
    try {
      const res = await apiClient.post('/api/simulator/start', {
        scenario,
        rate: parseFloat(rate),
        duration: parseInt(duration, 10),
      });
      setContinuousMessage(res.data.message || 'Continuous background simulator started.');
      await fetchSimulatorStatus();
    } catch (err) {
      console.error('Failed to start simulator:', err);
      const errMsg = err.response?.data?.error || err.response?.data?.details || 'Failed to start simulator.';
      setContinuousError(errMsg);
    }
  };

  const handleStop = async () => {
    setContinuousMessage('');
    setContinuousError('');
    try {
      const res = await apiClient.post('/api/simulator/stop');
      setContinuousMessage(res.data.message || 'Continuous background simulator stopped.');
      await fetchSimulatorStatus();
    } catch (err) {
      console.error('Failed to stop simulator:', err);
      const errMsg = err.response?.data?.error || err.response?.data?.details || 'Failed to stop simulator.';
      setContinuousError(errMsg);
    }
  };

  const handleTriggerAttack = async () => {
    setInjectionMessage('');
    setInjectionError('');
    try {
      const res = await apiClient.post('/api/simulator/trigger-attack', {
        attack_type: selectedInject,
      });
      const data = res.data;
      const resResult = data.pipeline_result || data;
      setInjectionResult(resResult);
      setInjectionMessage(data.message || `Successfully injected attack scenario: ${selectedInject}`);
      
      // Refresh KPI counters immediately after successful injection
      await fetchSimulatorStatus();
    } catch (err) {
      console.error('Failed to inject attack:', err);
      const errMsg = err.response?.data?.error || err.response?.data?.details || err.message || 'Failed to inject attack scenario.';
      setInjectionError(errMsg);
    }
  };

  return (
    <div>
      <div className="header-bar">
        <div>
          <h1 className="page-title">Real-Time Cyber Attack & Traffic Simulator</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.2rem' }}>
            Multithreaded Background Traffic Generator feeding the detection & response pipeline
          </p>
        </div>
        <div>
          <span className={(status?.status === 'running' || status?.is_running) ? 'system-badge' : 'badge-critical'}>
            <span className="badge-dot"></span>
            {(status?.status === 'running' || status?.is_running) ? 'SIMULATOR ACTIVE' : 'SIMULATOR STOPPED'}
          </span>
        </div>
      </div>

      {/* Simulator Execution Counters Grid (Database Backed) */}
      <div className="kpi-grid">
        <KPICard
          title="Total Generated"
          value={status?.total_generated ?? status?.stats?.total_generated ?? 0}
          subtext="Simulated Telemetry Records"
          icon="⚡"
          accentColor="var(--accent-cyan)"
        />
        <KPICard
          title="Normal Traffic"
          value={status?.normal_events ?? status?.stats?.normal_generated ?? 0}
          subtext="Baseline Events"
          icon="🟢"
          accentColor="var(--accent-green)"
        />
        <KPICard
          title="Attacks Generated"
          value={status?.attack_events ?? status?.stats?.attacks_generated ?? 0}
          subtext="Malicious Payloads"
          icon="🔥"
          accentColor="var(--accent-red)"
        />
        <KPICard
          title="Auto Blocks Triggered"
          value={status?.blocked_ips ?? status?.stats?.auto_blocks_triggered ?? 0}
          subtext="Critical Threat Mitigations"
          icon="🔒"
          accentColor="var(--accent-amber)"
        />
      </div>

      {/* Simulator Controls & Trigger Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1.5rem', marginBottom: '2rem' }}>
        {/* Continuous Simulator Panel */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '1.25rem' }}>
            ⚙️ Continuous Background Simulation
          </h3>

          {continuousMessage && (
            <div
              style={{
                background: 'rgba(0, 242, 254, 0.1)',
                border: '1px solid var(--accent-cyan)',
                color: 'var(--accent-cyan)',
                padding: '0.75rem 1rem',
                borderRadius: '6px',
                marginBottom: '1rem',
                fontSize: '0.85rem',
              }}
            >
              💡 {continuousMessage}
            </div>
          )}

          {continuousError && (
            <div
              style={{
                background: 'rgba(255, 75, 75, 0.15)',
                border: '1px solid var(--accent-red)',
                color: 'var(--accent-red)',
                padding: '0.75rem 1rem',
                borderRadius: '6px',
                marginBottom: '1rem',
                fontSize: '0.85rem',
              }}
            >
              ⚠️ {continuousError}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                TRAFFIC SCENARIO
              </label>
              <select
                className="cyber-select"
                value={scenario}
                onChange={(e) => setScenario(e.target.value)}
                disabled={status?.is_running}
              >
                <option value="Mixed">Mixed Traffic (60% Normal, 40% Attacks)</option>
                <option value="Normal">Normal Traffic Stream</option>
                <option value="DDoS">DDoS Flood Attack</option>
                <option value="Port Scan">Port Scan Reconnaissance</option>
                <option value="Brute Force">Brute Force Authentication Attack</option>
                <option value="Malicious Payload">Malicious Exploit Payload</option>
              </select>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                  RATE (REQ/SEC)
                </label>
                <input
                  type="number"
                  step="0.5"
                  className="cyber-input"
                  value={rate}
                  onChange={(e) => setRate(e.target.value)}
                  disabled={status?.is_running}
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                  DURATION (SEC)
                </label>
                <input
                  type="number"
                  className="cyber-input"
                  value={duration}
                  onChange={(e) => setDuration(e.target.value)}
                  disabled={status?.is_running}
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem' }}>
              <button
                className="btn-cyber"
                onClick={handleStart}
                disabled={status?.is_running}
                style={{ flex: 1 }}
              >
                ▶️ START SIMULATION
              </button>
              <button
                className="btn-danger"
                onClick={handleStop}
                disabled={!status?.is_running}
                style={{ flex: 1 }}
              >
                ⏹️ STOP SIMULATION
              </button>
            </div>
          </div>
        </div>

        {/* Instant Single Attack Injection */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '1.2rem', fontWeight: 700, marginBottom: '1.25rem' }}>
            💥 Instant Scenario Injection
          </h3>

          {injectionMessage && (
            <div
              style={{
                background: 'rgba(0, 242, 254, 0.1)',
                border: '1px solid var(--accent-cyan)',
                color: 'var(--accent-cyan)',
                padding: '0.75rem 1rem',
                borderRadius: '6px',
                marginBottom: '1rem',
                fontSize: '0.85rem',
              }}
            >
              💡 {injectionMessage}
            </div>
          )}

          {injectionError && (
            <div
              style={{
                background: 'rgba(255, 75, 75, 0.15)',
                border: '1px solid var(--accent-red)',
                color: 'var(--accent-red)',
                padding: '0.75rem 1rem',
                borderRadius: '6px',
                marginBottom: '1rem',
                fontSize: '0.85rem',
              }}
            >
              ⚠️ {injectionError}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                SELECT ATTACK SCENARIO TO INJECT
              </label>
              <select
                className="cyber-select"
                value={selectedInject}
                onChange={(e) => setSelectedInject(e.target.value)}
              >
                <option value="DDoS">DDoS Flood Vector</option>
                <option value="Port Scan">Port Scan Probe</option>
                <option value="Brute Force">Brute Force Auth Burst</option>
                <option value="Malicious Payload">Malicious HTTP Payload</option>
                <option value="Normal">Normal Request Baseline</option>
              </select>
            </div>

            <button className="btn-cyber" onClick={handleTriggerAttack} style={{ marginTop: '0.5rem' }}>
              ⚡ TRIGGER INSTANT ATTACK
            </button>

            {injectionResult && (
              <div
                style={{
                  background: 'rgba(15, 23, 42, 0.9)',
                  padding: '1rem',
                  borderRadius: '8px',
                  border: '1px solid var(--border-color)',
                  marginTop: '0.5rem',
                }}
              >
                <div style={{ fontWeight: 600, color: 'var(--accent-cyan)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                  PIPELINE EXECUTION RESULT:
                </div>
                <div className="font-mono" style={{ fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                  <div>Source IP: <span style={{ color: '#fff' }}>{injectionResult.source_ip}</span></div>
                  <div>Attack Type: <span style={{ color: '#fff' }}>{injectionResult.attack_type}</span></div>
                  <div>Prediction: <span style={{ color: injectionResult.is_attack ? 'var(--accent-red)' : 'var(--accent-green)', fontWeight: 700 }}>
                    {injectionResult.prediction || (injectionResult.is_attack ? 'Attack' : 'Normal')}
                  </span></div>
                  <div>Confidence: <span style={{ color: '#fff' }}>
                    {injectionResult.confidence !== undefined ? (injectionResult.confidence * 100).toFixed(2) + '%' : '100.00%'}
                  </span></div>
                  <div>Risk Score: <span style={{ color: injectionResult.risk_score >= 81 ? 'var(--accent-red)' : injectionResult.risk_score >= 51 ? 'var(--accent-amber)' : 'var(--accent-green)', fontWeight: 700 }}>
                    {injectionResult.risk_score} ({injectionResult.risk_level || injectionResult.risk_category || 'Safe'})
                  </span></div>
                  <div>
                    Auto Block: <span style={{ fontWeight: 700 }}>
                      {injectionResult.auto_mitigation_triggered ? '🔒 YES (BLOCKED)' : '👁️ NO (SAFE)'}
                    </span>
                  </div>
                  <div>Block Status: <span style={{ color: 'var(--text-secondary)' }}>
                    {injectionResult.block_status || (injectionResult.auto_mitigation_triggered ? 'IP Blocked' : 'Monitoring Only')}
                  </span></div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Simulator;
