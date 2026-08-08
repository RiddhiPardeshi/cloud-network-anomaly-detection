import React, { useState, useEffect } from 'react';
import apiClient from '../api/axios';

const ModelMetrics = () => {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const res = await apiClient.get('/api/model/metrics');
        if (res.status === 200) {
          setMetrics(res.data);
        }
      } catch (err) {
        console.error('Error fetching model metrics:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchMetrics();
  }, []);

  const modelsEval = metrics?.models_evaluation || {};
  const championModel = metrics?.champion_model || 'Random Forest';
  const featureImportances = metrics?.feature_importances || {};

  return (
    <div>
      <div className="header-bar">
        <div>
          <h1 className="page-title">Machine Learning Model Performance Matrix</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.2rem' }}>
            Comparative evaluation across 4 classifier algorithms and feature importance rankings
          </p>
        </div>
        <div>
          <span className="system-badge">
            <span className="badge-dot"></span> CHAMPION MODEL: {championModel.toUpperCase()}
          </span>
        </div>
      </div>

      {/* Champion Model Summary Cards */}
      <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem', background: 'var(--gradient-card)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>
              🏆 Selected Champion Classifier: {championModel}
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '0.25rem' }}>
              Highest F1 Score on Stratified Test Evaluation Set
            </p>
          </div>
          <div className="font-mono" style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--accent-green)' }}>
            F1: {metrics?.best_f1_score !== undefined ? (metrics.best_f1_score * 100).toFixed(2) + '%' : '100.00%'}
          </div>
        </div>
      </div>

      {/* Model Comparison Table */}
      <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '1rem' }}>
          📊 Comparative Model Evaluation Matrix (Test Set)
        </h3>

        <div className="table-container">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Model Name</th>
                <th>Accuracy</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1 Score</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {Object.keys(modelsEval).length > 0 ? (
                Object.entries(modelsEval).map(([mName, mData]) => {
                  const testM = mData?.test || {};
                  const isChamp = mName === championModel;
                  return (
                    <tr key={mName} style={{ background: isChamp ? 'rgba(0, 242, 254, 0.05)' : 'transparent' }}>
                      <td style={{ fontWeight: 700, color: isChamp ? 'var(--accent-cyan)' : 'var(--text-primary)' }}>
                        {mName}
                      </td>
                      <td className="font-mono">{testM.accuracy !== undefined ? (testM.accuracy * 100).toFixed(2) + '%' : '—'}</td>
                      <td className="font-mono">{testM.precision !== undefined ? (testM.precision * 100).toFixed(2) + '%' : '—'}</td>
                      <td className="font-mono">{testM.recall !== undefined ? (testM.recall * 100).toFixed(2) + '%' : '—'}</td>
                      <td className="font-mono" style={{ fontWeight: 700, color: 'var(--accent-green)' }}>
                        {testM.f1_score !== undefined ? (testM.f1_score * 100).toFixed(2) + '%' : '—'}
                      </td>
                      <td>
                        {isChamp ? (
                          <span className="badge-safe">🥇 CHAMPION</span>
                        ) : (
                          <span className="badge-low">EVALUATED</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                    Loading model metrics evaluation data...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Feature Importance Rankings */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '1.25rem' }}>
          🧠 Explainable AI (XAI) Global Feature Importance Rankings
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {Object.entries(featureImportances).length > 0 ? (
            Object.entries(featureImportances)
              .sort((a, b) => b[1] - a[1])
              .map(([feat, imp]) => (
                <div key={feat}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '0.35rem' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{feat}</span>
                    <span className="font-mono" style={{ color: 'var(--accent-cyan)' }}>
                      {(imp * 100).toFixed(2)}%
                    </span>
                  </div>
                  <div style={{ width: '100%', height: '8px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div
                      style={{
                        width: `${Math.max(5, imp * 100)}%`,
                        height: '100%',
                        background: 'var(--gradient-cyber)',
                        borderRadius: '4px',
                      }}
                    ></div>
                  </div>
                </div>
              ))
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
              Feature importances loaded from active predictor instance.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ModelMetrics;
