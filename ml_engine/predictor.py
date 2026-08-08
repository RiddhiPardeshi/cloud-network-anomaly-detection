"""
Real-Time ML Prediction & Explainable AI (XAI) Engine.
Uses trained champion model (Random Forest / XGBoost) to predict cyber attack anomalies
and extracts feature importance to generate natural language diagnostic explanations.
Handles missing values, edge cases, type coercion, and robust error validation.
"""

import sys
import json
import logging
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
import sklearn

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import Config

logger = logging.getLogger(__name__)


class CloudAnomalyPredictor:
    """Singleton Real-Time Anomaly Predictor & Explainable AI Engine."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CloudAnomalyPredictor, cls).__new__(cls)
            cls._instance._load_artifacts()
        return cls._instance

    def _load_artifacts(self):
        """Load trained model, scaler, encoder, and feature names."""
        try:
            self.model_path = Config.MODELS_DIR / 'best_model.pkl'
            self.scaler_path = Config.MODELS_DIR / 'scaler.pkl'
            self.encoder_path = Config.MODELS_DIR / 'encoder.pkl'
            self.features_path = Config.MODELS_DIR / 'feature_names.json'

            if not self.model_path.exists():
                raise FileNotFoundError(f"Model file missing at {self.model_path}. Run training first.")
            if not self.scaler_path.exists():
                raise FileNotFoundError(f"Scaler file missing at {self.scaler_path}. Run training first.")
            if not self.encoder_path.exists():
                raise FileNotFoundError(f"Encoder file missing at {self.encoder_path}. Run training first.")

            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            self.encoder = joblib.load(self.encoder_path)

            with open(self.features_path, 'r') as f:
                self.feature_names = json.load(f)

            # Metadata properties
            self.model_type = type(self.model).__name__
            self.sklearn_version = sklearn.__version__

            # Global tree feature importances
            if hasattr(self.model, 'feature_importances_'):
                self.global_importances = dict(zip(self.feature_names, self.model.feature_importances_))
            else:
                self.global_importances = {feat: 1.0 / len(self.feature_names) for feat in self.feature_names}

            logger.info(f"CloudAnomalyPredictor initialized: Model={self.model_type}, Sklearn={self.sklearn_version}")
        except Exception as e:
            logger.error(f"Failed to load ML prediction artifacts: {e}")
            raise e

    def _sanitize_telemetry(self, raw_dict):
        """Clean, sanitize, and type-coerce raw telemetry inputs."""
        sanitized = {}
        for key in ['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Port', 
                    'Packets', 'Bytes', 'Request Count', 'Login Attempts', 
                    'CPU Usage', 'Memory Usage', 'Response Time']:
            # Accept camelCase, snake_case, or exact Schema capitalization
            alt_key = key.lower().replace(' ', '_')
            val = raw_dict.get(key)
            if val is None:
                val = raw_dict.get(alt_key)
            sanitized[key] = val

        # Handle fallback defaults & numeric bounds
        sanitized['Protocol'] = str(sanitized['Protocol'] or 'TCP').upper()
        if sanitized['Protocol'] not in getattr(self.encoder, 'classes_', ['HTTP', 'HTTPS', 'TCP', 'UDP']):
            sanitized['Protocol'] = 'TCP'

        try:
            sanitized['Port'] = max(1, min(65535, int(sanitized['Port'] if sanitized['Port'] is not None else 80)))
        except (ValueError, TypeError):
            sanitized['Port'] = 80

        try:
            sanitized['Packets'] = max(0, int(sanitized['Packets'] if sanitized['Packets'] is not None else 1))
        except (ValueError, TypeError):
            sanitized['Packets'] = 1

        try:
            sanitized['Bytes'] = max(0, int(sanitized['Bytes'] if sanitized['Bytes'] is not None else 500))
        except (ValueError, TypeError):
            sanitized['Bytes'] = 500

        try:
            sanitized['Request Count'] = max(0, int(sanitized['Request Count'] if sanitized['Request Count'] is not None else 1))
        except (ValueError, TypeError):
            sanitized['Request Count'] = 1

        try:
            sanitized['Login Attempts'] = max(0, int(sanitized['Login Attempts'] if sanitized['Login Attempts'] is not None else 0))
        except (ValueError, TypeError):
            sanitized['Login Attempts'] = 0

        try:
            sanitized['CPU Usage'] = max(0.0, min(100.0, float(sanitized['CPU Usage'] if sanitized['CPU Usage'] is not None else 10.0)))
        except (ValueError, TypeError):
            sanitized['CPU Usage'] = 10.0

        try:
            sanitized['Memory Usage'] = max(0.0, min(100.0, float(sanitized['Memory Usage'] if sanitized['Memory Usage'] is not None else 20.0)))
        except (ValueError, TypeError):
            sanitized['Memory Usage'] = 20.0

        try:
            sanitized['Response Time'] = max(0.0, float(sanitized['Response Time'] if sanitized['Response Time'] is not None else 50.0))
        except (ValueError, TypeError):
            sanitized['Response Time'] = 50.0

        return sanitized

    def _infer_attack_type(self, raw_telemetry, is_attack):
        """Infer attack type category based on telemetry metric thresholds."""
        if not is_attack:
            return 'Normal'

        packets = raw_telemetry.get('Packets', 0)
        bytes_cnt = raw_telemetry.get('Bytes', 0)
        req_cnt = raw_telemetry.get('Request Count', 0)
        login_att = raw_telemetry.get('Login Attempts', 0)
        cpu = raw_telemetry.get('CPU Usage', 0)
        resp_time = raw_telemetry.get('Response Time', 0)

        # 1. Brute Force Check (high login attempts)
        if login_att >= 5:
            return 'Brute Force'

        # 2. Port Scan Check (high requests to multiple ports, low packets per request, fast response)
        elif req_cnt >= 15 and packets <= 10 and resp_time <= 50.0:
            return 'Port Scan'

        # 3. DDoS Flood Check (massive packet volume, high request count, or high CPU spike)
        elif packets >= 500 or req_cnt >= 100 or cpu >= 75.0 or bytes_cnt >= 100000:
            return 'DDoS'

        # 4. Malicious Payload Check (large request payload / abnormal response time)
        elif bytes_cnt >= 10000 or resp_time >= 200.0:
            return 'Malicious Payload'

        else:
            return 'DDoS'


    def _generate_xai_explanation(self, raw_telemetry, top_features, attack_type, is_attack):
        """Generate human-readable Explainable AI diagnostic summary."""
        if not is_attack:
            return "Request behavior is normal. All network and system metrics are within standard baseline thresholds."

        feat_desc = []
        for feat, val, score in top_features:
            if feat == 'Packets':
                feat_desc.append(f"abnormally high packet volume ({val:,} packets)")
            elif feat == 'Bytes':
                feat_desc.append(f"excessive payload size ({val:,} bytes)")
            elif feat == 'CPU Usage':
                feat_desc.append(f"critical CPU utilization spike ({val:.1f}%)")
            elif feat == 'Memory Usage':
                feat_desc.append(f"high memory consumption ({val:.1f}%)")
            elif feat == 'Login Attempts':
                feat_desc.append(f"repeated failed authentication attempts ({val} logins)")
            elif feat == 'Response Time':
                feat_desc.append(f"severe request latency delay ({val:.1f} ms)")
            elif feat == 'Request Count':
                feat_desc.append(f"high request frequency per window ({val} reqs)")

        if feat_desc:
            reasons_str = ", ".join(feat_desc[:3])
            return f"Alert: Classified as '{attack_type}' due to {reasons_str}."
        else:
            return f"Alert: Classified as '{attack_type}' based on abnormal multi-source telemetry metrics."

    def predict(self, telemetry_data):
        """
        Main inference pipeline.
        Predicts binary label, probability confidence, attack category, top contributing features, and XAI text.
        """
        if hasattr(telemetry_data, 'to_dict'):
            raw_dict = telemetry_data.to_dict()
        elif isinstance(telemetry_data, dict):
            raw_dict = telemetry_data
        else:
            raw_dict = {}

        # 1. Sanitize & Coerce Types
        clean_dict = self._sanitize_telemetry(raw_dict)

        # 2. Encode Protocol & Extract Feature Vector
        protocol_str = clean_dict['Protocol']
        try:
            protocol_encoded = self.encoder.transform([protocol_str])[0]
        except Exception:
            protocol_encoded = 0

        feature_vector = [
            protocol_encoded,
            clean_dict['Port'],
            clean_dict['Packets'],
            clean_dict['Bytes'],
            clean_dict['Request Count'],
            clean_dict['Login Attempts'],
            clean_dict['CPU Usage'],
            clean_dict['Memory Usage'],
            clean_dict['Response Time']
        ]

        # 3. Scale Features & Predict
        input_df = pd.DataFrame([feature_vector], columns=self.feature_names)
        scaled_features = self.scaler.transform(input_df)
        scaled_df = pd.DataFrame(scaled_features, columns=self.feature_names)

        prediction_label = int(self.model.predict(scaled_df)[0])
        probabilities = self.model.predict_proba(scaled_df)[0]
        confidence = float(probabilities[prediction_label])
        confidence = max(0.0, min(1.0, confidence))  # Guarantee bound [0.0, 1.0]

        is_attack = bool(prediction_label == 1)
        attack_type = self._infer_attack_type(clean_dict, is_attack)

        # 4. Explainable AI Feature Contribution Calculation
        scaled_row = np.abs(scaled_features[0])
        feature_contributions = []

        for idx, feat_name in enumerate(self.feature_names):
            global_imp = self.global_importances.get(feat_name, 0.1)
            local_score = round(float(scaled_row[idx] * global_imp), 4)
            raw_val = clean_dict.get(feat_name, feature_vector[idx])
            feature_contributions.append((feat_name, raw_val, local_score))

        feature_contributions.sort(key=lambda x: x[2], reverse=True)
        top_features = feature_contributions[:4]

        explanation = self._generate_xai_explanation(clean_dict, top_features, attack_type, is_attack)

        top_features_list = [
            {'feature': f[0], 'value': f[1], 'importance_score': f[2]} for f in top_features
        ]

        return {
            'is_attack': is_attack,
            'prediction_label': prediction_label,
            'attack_type': attack_type,
            'confidence': round(confidence, 4),
            'top_features': top_features_list,
            'explanation': explanation,
            'sanitized_telemetry': clean_dict
        }
