"""
Unified System API Router & Gateway Blueprint for Cloud Network Anomaly Detection.
Exposes System Status Gateway, Model Performance Metrics API, and Database Health Monitoring.
"""

import json
import logging
from flask import Blueprint, jsonify
from backend.db import db, User, TelemetryLog, PredictionLog, BlockedIP, AttackAlert
from backend.simulator import traffic_simulator
from ml_engine.predictor import CloudAnomalyPredictor
from config import Config

api_bp = Blueprint('api', __name__)
logger = logging.getLogger(__name__)


@api_bp.route('/system/status', methods=['GET'])
def get_system_status():
    """
    GET /api/system/status
    Returns comprehensive system health status:
    - Database Status & Table Record Counts
    - ML Model Engine Status & Champion Artifacts
    - Background Traffic Simulator State
    - Security Configuration & Threshold Settings
    """
    try:
        # 1. Database Status
        db_status = "online"
        try:
            db.session.execute(db.text("SELECT 1"))
            user_cnt = db.session.query(db.func.count(User.id)).scalar() or 0
            telemetry_cnt = db.session.query(db.func.count(TelemetryLog.id)).scalar() or 0
            pred_cnt = db.session.query(db.func.count(PredictionLog.id)).scalar() or 0
            blocked_cnt = db.session.query(db.func.count(BlockedIP.id)).filter(BlockedIP.is_active == True).scalar() or 0
            alert_cnt = db.session.query(db.func.count(AttackAlert.id)).scalar() or 0
        except Exception as db_err:
            logger.error(f"Database health check failed: {db_err}")
            db_status = "error"
            user_cnt = telemetry_cnt = pred_cnt = blocked_cnt = alert_cnt = 0

        # 2. ML Engine Status
        ml_status = "online"
        try:
            predictor = CloudAnomalyPredictor()
            model_name = predictor.model_type
            feature_names = predictor.feature_names
            feature_count = len(feature_names)
            feature_importances = predictor.global_importances
        except Exception as ml_err:
            logger.warning(f"ML Predictor artifact check: {ml_err}")
            ml_status = "degraded"
            model_name = "RandomForestClassifier"
            feature_names = []
            feature_count = 9
            feature_importances = {}

        # 3. Simulator Status
        sim_status = {
            'is_running': traffic_simulator.is_running,
            'scenario': traffic_simulator.scenario,
            'rate_per_sec': traffic_simulator.rate_per_sec,
            'total_generated': traffic_simulator.stats['total_generated'],
            'attacks_generated': traffic_simulator.stats['attacks_generated']
        }

        # 4. Security Configuration
        security_config = {
            'risk_threshold_high': Config.RISK_THRESHOLD_HIGH,
            'risk_threshold_critical': Config.RISK_THRESHOLD_CRITICAL,
            'alert_email_sender': Config.ALERT_EMAIL_SENDER,
            'alert_email_recipient': Config.ALERT_EMAIL_RECIPIENT,
            'smtp_configured': bool(Config.SMTP_USER and Config.SMTP_PASSWORD)
        }

        return jsonify({
            'system_status': 'healthy' if db_status == 'online' else 'degraded',
            'timestamp': Config.BASE_DIR.stat().st_mtime if Config.BASE_DIR.exists() else None,
            'database': {
                'status': db_status,
                'counts': {
                    'users': user_cnt,
                    'telemetry_logs': telemetry_cnt,
                    'prediction_logs': pred_cnt,
                    'active_blocked_ips': blocked_cnt,
                    'attack_alerts': alert_cnt
                }
            },
            'ml_engine': {
                'status': ml_status,
                'champion_model': model_name,
                'feature_count': feature_count,
                'feature_names': feature_names,
                'feature_importances': feature_importances
            },
            'simulator': sim_status,
            'security_config': security_config
        }), 200

    except Exception as e:
        logger.error(f"Error compiling system status: {e}", exc_info=True)
        return jsonify({'error': 'Failed to compile system status.'}), 500


@api_bp.route('/model/metrics', methods=['GET'])
def get_model_metrics():
    """
    GET /api/model/metrics
    Exposes champion ML model evaluation metrics, comparative classifier results,
    confusion matrices, and global feature importance rankings from models/metrics.json.
    """
    try:
        metrics_file = Config.MODELS_DIR / 'metrics.json'
        if not metrics_file.exists():
            return jsonify({'error': 'Model evaluation metrics.json file not found.'}), 404

        with open(metrics_file, 'r') as f:
            metrics_data = json.load(f)

        # Inject feature importances from predictor artifact
        try:
            predictor = CloudAnomalyPredictor()
            metrics_data['feature_importances'] = predictor.global_importances
            metrics_data['feature_columns'] = predictor.feature_names
        except Exception as e:
            logger.warning(f"Could not load predictor for feature importances: {e}")

        return jsonify(metrics_data), 200

    except Exception as e:
        logger.error(f"Error retrieving model evaluation metrics: {e}")
        return jsonify({'error': 'Failed to retrieve model metrics.'}), 500
