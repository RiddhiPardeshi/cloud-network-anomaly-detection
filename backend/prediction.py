"""
Prediction Blueprint for Cloud Network Anomaly Detection.
Provides REST APIs for real-time machine learning prediction and Explainable AI diagnostics.
"""

import time
import json
import logging
from flask import Blueprint, request, jsonify
from backend.db import db, TelemetryLog, PredictionLog
from ml_engine.predictor import CloudAnomalyPredictor
from backend.risk_engine import calculate_risk_score
from config import Config

# Define Blueprint
prediction_bp = Blueprint('prediction', __name__)
logger = logging.getLogger(__name__)


def compute_deterministic_risk_score(is_attack, confidence, raw_dict):
    """Wrapper using central backend.risk_engine module."""
    score, category, _ = calculate_risk_score(is_attack, confidence, raw_dict)
    return score, category



@prediction_bp.route('/single', methods=['POST'])
def predict_single():
    """
    POST /api/predict/single
    Predict cyber attack anomaly for a single telemetry payload.
    """
    start_time = time.time()
    try:
        data = request.get_json(silent=True)
        if data is None:
            data = {}

        predictor = CloudAnomalyPredictor()

        # Execute ML inference & XAI explanation
        result = predictor.predict(data)
        execution_latency_ms = round((time.time() - start_time) * 1000, 2)

        source_ip = data.get('Source IP') or data.get('source_ip') or request.remote_addr or '127.0.0.1'
        raw_dict = result['sanitized_telemetry']

        # Calculate Risk Score
        risk_score, risk_category = compute_deterministic_risk_score(
            result['is_attack'], result['confidence'], raw_dict
        )

        # Store prediction log in database
        pred_entry = PredictionLog(
            telemetry_id=data.get('telemetry_id'),
            source_ip=source_ip,
            attack_type=result['attack_type'],
            is_attack=result['is_attack'],
            confidence=result['confidence'],
            risk_score=risk_score,
            risk_category=risk_category,
            top_features_json=json.dumps(result['top_features']),
            explanation=result['explanation']
        )

        db.session.add(pred_entry)
        db.session.commit()

        # Automated mitigation check: trigger if Risk Score >= 81 (Critical)
        if risk_score >= Config.RISK_THRESHOLD_CRITICAL:
            from backend.mitigation import trigger_automatic_mitigation
            trigger_automatic_mitigation(
                source_ip=source_ip,
                attack_type=result['attack_type'],
                risk_score=risk_score,
                confidence=result['confidence'],
                top_features=result['top_features'],
                dest_ip=data.get('Destination IP') or data.get('destination_ip') or '10.0.0.1'
            )

        logger.info(
            f"Prediction complete: ID={pred_entry.id}, IP={source_ip}, "
            f"Attack={result['attack_type']}, Confidence={result['confidence']}, "
            f"Risk={risk_score} ({risk_category}), Latency={execution_latency_ms}ms"
        )

        return jsonify({
            'prediction_id': pred_entry.id,
            'telemetry_id': pred_entry.telemetry_id,
            'timestamp': pred_entry.timestamp.isoformat(),
            'source_ip': source_ip,
            'is_attack': result['is_attack'],
            'attack_type': result['attack_type'],
            'confidence': result['confidence'],
            'risk_score': risk_score,
            'risk_category': risk_category,
            'model_name': predictor.model_type,
            'response_time_ms': execution_latency_ms,
            'top_features': result['top_features'],
            'explanation': result['explanation']
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Prediction failed: {e}", exc_info=True)
        return jsonify({'error': 'Failed to execute real-time prediction.', 'details': str(e)}), 500


@prediction_bp.route('/telemetry/<int:telemetry_id>', methods=['POST'])
def predict_by_telemetry_id(telemetry_id):
    """
    POST /api/predict/telemetry/<telemetry_id>
    Predict anomaly for an existing stored TelemetryLog record.
    """
    start_time = time.time()
    try:
        telemetry = TelemetryLog.query.get(telemetry_id)
        if not telemetry:
            logger.warning(f"Prediction request for non-existent telemetry ID: {telemetry_id}")
            return jsonify({'error': f'TelemetryLog with ID {telemetry_id} not found.'}), 404

        predictor = CloudAnomalyPredictor()
        feature_vector = telemetry.to_ml_feature_vector()

        result = predictor.predict(feature_vector)
        execution_latency_ms = round((time.time() - start_time) * 1000, 2)

        risk_score, risk_category = compute_deterministic_risk_score(
            result['is_attack'], result['confidence'], feature_vector
        )

        pred_entry = PredictionLog(
            telemetry_id=telemetry.id,
            source_ip=telemetry.source_ip,
            attack_type=result['attack_type'],
            is_attack=result['is_attack'],
            confidence=result['confidence'],
            risk_score=risk_score,
            risk_category=risk_category,
            top_features_json=json.dumps(result['top_features']),
            explanation=result['explanation']
        )

        db.session.add(pred_entry)
        db.session.commit()

        if risk_score >= Config.RISK_THRESHOLD_CRITICAL:
            from backend.mitigation import trigger_automatic_mitigation
            trigger_automatic_mitigation(
                source_ip=telemetry.source_ip,
                attack_type=result['attack_type'],
                risk_score=risk_score,
                confidence=result['confidence'],
                top_features=result['top_features'],
                dest_ip=telemetry.destination_ip
            )

        return jsonify({
            'prediction_id': pred_entry.id,
            'telemetry_id': telemetry.id,
            'timestamp': pred_entry.timestamp.isoformat(),
            'source_ip': telemetry.source_ip,
            'is_attack': result['is_attack'],
            'attack_type': result['attack_type'],
            'confidence': result['confidence'],
            'risk_score': risk_score,
            'risk_category': risk_category,
            'model_name': predictor.model_type,
            'response_time_ms': execution_latency_ms,
            'top_features': result['top_features'],
            'explanation': result['explanation']
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Prediction by telemetry ID {telemetry_id} failed: {e}")
        return jsonify({'error': 'Failed to execute prediction.'}), 500


@prediction_bp.route('/recent', methods=['GET'])
def get_recent_predictions():
    """
    GET /api/predict/recent?limit=50
    Retrieve recent anomaly prediction logs ordered by timestamp.
    """
    try:
        limit = request.args.get('limit', default=50, type=int)
        limit = min(max(limit, 1), 500)
        records = PredictionLog.query.order_by(PredictionLog.timestamp.desc()).limit(limit).all()
        return jsonify({
            'count': len(records),
            'predictions': [r.to_dict() for r in records]
        }), 200
    except Exception as e:
        logger.error(f"Error fetching predictions: {e}")
        return jsonify({'error': 'Failed to fetch prediction history.'}), 500
