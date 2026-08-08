"""
Automated Mitigation & Incident Alerting Blueprint for Cloud Network Anomaly Detection.
Provides API endpoints for automated IP blocking, alert logging, email notification dispatch,
and manual firewall rule overrides.
"""

import json
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from backend.db import db, BlockedIP, AttackAlert
from backend.risk_engine import calculate_risk_score, send_security_alert_email
from config import Config

mitigation_bp = Blueprint('mitigation', __name__)
logger = logging.getLogger(__name__)


def trigger_automatic_mitigation(source_ip, attack_type, risk_score, confidence, top_features=None, dest_ip='10.0.0.1'):
    """
    Automated Mitigation Engine Action:
    Triggers when Risk Score >= 81 (Critical Risk).
    1. Blocks Source IP in BlockedIP table.
    2. Dispatches SMTP email alert.
    3. Logs incident record in AttackAlert table.
    """
    if top_features is None:
        top_features = []

    # 1. Block Source IP in database if not already blocked
    blocked_entry = BlockedIP.query.filter_by(ip_address=source_ip).first()
    if not blocked_entry:
        blocked_entry = BlockedIP(
            ip_address=source_ip,
            reason=f"Automated Block: Critical {attack_type} Threat Detected",
            risk_score=risk_score,
            is_active=True
        )
        db.session.add(blocked_entry)
    else:
        blocked_entry.is_active = True
        blocked_entry.reason = f"Automated Re-Block: Critical {attack_type} Threat"
        blocked_entry.risk_score = risk_score
        blocked_entry.blocked_at = datetime.utcnow()

    # 2. Dispatch SMTP Security Email Alert
    alert_payload = {
        'timestamp': datetime.utcnow().isoformat(),
        'source_ip': source_ip,
        'destination_ip': dest_ip,
        'attack_type': attack_type,
        'confidence': confidence,
        'risk_score': risk_score,
        'top_features': top_features,
        'block_status': f"IP {source_ip} Automatically Blocked in Active Firewall"
    }

    email_sent = send_security_alert_email(alert_payload)

    # 3. Create AttackAlert record
    alert_entry = AttackAlert(
        source_ip=source_ip,
        attack_type=attack_type,
        risk_score=risk_score,
        alert_level='Critical' if risk_score >= 81 else 'High',
        notification_sent=email_sent,
        details_json=json.dumps(alert_payload)
    )
    db.session.add(alert_entry)
    db.session.commit()

    logger.info(f"Automated mitigation executed for IP={source_ip}: Blocked=True, Alert_ID={alert_entry.id}, Email={email_sent}")
    return blocked_entry, alert_entry, email_sent


@mitigation_bp.route('/evaluate', methods=['POST'])
def evaluate_and_mitigate():
    """
    POST /api/mitigation/evaluate
    Evaluates telemetry/prediction results and triggers automatic IP blocking and email alert
    if Risk Score >= 81.
    """
    try:
        data = request.get_json(silent=True) or {}
        source_ip = data.get('source_ip') or data.get('Source IP') or '127.0.0.1'
        dest_ip = data.get('destination_ip') or data.get('Destination IP') or '10.0.0.1'
        attack_type = data.get('attack_type') or data.get('Attack Type') or 'DDoS'
        confidence = float(data.get('confidence', 0.95))
        is_attack = bool(data.get('is_attack', True))
        top_features = data.get('top_features', [])

        risk_score = data.get('risk_score')
        if risk_score is None:
            risk_score, category, _ = calculate_risk_score(is_attack, confidence, data)
        else:
            risk_score = float(risk_score)

        if risk_score >= Config.RISK_THRESHOLD_CRITICAL:  # >= 81
            blocked_entry, alert_entry, email_sent = trigger_automatic_mitigation(
                source_ip=source_ip,
                attack_type=attack_type,
                risk_score=risk_score,
                confidence=confidence,
                top_features=top_features,
                dest_ip=dest_ip
            )
            return jsonify({
                'action_taken': 'blocked',
                'auto_mitigation': True,
                'risk_score': risk_score,
                'risk_category': 'Critical',
                'blocked_ip': blocked_entry.to_dict(),
                'alert': alert_entry.to_dict(),
                'email_notification_sent': email_sent
            }), 200
        else:
            return jsonify({
                'action_taken': 'monitored',
                'auto_mitigation': False,
                'risk_score': risk_score,
                'message': 'Risk score is below critical response threshold (81). No blocking action taken.'
            }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error evaluating mitigation: {e}", exc_info=True)
        return jsonify({'error': 'Failed to execute mitigation evaluation.', 'details': str(e)}), 500


@mitigation_bp.route('/block', methods=['POST'])
def manual_block_ip():
    """
    POST /api/mitigation/block
    Manually block an IP address.
    """
    try:
        data = request.get_json(silent=True) or {}
        ip_address = data.get('ip_address') or data.get('source_ip')
        if not ip_address:
            return jsonify({'error': 'ip_address is required.'}), 400

        reason = data.get('reason', 'Manual Security Administration Block')
        risk_score = float(data.get('risk_score', 85.0))

        blocked_entry = BlockedIP.query.filter_by(ip_address=ip_address).first()
        if not blocked_entry:
            blocked_entry = BlockedIP(
                ip_address=ip_address,
                reason=reason,
                risk_score=risk_score,
                is_active=True
            )
            db.session.add(blocked_entry)
        else:
            blocked_entry.is_active = True
            blocked_entry.reason = reason
            blocked_entry.risk_score = risk_score
            blocked_entry.blocked_at = datetime.utcnow()

        db.session.commit()
        logger.info(f"Manual IP Block registered: {ip_address}")

        return jsonify({
            'message': f"IP address {ip_address} blocked successfully.",
            'blocked_ip': blocked_entry.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error blocking IP: {e}")
        return jsonify({'error': 'Failed to block IP address.'}), 500


@mitigation_bp.route('/unblock', methods=['POST'])
def unblock_ip():
    """
    POST /api/mitigation/unblock
    Unblock an active IP address.
    """
    try:
        data = request.get_json(silent=True) or {}
        ip_address = data.get('ip_address') or data.get('source_ip')
        if not ip_address:
            return jsonify({'error': 'ip_address is required.'}), 400

        blocked_entry = BlockedIP.query.filter_by(ip_address=ip_address, is_active=True).first()
        if not blocked_entry:
            return jsonify({'error': f"Active block for IP '{ip_address}' not found."}), 404

        blocked_entry.is_active = False
        db.session.commit()
        logger.info(f"IP address unblocked: {ip_address}")

        return jsonify({
            'message': f"IP address {ip_address} unblocked successfully.",
            'ip_address': ip_address
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error unblocking IP: {e}")
        return jsonify({'error': 'Failed to unblock IP address.'}), 500


@mitigation_bp.route('/blocked-ips', methods=['GET'])
def get_blocked_ips():
    """
    GET /api/mitigation/blocked-ips?active_only=true
    Retrieve registered blocked IP list.
    """
    try:
        active_only = request.args.get('active_only', 'false').lower() == 'true'
        query = BlockedIP.query
        if active_only:
            query = query.filter_by(is_active=True)

        records = query.order_by(BlockedIP.blocked_at.desc()).all()
        return jsonify({
            'count': len(records),
            'blocked_ips': [r.to_dict() for r in records]
        }), 200

    except Exception as e:
        logger.error(f"Error retrieving blocked IPs: {e}")
        return jsonify({'error': 'Failed to retrieve blocked IPs.'}), 500


@mitigation_bp.route('/alerts', methods=['GET'])
def get_attack_alerts():
    """
    GET /api/mitigation/alerts?limit=50
    Retrieve security incident alert logs.
    """
    try:
        limit = request.args.get('limit', default=50, type=int)
        limit = min(max(limit, 1), 500)

        alerts = AttackAlert.query.order_by(AttackAlert.timestamp.desc()).limit(limit).all()
        return jsonify({
            'count': len(alerts),
            'alerts': [a.to_dict() for a in alerts]
        }), 200

    except Exception as e:
        logger.error(f"Error fetching attack alerts: {e}")
        return jsonify({'error': 'Failed to retrieve attack alerts.'}), 500
