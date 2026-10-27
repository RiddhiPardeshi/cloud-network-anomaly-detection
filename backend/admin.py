"""
Admin Panel API Blueprint for Cloud Network Anomaly Detection.
Provides admin-only routes for system management, user management, and operational oversight.
"""

import logging
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from backend.db import db, User, TelemetryLog, PredictionLog, BlockedIP, AttackAlert
from backend.auth import require_admin
from config import Config

admin_bp = Blueprint('admin', __name__)
logger = logging.getLogger(__name__)


@admin_bp.route('/dashboard', methods=['GET'])
@require_admin
def admin_dashboard():
    """
    GET /api/admin/dashboard
    Admin dashboard overview with system-wide statistics.
    Returns flat structure matching frontend expectations.
    """
    try:
        # User statistics
        total_users = db.session.query(db.func.count(User.id)).scalar() or 0
        admin_users = db.session.query(db.func.count(User.id)).filter(User.role == 'admin').scalar() or 0
        
        # Prediction statistics
        total_predictions = db.session.query(db.func.count(PredictionLog.id)).scalar() or 0
        attack_predictions = db.session.query(db.func.count(PredictionLog.id)).filter(PredictionLog.is_attack == True).scalar() or 0
        normal_predictions = db.session.query(db.func.count(PredictionLog.id)).filter(PredictionLog.is_attack == False).scalar() or 0
        
        # Security statistics
        blocked_ips = db.session.query(db.func.count(BlockedIP.id)).filter(BlockedIP.is_active == True).scalar() or 0
        total_alerts = db.session.query(db.func.count(AttackAlert.id)).scalar() or 0
        
        # Calculate attack detection rate (only if we have predictions)
        if total_predictions > 0 and attack_predictions > 0:
            # This is the percentage of attacks detected out of total traffic
            attack_detection_rate = round((attack_predictions / total_predictions) * 100, 1)
        else:
            attack_detection_rate = None  # Frontend will show "—"
        
        logger.info(f"Admin dashboard stats - Users: {total_users}, Admins: {admin_users}, Predictions: {total_predictions}, Alerts: {total_alerts}, Blocked IPs: {blocked_ips}")
        
        return jsonify({
            'total_users': total_users,
            'admin_users': admin_users,
            'total_predictions': total_predictions,
            'attack_predictions': attack_predictions,
            'normal_predictions': normal_predictions,
            'total_alerts': total_alerts,
            'blocked_ips': blocked_ips,
            'attack_detection_rate': attack_detection_rate
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching admin dashboard: {e}", exc_info=True)
        return jsonify({'error': 'Failed to retrieve admin dashboard data.'}), 500


@admin_bp.route('/users', methods=['GET'])
@require_admin
def get_all_users():
    """
    GET /api/admin/users
    Get list of all registered users (admin only).
    """
    try:
        users = User.query.order_by(User.created_at.desc()).all()
        return jsonify({
            'count': len(users),
            'users': [u.to_dict() for u in users]
        }), 200
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return jsonify({'error': 'Failed to retrieve users.'}), 500


@admin_bp.route('/users/role', methods=['POST'])
@require_admin
def update_user_role():
    """
    POST /api/admin/users/role
    Update user role (admin only).
    Payload: { "user_id": 1, "role": "admin" or "user" }
    """
    try:
        data = request.get_json(silent=True) or {}
        user_id = data.get('user_id')
        new_role = data.get('role', '').strip()
        
        if not user_id:
            return jsonify({'error': 'user_id is required.'}), 400
        
        if new_role not in ['admin', 'user']:
            return jsonify({'error': 'Invalid role. Must be "admin" or "user".'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found.'}), 404
        
        old_role = user.role
        user.role = new_role
        db.session.commit()
        
        logger.info(f"Admin updated user {user.username} role from {old_role} to {new_role}")
        
        return jsonify({
            'message': f'User role updated successfully.',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating user role: {e}")
        return jsonify({'error': 'Failed to update user role.'}), 500


@admin_bp.route('/blocked-ips', methods=['GET'])
@require_admin
def admin_get_blocked_ips():
    """
    GET /api/admin/blocked-ips?active_only=false&limit=100
    Get all blocked IPs (admin only).
    """
    try:
        active_only = request.args.get('active_only', 'false').lower() == 'true'
        limit = min(int(request.args.get('limit', 100)), 500)
        
        query = BlockedIP.query
        if active_only:
            query = query.filter_by(is_active=True)
        
        blocked_ips = query.order_by(BlockedIP.blocked_at.desc()).limit(limit).all()
        
        return jsonify({
            'count': len(blocked_ips),
            'blocked_ips': [ip.to_dict() for ip in blocked_ips]
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching blocked IPs: {e}")
        return jsonify({'error': 'Failed to retrieve blocked IPs.'}), 500


@admin_bp.route('/blocked-ips/unblock', methods=['POST'])
@require_admin
def admin_unblock_ip():
    """
    POST /api/admin/blocked-ips/unblock
    Unblock a specific IP address (admin only).
    Payload: { "ip_id": 1 }
    """
    try:
        data = request.get_json(silent=True) or {}
        block_id = data.get('ip_id')
        
        if not block_id:
            return jsonify({'error': 'ip_id is required.'}), 400
        
        blocked_entry = BlockedIP.query.get(block_id)
        if not blocked_entry:
            return jsonify({'error': 'Blocked IP entry not found.'}), 404
        
        if not blocked_entry.is_active:
            return jsonify({'message': 'IP is already unblocked.', 'blocked_ip': blocked_entry.to_dict()}), 200
        
        blocked_entry.is_active = False
        db.session.commit()
        
        logger.info(f"Admin unblocked IP: {blocked_entry.ip_address}")
        
        return jsonify({
            'message': f'IP {blocked_entry.ip_address} unblocked successfully.',
            'blocked_ip': blocked_entry.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error unblocking IP: {e}")
        return jsonify({'error': 'Failed to unblock IP.'}), 500


@admin_bp.route('/alerts', methods=['GET'])
@require_admin
def admin_get_alerts():
    """
    GET /api/admin/alerts?limit=100&level=Critical
    Get all security alerts (admin only).
    """
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        alert_level = request.args.get('level', '').strip()
        
        query = AttackAlert.query
        if alert_level in ['Critical', 'High']:
            query = query.filter_by(alert_level=alert_level)
        
        alerts = query.order_by(AttackAlert.timestamp.desc()).limit(limit).all()
        
        return jsonify({
            'count': len(alerts),
            'alerts': [a.to_dict() for a in alerts]
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return jsonify({'error': 'Failed to retrieve alerts.'}), 500


@admin_bp.route('/predictions', methods=['GET'])
@require_admin
def admin_get_predictions():
    """
    GET /api/admin/predictions?limit=100&attack_only=false
    Get all prediction logs (admin only).
    """
    try:
        limit = min(int(request.args.get('limit', 100)), 500)
        attack_only = request.args.get('attack_only', 'false').lower() == 'true'
        
        query = PredictionLog.query
        if attack_only:
            query = query.filter_by(is_attack=True)
        
        predictions = query.order_by(PredictionLog.timestamp.desc()).limit(limit).all()
        
        return jsonify({
            'count': len(predictions),
            'predictions': [p.to_dict() for p in predictions]
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching predictions: {e}")
        return jsonify({'error': 'Failed to retrieve predictions.'}), 500


@admin_bp.route('/system/stats', methods=['GET'])
@require_admin
def admin_system_stats():
    """
    GET /api/admin/system/stats
    Get detailed system statistics (admin only).
    Returns flat structure matching frontend expectations.
    """
    try:
        # Database statistics
        total_telemetry_logs = db.session.query(db.func.count(TelemetryLog.id)).scalar() or 0
        prediction_count = db.session.query(db.func.count(PredictionLog.id)).scalar() or 0
        user_count = db.session.query(db.func.count(User.id)).scalar() or 0
        blocked_ip_count = db.session.query(db.func.count(BlockedIP.id)).scalar() or 0
        alert_count = db.session.query(db.func.count(AttackAlert.id)).scalar() or 0
        
        # Calculate approximate database size (sum of all records)
        total_records = total_telemetry_logs + prediction_count + user_count + blocked_ip_count + alert_count
        # Rough estimate: average 500 bytes per record
        estimated_size_mb = (total_records * 500) / (1024 * 1024)
        if estimated_size_mb < 1:
            database_size = f"{estimated_size_mb * 1024:.1f} KB"
        else:
            database_size = f"{estimated_size_mb:.2f} MB"
        
        # Model version info
        model_version = "XGBoost v1.0"  # Could read from model metadata if available
        
        # Uptime (placeholder - would need app start time tracking)
        uptime = "N/A"  # Without tracking start time, we can't calculate uptime
        
        logger.info(f"System stats - Telemetry: {total_telemetry_logs}, Predictions: {prediction_count}, DB Size: {database_size}")
        
        return jsonify({
            'database_size': database_size,
            'total_telemetry_logs': total_telemetry_logs,
            'model_version': model_version,
            'uptime': uptime,
            # Additional details for debugging
            'total_predictions': prediction_count,
            'total_users': user_count,
            'total_blocked_ips': blocked_ip_count,
            'total_alerts': alert_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching system stats: {e}", exc_info=True)
        return jsonify({'error': 'Failed to retrieve system statistics.'}), 500
