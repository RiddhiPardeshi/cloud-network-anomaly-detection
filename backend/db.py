"""
Database Manager & SQLAlchemy ORM Models for Cloud Network Anomaly Detection.
Supports MySQL database storage via PyMySQL with complete schema consistency.
"""

from datetime import datetime
import json
import logging
from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy instance
db = SQLAlchemy()

logger = logging.getLogger(__name__)


def init_db(app):
    """Initialize database connection and create all registered tables safely for production."""
    from config import Config
    app.config['SQLALCHEMY_DATABASE_URI'] = Config.get_sqlalchemy_uri()

    db.init_app(app)
    with app.app_context():
        try:
            # Ensure models are imported so SQLAlchemy registers metadata
            import backend.db  # noqa: F401
            db.create_all()

            # Safe ALTER TABLE migration for existing database schema
            try:
                db.session.execute(db.text("ALTER TABLE users ADD COLUMN name VARCHAR(100) NULL;"))
                db.session.commit()
                logger.info("Migrated 'users' table: added 'name' column if missing.")
            except Exception:
                db.session.rollback()  # Column already exists or up-to-date

            logger.info("All MySQL database tables initialized & verified successfully.")
        except Exception as e:
            logger.error(f"Error initializing MySQL database tables: {e}")
            raise e


# ============================================================================
# Database Models
# ============================================================================

class User(db.Model):
    """User table for cloud application authentication."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name or self.username,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class TelemetryLog(db.Model):
    """
    Multi-source telemetry collection log table.
    Schema maps 1-to-1 with ML Dataset features.
    """
    __tablename__ = 'telemetry_logs'

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), default='10.0.0.1')
    protocol = db.Column(db.String(10), default='TCP')
    port = db.Column(db.Integer, default=80)
    packets = db.Column(db.Integer, default=1)
    bytes = db.Column(db.BigInteger, default=500)
    request_count = db.Column(db.Integer, default=1)
    login_attempts = db.Column(db.Integer, default=0)
    cpu_usage = db.Column(db.Float, default=10.0)
    memory_usage = db.Column(db.Float, default=20.0)
    response_time = db.Column(db.Float, default=50.0)  # milliseconds
    method = db.Column(db.String(10), default='GET')
    path = db.Column(db.String(255), default='/')
    endpoint = db.Column(db.String(100), default='index')

    def to_dict(self):
        return {
            'id': self.id,
            'Timestamp': self.timestamp.isoformat(),
            'Source IP': self.source_ip,
            'Destination IP': self.destination_ip,
            'Protocol': self.protocol,
            'Port': self.port,
            'Packets': self.packets,
            'Bytes': self.bytes,
            'Request Count': self.request_count,
            'Login Attempts': self.login_attempts,
            'CPU Usage': self.cpu_usage,
            'Memory Usage': self.memory_usage,
            'Response Time': self.response_time,
            'method': self.method,
            'path': self.path,
            'endpoint': self.endpoint
        }

    def to_ml_feature_vector(self):
        """
        Returns exact feature mapping matching Module 5 Dataset columns.
        Exact Spelling, Capitalization, and Feature Ordering.
        """
        return {
            'Timestamp': self.timestamp.isoformat(),
            'Source IP': self.source_ip,
            'Destination IP': self.destination_ip,
            'Protocol': self.protocol,
            'Port': self.port,
            'Packets': self.packets,
            'Bytes': self.bytes,
            'Request Count': self.request_count,
            'Login Attempts': self.login_attempts,
            'CPU Usage': self.cpu_usage,
            'Memory Usage': self.memory_usage,
            'Response Time': self.response_time
        }


class PredictionLog(db.Model):
    """Real-time ML anomaly prediction audit log table."""
    __tablename__ = 'prediction_logs'

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    telemetry_id = db.Column(db.BigInteger, db.ForeignKey('telemetry_logs.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    attack_type = db.Column(db.String(50), nullable=False)  # Normal, DDoS, Port Scan, Brute Force, Malicious Payload
    is_attack = db.Column(db.Boolean, nullable=False, default=False)
    confidence = db.Column(db.Float, nullable=False, default=0.0)
    risk_score = db.Column(db.Float, nullable=False, default=0.0)
    risk_category = db.Column(db.String(20), nullable=False, default='Safe')
    top_features_json = db.Column(db.Text, nullable=True)
    explanation = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'telemetry_id': self.telemetry_id,
            'Timestamp': self.timestamp.isoformat(),
            'Source IP': self.source_ip,
            'Attack Type': self.attack_type,
            'is_attack': self.is_attack,
            'confidence': round(self.confidence, 4),
            'risk_score': round(self.risk_score, 2),
            'risk_category': self.risk_category,
            'top_features': json.loads(self.top_features_json) if self.top_features_json else [],
            'explanation': self.explanation
        }


class BlockedIP(db.Model):
    """Automated mitigation blocked IP registry table."""
    __tablename__ = 'blocked_ips'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=False)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    risk_score = db.Column(db.Float, nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'blocked_at': self.blocked_at.isoformat(),
            'risk_score': self.risk_score,
            'is_active': self.is_active
        }


class AttackAlert(db.Model):
    """Security Incident Alert table."""
    __tablename__ = 'attack_alerts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False)
    attack_type = db.Column(db.String(50), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    alert_level = db.Column(db.String(20), nullable=False)  # High / Critical
    notification_sent = db.Column(db.Boolean, default=False)
    details_json = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'attack_type': self.attack_type,
            'risk_score': self.risk_score,
            'alert_level': self.alert_level,
            'notification_sent': self.notification_sent,
            'details': json.loads(self.details_json) if self.details_json else {}
        }
