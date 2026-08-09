"""
Configuration Manager for Cloud Network Anomaly Detection System.
Loads environment variables from .env file using python-dotenv.
"""

import os
from pathlib import Path
from urllib.parse import quote_plus
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Explicitly load .env file from base directory if present (do NOT override environment variables set by Render)
env_path = BASE_DIR / '.env'
load_dotenv(dotenv_path=env_path, override=False)


class Config:
    """Application Configuration Class."""
    BASE_DIR = BASE_DIR
    SECRET_KEY = os.getenv('SECRET_KEY', 'cloud_anomaly_detection_secret_key_2026_btech')

    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))

    # MySQL Database Connection Parameters (Sanitized for Render & Aiven MySQL)
    DB_USER = os.getenv('DB_USER', 'root').strip()
    DB_PASSWORD = os.getenv('DB_PASSWORD', '').strip()

    # Sanitize DB_HOST (handles accidental schemes like mysql:// or embedded ports like host:port)
    raw_host = os.getenv('DB_HOST', 'localhost').strip()
    if '://' in raw_host:
        raw_host = raw_host.split('://')[-1]
    raw_host = raw_host.split('/')[0].split('?')[0]

    extracted_port = None
    if ':' in raw_host:
        parts = raw_host.split(':')
        raw_host = parts[0]
        try:
            extracted_port = int(parts[1])
        except ValueError:
            pass

    DB_HOST = raw_host

    raw_port = os.getenv('DB_PORT', '').strip()
    if raw_port:
        try:
            DB_PORT = int(raw_port)
        except ValueError:
            DB_PORT = extracted_port or 3306
    elif extracted_port:
        DB_PORT = extracted_port
    else:
        DB_PORT = 3306

    DB_NAME = os.getenv('DB_NAME', 'defaultdb').strip()

    @classmethod
    def get_sqlalchemy_uri(cls, override_password=None):
        pwd = override_password if override_password is not None else cls.DB_PASSWORD
        encoded_pwd = quote_plus(pwd) if pwd else ''
        if encoded_pwd:
            return f"mysql+pymysql://{cls.DB_USER}:{encoded_pwd}@{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"
        else:
            return f"mysql+pymysql://{cls.DB_USER}@{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Configure SQLAlchemy with PyMySQL and SSL/TLS required by Aiven MySQL
    _ssl_config = {}
    if DB_HOST not in ('localhost', '127.0.0.1'):
        _ssl_config = {'ssl_mode': 'REQUIRED', 'check_hostname': False}

    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 280,
        'pool_pre_ping': True,
        'connect_args': {
            'ssl': _ssl_config
        } if _ssl_config else {}
    }

    # Directories
    DATASET_DIR = BASE_DIR / 'dataset'
    MODELS_DIR = BASE_DIR / 'models'
    LOGS_DIR = BASE_DIR / 'logs'
    DELIVERABLES_DIR = BASE_DIR / 'deliverables'

    # Security Thresholds & SMTP Alerting
    RISK_THRESHOLD_HIGH = int(os.getenv('RISK_THRESHOLD_HIGH', 70))
    RISK_THRESHOLD_CRITICAL = int(os.getenv('RISK_THRESHOLD_CRITICAL', 81))
    ALERT_EMAIL_SENDER = os.getenv('ALERT_EMAIL_SENDER', 'alerts@cloudsecurity.io')
    ALERT_EMAIL_RECIPIENT = os.getenv('ALERT_EMAIL_RECIPIENT', 'admin@cloudsecurity.io')
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USER = os.getenv('SMTP_USER', '')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')

    @classmethod
    def init_app(cls, app):
        """Ensure necessary directories exist."""
        cls.DATASET_DIR.mkdir(parents=True, exist_ok=True)
        cls.MODELS_DIR.mkdir(parents=True, exist_ok=True)
        cls.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        cls.DELIVERABLES_DIR.mkdir(parents=True, exist_ok=True)


# Define static attribute after class creation
Config.SQLALCHEMY_DATABASE_URI = Config.get_sqlalchemy_uri()
