"""
Configuration Manager for Cloud Network Anomaly Detection System.
Supports Neon PostgreSQL via DATABASE_URL and Aiven MySQL as fallback.
"""

import os
from pathlib import Path
from urllib.parse import quote_plus
from dotenv import load_dotenv

# ============================================================
# BASE DIRECTORY & ENVIRONMENT
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

# Load .env without overriding environment variables set by Render
env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path, override=False)


class Config:
    """Application Configuration Class."""

    BASE_DIR = BASE_DIR

    # ========================================================
    # FLASK CONFIGURATION
    # ========================================================

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "cloud_anomaly_detection_secret_key_2026_btech"
    )

    FLASK_ENV = os.getenv(
        "FLASK_ENV",
        "development"
    )

    FLASK_PORT = int(
        os.getenv("FLASK_PORT", 5000)
    )

    # ========================================================
    # DATABASE CONFIGURATION
    # ========================================================

    # Preferred database:
    # Neon PostgreSQL when DATABASE_URL is present.
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        ""
    ).strip().strip("'").strip('"')

    # --------------------------------------------------------
    # Existing Aiven MySQL fallback
    # --------------------------------------------------------

    DB_USER = os.getenv(
        "DB_USER",
        "root"
    ).strip().strip("'").strip('"')

    DB_PASSWORD = os.getenv(
        "DB_PASSWORD",
        ""
    ).strip().strip("'").strip('"')

    raw_host = os.getenv(
        "DB_HOST",
        "localhost"
    ).strip().strip("'").strip('"')

    # Handle accidental schemes such as:
    # mysql://hostname
    if "://" in raw_host:
        raw_host = raw_host.split("://")[-1]

    # Remove path/query if present
    raw_host = raw_host.split("/")[0].split("?")[0]

    extracted_port = None

    # Handle host:port
    if ":" in raw_host:
        parts = raw_host.split(":")

        raw_host = parts[0]

        try:
            extracted_port = int(parts[1])
        except ValueError:
            pass

    DB_HOST = raw_host.strip().strip("'").strip('"')

    raw_port = os.getenv(
        "DB_PORT",
        ""
    ).strip().strip("'").strip('"')

    if raw_port:
        try:
            DB_PORT = int(raw_port)
        except ValueError:
            DB_PORT = extracted_port or 3306

    elif extracted_port:
        DB_PORT = extracted_port

    else:
        DB_PORT = 3306

    DB_NAME = os.getenv(
        "DB_NAME",
        "defaultdb"
    ).strip().strip("'").strip('"')

    # ========================================================
    # SQLALCHEMY DATABASE URI
    # ========================================================

    @classmethod
    def get_sqlalchemy_uri(cls, override_password=None):
        """
        Return the SQLAlchemy database URI.

        Priority:
        1. SQLite if USE_SQLITE=true
        2. Neon PostgreSQL if DATABASE_URL exists
        3. Existing Aiven/MySQL configuration
        4. Local SQLite fallback if local MySQL is unavailable
        """

        # ----------------------------------------------------
        # 1. Explicit SQLite fallback
        # ----------------------------------------------------

        if os.getenv(
            "USE_SQLITE",
            ""
        ).lower() == "true":

            sqlite_path = (
                cls.BASE_DIR / "cloud_anomaly.db"
            )

            return f"sqlite:///{sqlite_path}"

        # ----------------------------------------------------
        # 2. Neon PostgreSQL
        # ----------------------------------------------------

        if cls.DATABASE_URL:

            database_url = cls.DATABASE_URL

            # Use Psycopg 3 with SQLAlchemy.
            #
            # postgresql://
            #        ↓
            # postgresql+psycopg://

            if database_url.startswith("postgres://"):

                database_url = database_url.replace(
                    "postgres://",
                    "postgresql+psycopg://",
                    1
                )

            elif database_url.startswith("postgresql://"):

                database_url = database_url.replace(
                    "postgresql://",
                    "postgresql+psycopg://",
                    1
                )

            return database_url

        # ----------------------------------------------------
        # 3. Existing Aiven MySQL fallback
        # ----------------------------------------------------

        pwd = (
            override_password
            if override_password is not None
            else cls.DB_PASSWORD
        )

        encoded_pwd = (
            quote_plus(pwd)
            if pwd
            else ""
        )

        if encoded_pwd:

            mysql_uri = (
                f"mysql+pymysql://"
                f"{cls.DB_USER}:{encoded_pwd}"
                f"@{cls.DB_HOST}:{cls.DB_PORT}"
                f"/{cls.DB_NAME}"
            )

        else:

            mysql_uri = (
                f"mysql+pymysql://"
                f"{cls.DB_USER}"
                f"@{cls.DB_HOST}:{cls.DB_PORT}"
                f"/{cls.DB_NAME}"
            )

        # ----------------------------------------------------
        # 4. Local MySQL fallback → SQLite
        # ----------------------------------------------------

        if cls.DB_HOST in (
            "localhost",
            "127.0.0.1"
        ):

            try:

                import socket

                sock = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                )

                sock.settimeout(1.0)

                res = sock.connect_ex(
                    (
                        "127.0.0.1",
                        cls.DB_PORT
                    )
                )

                sock.close()

                if res != 0:

                    sqlite_path = (
                        cls.BASE_DIR / "cloud_anomaly.db"
                    )

                    return f"sqlite:///{sqlite_path}"

                # Verify local MySQL
                import pymysql

                conn = pymysql.connect(
                    host="127.0.0.1",
                    port=cls.DB_PORT,
                    user=cls.DB_USER,
                    password=pwd,
                    connect_timeout=1.0
                )

                conn.close()

            except Exception:

                sqlite_path = (
                    cls.BASE_DIR / "cloud_anomaly.db"
                )

                return f"sqlite:///{sqlite_path}"

        return mysql_uri

    # ========================================================
    # SQLALCHEMY CONFIGURATION
    # ========================================================

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 280,
        "pool_pre_ping": True,
    }

    # ========================================================
    # PROJECT DIRECTORIES
    # ========================================================

    DATASET_DIR = (
        BASE_DIR / "dataset"
    )

    MODELS_DIR = (
        BASE_DIR / "models"
    )

    LOGS_DIR = (
        BASE_DIR / "logs"
    )

    DELIVERABLES_DIR = (
        BASE_DIR / "deliverables"
    )

    # ========================================================
    # SECURITY THRESHOLDS
    # ========================================================

    RISK_THRESHOLD_HIGH = int(
        os.getenv(
            "RISK_THRESHOLD_HIGH",
            70
        )
    )

    RISK_THRESHOLD_CRITICAL = int(
        os.getenv(
            "RISK_THRESHOLD_CRITICAL",
            81
        )
    )

    # ========================================================
    # EMAIL / SMTP CONFIGURATION
    # ========================================================

    ALERT_EMAIL_SENDER = os.getenv(
        "ALERT_EMAIL_SENDER",
        "alerts@cloudsecurity.io"
    )

    ALERT_EMAIL_RECIPIENT = os.getenv(
        "ALERT_EMAIL_RECIPIENT",
        "admin@cloudsecurity.io"
    )

    SMTP_SERVER = os.getenv(
        "SMTP_SERVER",
        "smtp.gmail.com"
    )

    SMTP_PORT = int(
        os.getenv(
            "SMTP_PORT",
            587
        )
    )

    SMTP_USER = os.getenv(
        "SMTP_USER",
        ""
    )

    SMTP_PASSWORD = os.getenv(
        "SMTP_PASSWORD",
        ""
    )

    # ========================================================
    # APPLICATION INITIALIZATION
    # ========================================================

    @classmethod
    def init_app(cls, app):
        """Ensure necessary application directories exist."""

        cls.DATASET_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        cls.MODELS_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        cls.LOGS_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        cls.DELIVERABLES_DIR.mkdir(
            parents=True,
            exist_ok=True
        )


# ============================================================
# DEFINE DATABASE URI AFTER CLASS CREATION
# ============================================================

Config.SQLALCHEMY_DATABASE_URI = (
    Config.get_sqlalchemy_uri()
)