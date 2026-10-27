"""
Lightweight Flask Application Entry Point for Cloud Network Anomaly Detection.
Initializes database, CORS, configuration, and registers Blueprint modules.
"""

import sys
import logging
from pathlib import Path
from datetime import timedelta
from flask import Flask, jsonify
from flask_cors import CORS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add root directory to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import Config
from backend.db import init_db


def create_app():
    """Application factory for Flask backend."""
    app = Flask(__name__, static_folder="../frontend", static_url_path="")
    app.config.from_object(Config)
    
    # Configure Flask session
    app.config['SECRET_KEY'] = Config.SECRET_KEY or 'dev-secret-key-please-change-in-production'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Works for same-site requests
    app.config['SESSION_COOKIE_SECURE'] = False  # Set True in production with HTTPS
    app.config['SESSION_COOKIE_NAME'] = 'cloud_anomaly_session'
    app.config['SESSION_COOKIE_DOMAIN'] = None  # Let browser handle it (works for both localhost and 127.0.0.1)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

    # Enable Cross-Origin Resource Sharing
    # Configure CORS for local development (frontend on port 3000, backend on port 5000)
    # and production (same origin)
    CORS(app, 
         resources={r"/api/*": {"origins": ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173", "http://127.0.0.1:5173"]}},
         supports_credentials=True,
         allow_headers=["Content-Type", "Authorization"],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

    # Initialize Configuration & Database
    Config.init_app(app)
    init_db(app)

    # Register Blueprints
    from backend.auth import auth_bp
    from backend.telemetry import telemetry_bp
    from backend.prediction import prediction_bp
    from backend.mitigation import mitigation_bp
    from backend.dashboard import dashboard_bp
    from backend.simulator import simulator_bp
    from backend.api import api_bp
    from backend.admin import admin_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(telemetry_bp, url_prefix='/api/telemetry')
    app.register_blueprint(prediction_bp, url_prefix='/api/predict')
    app.register_blueprint(mitigation_bp, url_prefix='/api/mitigation')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(simulator_bp, url_prefix='/api/simulator')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')

    @app.route('/')
    def index():
        dist_index = ROOT_DIR / 'frontend' / 'dist' / 'index.html'
        if dist_index.exists():
            from flask import send_from_directory
            return send_from_directory(str(dist_index.parent), 'index.html')
        return app.send_static_file('index.html')

    @app.route('/assets/<path:filename>')
    def serve_assets(filename):
        from flask import send_from_directory
        dist_assets = ROOT_DIR / 'frontend' / 'dist' / 'assets'
        if dist_assets.exists():
            return send_from_directory(str(dist_assets), filename)
        return app.send_static_file(f'assets/{filename}')

    @app.route('/health')
    def health_check():
        return jsonify({
            'status': 'online',
            'service': 'Cloud Network Anomaly Detection Engine',
            'version': '1.0.0'
        }), 200

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=Config.FLASK_PORT, debug=True)
