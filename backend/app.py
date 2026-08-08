"""
Lightweight Flask Application Entry Point for Cloud Network Anomaly Detection.
Initializes database, CORS, configuration, and registers Blueprint modules.
"""

import sys
from pathlib import Path
from flask import Flask, jsonify
from flask_cors import CORS

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

    # Enable Cross-Origin Resource Sharing
    CORS(app)

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

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(telemetry_bp, url_prefix='/api/telemetry')
    app.register_blueprint(prediction_bp, url_prefix='/api/predict')
    app.register_blueprint(mitigation_bp, url_prefix='/api/mitigation')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(simulator_bp, url_prefix='/api/simulator')
    app.register_blueprint(api_bp, url_prefix='/api')

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
