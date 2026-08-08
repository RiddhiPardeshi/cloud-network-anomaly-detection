"""
Real-Time Traffic & Cyber Attack Simulator Engine for Cloud Network Anomaly Detection.
Provides multithreaded continuous traffic generation (Normal, DDoS, Port Scan, Brute Force, Malicious Payload)
that flows through Telemetry -> ML Prediction -> Risk Scoring -> Auto Mitigation -> Dashboard.
"""

import time
import json
import random
import threading
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from backend.db import db, TelemetryLog, PredictionLog, BlockedIP, AttackAlert
from ml_engine.predictor import CloudAnomalyPredictor
from backend.risk_engine import calculate_risk_score
from backend.mitigation import trigger_automatic_mitigation
from config import Config

simulator_bp = Blueprint('simulator', __name__)
logger = logging.getLogger(__name__)


def generate_random_ip(prefix="198.51"):
    """Helper to generate realistic IPv4 addresses."""
    return f"{prefix}.{random.randint(10, 200)}.{random.randint(1, 254)}"


class CloudTrafficSimulator:
    """Singleton Background Multithreaded Traffic & Attack Simulator."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(CloudTrafficSimulator, cls).__new__(cls)
                cls._instance._init_simulator()
            return cls._instance

    def _init_simulator(self):
        self.is_running = False
        self.stop_event = threading.Event()
        self.thread = None

        self.scenario = 'Mixed'  # 'Normal', 'DDoS', 'Port Scan', 'Brute Force', 'Malicious Payload', 'Mixed'
        self.rate_per_sec = 2.0  # requests per second
        self.duration_seconds = None  # None for infinite until stopped

        self.stats = {
            'total_generated': 0,
            'normal_generated': 0,
            'attacks_generated': 0,
            'auto_blocks_triggered': 0,
            'start_time': None,
            'last_generated_time': None,
            'scenario_breakdown': {
                'Normal': 0,
                'DDoS': 0,
                'Port Scan': 0,
                'Brute Force': 0,
                'Malicious Payload': 0
            }
        }

        # IP Pools
        self.ip_pools = {
            'Normal': [generate_random_ip("172.16") for _ in range(20)],
            'DDoS': [generate_random_ip("198.51") for _ in range(10)],
            'Port Scan': [generate_random_ip("203.0") for _ in range(5)],
            'Brute Force': [generate_random_ip("192.0") for _ in range(5)],
            'Malicious Payload': [generate_random_ip("198.18") for _ in range(5)]
        }

    def _generate_telemetry_payload(self, attack_type):
        """Synthesize telemetry payload dictionary for target scenario."""
        dest_ip = random.choice(['10.0.0.1', '10.0.0.2', '10.0.0.5'])

        if attack_type == 'Normal':
            source_ip = random.choice(self.ip_pools['Normal'])
            protocol = random.choice(['TCP', 'HTTP', 'HTTPS'])
            port = random.choice([80, 443, 8080])
            packets = random.randint(1, 30)
            bytes_cnt = random.randint(150, 4000)
            req_cnt = random.randint(1, 6)
            login_att = random.choice([0, 0, 0, 0, 1])
            cpu = round(random.uniform(5.0, 30.0), 2)
            mem = round(random.uniform(15.0, 40.0), 2)
            resp_time = round(random.uniform(10.0, 60.0), 2)

        elif attack_type == 'DDoS':
            source_ip = random.choice(self.ip_pools['DDoS'])
            protocol = random.choice(['TCP', 'UDP'])
            port = random.choice([80, 443])
            packets = random.randint(1200, 9000)
            bytes_cnt = random.randint(50000, 600000)
            req_cnt = random.randint(200, 2000)
            login_att = 0
            cpu = round(random.uniform(80.0, 99.9), 2)
            mem = round(random.uniform(75.0, 95.0), 2)
            resp_time = round(random.uniform(500.0, 3500.0), 2)

        elif attack_type == 'Port Scan':
            source_ip = random.choice(self.ip_pools['Port Scan'])
            protocol = 'TCP'
            port = random.randint(1, 65535)
            packets = random.randint(1, 5)
            bytes_cnt = random.randint(40, 250)
            req_cnt = random.randint(30, 150)
            login_att = 0
            cpu = round(random.uniform(35.0, 65.0), 2)
            mem = round(random.uniform(30.0, 55.0), 2)
            resp_time = round(random.uniform(5.0, 25.0), 2)

        elif attack_type == 'Brute Force':
            source_ip = random.choice(self.ip_pools['Brute Force'])
            protocol = 'HTTP'
            port = random.choice([80, 443, 22])
            packets = random.randint(15, 90)
            bytes_cnt = random.randint(1500, 9500)
            req_cnt = random.randint(20, 100)
            login_att = random.randint(10, 150)
            cpu = round(random.uniform(45.0, 80.0), 2)
            mem = round(random.uniform(40.0, 70.0), 2)
            resp_time = round(random.uniform(150.0, 700.0), 2)

        elif attack_type == 'Malicious Payload':
            source_ip = random.choice(self.ip_pools['Malicious Payload'])
            protocol = 'HTTP'
            port = random.choice([80, 443, 8080])
            packets = random.randint(60, 350)
            bytes_cnt = random.randint(20000, 120000)
            req_cnt = random.randint(5, 35)
            login_att = random.randint(0, 3)
            cpu = round(random.uniform(55.0, 90.0), 2)
            mem = round(random.uniform(55.0, 85.0), 2)
            resp_time = round(random.uniform(300.0, 1500.0), 2)

        else:
            source_ip = generate_random_ip("192.168")
            protocol = 'TCP'
            port = 80
            packets = 10
            bytes_cnt = 500
            req_cnt = 1
            login_att = 0
            cpu = 15.0
            mem = 25.0
            resp_time = 30.0

        return {
            'Timestamp': datetime.utcnow().isoformat(),
            'Source IP': source_ip,
            'Destination IP': dest_ip,
            'Protocol': protocol,
            'Port': port,
            'Packets': packets,
            'Bytes': bytes_cnt,
            'Request Count': req_cnt,
            'Login Attempts': login_att,
            'CPU Usage': cpu,
            'Memory Usage': mem,
            'Response Time': resp_time,
            'simulated_type': attack_type
        }

    def process_single_simulation_step(self, target_scenario=None, flask_app=None):
        """
        Executes complete end-to-end pipeline for 1 traffic item:
        Telemetry -> ML Predictor -> Risk Engine -> Auto Mitigation -> DB Persistence.
        """
        scenario = target_scenario or self.scenario
        if scenario == 'Mixed':
            # 60% Normal, 40% Attacks
            selected_type = random.choices(
                ['Normal', 'DDoS', 'Port Scan', 'Brute Force', 'Malicious Payload'],
                weights=[60, 15, 10, 10, 5]
            )[0]
        else:
            selected_type = scenario

        payload = self._generate_telemetry_payload(selected_type)

        # Helper function inside app context
        def _run_pipeline():
            try:
                # 1. Ingest Telemetry
                t_entry = TelemetryLog(
                    source_ip=payload['Source IP'],
                    destination_ip=payload['Destination IP'],
                    protocol=payload['Protocol'],
                    port=payload['Port'],
                    packets=payload['Packets'],
                    bytes=payload['Bytes'],
                    request_count=payload['Request Count'],
                    login_attempts=payload['Login Attempts'],
                    cpu_usage=payload['CPU Usage'],
                    memory_usage=payload['Memory Usage'],
                    response_time=payload['Response Time']
                )
                db.session.add(t_entry)
                db.session.commit()

                # 2. Real-time ML Prediction & XAI
                predictor = CloudAnomalyPredictor()
                result = predictor.predict(payload)

                # 3. Calculate Risk Score
                raw_dict = result['sanitized_telemetry']
                risk_score, category, _ = calculate_risk_score(
                    result['is_attack'], result['confidence'], raw_dict
                )

                # 4. Save Prediction Audit Log
                p_entry = PredictionLog(
                    telemetry_id=t_entry.id,
                    source_ip=payload['Source IP'],
                    attack_type=result['attack_type'],
                    is_attack=result['is_attack'],
                    confidence=result['confidence'],
                    risk_score=risk_score,
                    risk_category=category,
                    top_features_json=json.dumps(result['top_features']),
                    explanation=result['explanation']
                )
                db.session.add(p_entry)
                db.session.commit()

                # 5. Auto Mitigation Check (If Risk >= 81)
                auto_blocked = False
                if risk_score >= Config.RISK_THRESHOLD_CRITICAL:
                    trigger_automatic_mitigation(
                        source_ip=payload['Source IP'],
                        attack_type=result['attack_type'],
                        risk_score=risk_score,
                        confidence=result['confidence'],
                        top_features=result['top_features'],
                        dest_ip=payload['Destination IP']
                    )
                    auto_blocked = True

                # Update internal counters
                self.stats['total_generated'] += 1
                if result['is_attack']:
                    self.stats['attacks_generated'] += 1
                else:
                    self.stats['normal_generated'] += 1

                if auto_blocked:
                    self.stats['auto_blocks_triggered'] += 1

                self.stats['scenario_breakdown'][selected_type] = self.stats['scenario_breakdown'].get(selected_type, 0) + 1
                self.stats['last_generated_time'] = datetime.utcnow().isoformat()

                return {
                    'telemetry_id': t_entry.id,
                    'prediction_id': p_entry.id,
                    'source_ip': payload['Source IP'],
                    'attack_type': result['attack_type'],
                    'is_attack': result['is_attack'],
                    'confidence': result['confidence'],
                    'risk_score': risk_score,
                    'risk_category': category,
                    'auto_mitigation_triggered': auto_blocked,
                    'explanation': result['explanation']
                }

            except Exception as e:
                db.session.rollback()
                logger.error(f"Error processing simulation step: {e}", exc_info=True)
                raise e

        if flask_app:
            with flask_app.app_context():
                return _run_pipeline()
        else:
            return _run_pipeline()

    def _worker_loop(self, flask_app):
        """Background thread execution loop."""
        logger.info(f"Simulator worker loop started: Scenario={self.scenario}, Rate={self.rate_per_sec} req/sec")
        start_time = time.time()

        while not self.stop_event.is_set():
            loop_start = time.time()

            try:
                self.process_single_simulation_step(flask_app=flask_app)
            except Exception as e:
                logger.error(f"Simulator worker step failed: {e}")

            # Duration check
            if self.duration_seconds and (time.time() - start_time) >= self.duration_seconds:
                logger.info(f"Simulator reached configured duration limit of {self.duration_seconds}s. Stopping worker.")
                break

            # Sleep to match target rate
            elapsed = time.time() - loop_start
            target_delay = max(0.05, (1.0 / self.rate_per_sec) - elapsed)
            time.sleep(target_delay)

        self.is_running = False
        logger.info("Simulator worker loop terminated.")

    def start(self, scenario='Mixed', rate_per_sec=2.0, duration_seconds=None, flask_app=None):
        """Start background simulation thread."""
        with self._lock:
            if self.is_running:
                return False, "Simulator is already running."

            self.scenario = scenario
            self.rate_per_sec = float(max(0.2, min(50.0, rate_per_sec)))
            self.duration_seconds = float(duration_seconds) if duration_seconds else None

            self.stop_event.clear()
            self.stats['start_time'] = datetime.utcnow().isoformat()

            self.thread = threading.Thread(
                target=self._worker_loop,
                args=(flask_app,),
                daemon=True
            )
            self.is_running = True
            self.thread.start()

            return True, "Simulator started successfully."

    def stop(self):
        """Stop running simulation thread."""
        with self._lock:
            if not self.is_running:
                return False, "Simulator is not currently running."

            self.stop_event.set()
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=2.0)

            self.is_running = False
            return True, "Simulator stopped successfully."


# Global Simulator instance
traffic_simulator = CloudTrafficSimulator()


@simulator_bp.route('/start', methods=['POST'])
def start_simulator():
    """
    POST /api/simulator/start
    Start continuous real-time background traffic simulation.
    Payload: { "scenario": "DDoS", "rate": 2.0, "duration": 60 }
    Scenarios: Normal, DDoS, Port Scan, Brute Force, Malicious Payload, Mixed
    """
    try:
        from flask import current_app
        data = request.get_json(silent=True) or {}
        scenario = data.get('scenario', 'Mixed')
        rate = float(data.get('rate', 2.0))
        duration = data.get('duration')

        valid_scenarios = ['Normal', 'DDoS', 'Port Scan', 'Brute Force', 'Malicious Payload', 'Mixed']
        if scenario not in valid_scenarios:
            return jsonify({'error': f"Invalid scenario '{scenario}'. Must be one of {valid_scenarios}"}), 400

        # Get actual app object for thread context
        app_obj = current_app._get_current_object()
        success, msg = traffic_simulator.start(
            scenario=scenario,
            rate_per_sec=rate,
            duration_seconds=duration,
            flask_app=app_obj
        )

        if not success:
            return jsonify({'error': msg, 'status': 'already_running'}), 409

        return jsonify({
            'message': msg,
            'scenario': scenario,
            'rate_per_sec': rate,
            'duration_seconds': duration,
            'is_running': True
        }), 200

    except Exception as e:
        logger.error(f"Failed to start simulator: {e}", exc_info=True)
        return jsonify({'error': 'Failed to start traffic simulator.', 'details': str(e)}), 500


@simulator_bp.route('/stop', methods=['POST'])
def stop_simulator():
    """
    POST /api/simulator/stop
    Stop active background simulation thread.
    """
    try:
        success, msg = traffic_simulator.stop()
        if not success:
            return jsonify({'message': msg, 'is_running': False}), 200

        return jsonify({
            'message': msg,
            'is_running': False,
            'final_stats': traffic_simulator.stats
        }), 200

    except Exception as e:
        logger.error(f"Failed to stop simulator: {e}")
        return jsonify({'error': 'Failed to stop simulator.'}), 500


@simulator_bp.route('/status', methods=['GET'])
def get_simulator_status():
    """
    GET /api/simulator/status
    Get real-time simulator status and execution counters.
    """
    try:
        is_running = traffic_simulator.is_running
        stats = traffic_simulator.stats
        return jsonify({
            'status': 'running' if is_running else 'stopped',
            'is_running': is_running,
            'scenario': traffic_simulator.scenario,
            'rate_per_sec': traffic_simulator.rate_per_sec,
            'duration_seconds': traffic_simulator.duration_seconds,
            'total_generated': stats.get('total_generated', 0),
            'normal_events': stats.get('normal_generated', 0),
            'attack_events': stats.get('attacks_generated', 0),
            'blocked_ips': stats.get('auto_blocks_triggered', 0),
            'stats': stats
        }), 200

    except Exception as e:
        logger.error(f"Error getting simulator status: {e}")
        return jsonify({'error': 'Failed to retrieve simulator status.'}), 500


@simulator_bp.route('/trigger-attack', methods=['POST'])
@simulator_bp.route('/inject', methods=['POST'])
def trigger_single_attack():
    """
    POST /api/simulator/trigger-attack or /api/simulator/inject
    Inject an immediate single attack scenario through the complete pipeline.
    Payload: { "attack_type": "DDoS" }
    """
    try:
        from flask import current_app
        data = request.get_json(silent=True) or {}
        attack_type = data.get('attack_type') or data.get('scenario') or 'DDoS'

        valid_types = ['Normal', 'DDoS', 'Port Scan', 'Brute Force', 'Malicious Payload']
        if attack_type not in valid_types:
            return jsonify({'error': f"Invalid attack_type '{attack_type}'. Must be one of {valid_types}"}), 400

        app_obj = current_app._get_current_object()
        result = traffic_simulator.process_single_simulation_step(target_scenario=attack_type, flask_app=app_obj)

        return jsonify({
            'message': f"Single attack scenario '{attack_type}' injected and processed successfully.",
            'pipeline_result': result
        }), 201

    except Exception as e:
        logger.error(f"Failed to trigger single attack scenario: {e}", exc_info=True)
        return jsonify({'error': 'Failed to inject attack scenario.', 'details': str(e)}), 500
