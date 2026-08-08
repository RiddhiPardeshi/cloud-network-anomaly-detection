"""
Telemetry Collector Blueprint for Cloud Network Anomaly Detection.
Collects, aggregates, and stores multi-source telemetry logs (Network, App, API, System metrics).
Designed to output schema-aligned features for ML Prediction Engine.
"""

import time
from datetime import datetime
import logging
import psutil
from flask import Blueprint, request, jsonify
from backend.db import db, TelemetryLog

# Define Blueprint
telemetry_bp = Blueprint('telemetry', __name__)
logger = logging.getLogger(__name__)


def capture_system_metrics():
    """Capture host system hardware metrics using psutil."""
    try:
        cpu_usage = psutil.cpu_percent(interval=None)
        memory_info = psutil.virtual_memory()
        return round(cpu_usage, 2), round(memory_info.percent, 2)
    except Exception as e:
        logger.warning(f"Failed to capture system metrics via psutil: {e}")
        return 15.0, 30.0  # Default fallback metrics


def format_ml_feature_vector(telemetry_record):
    """
    Format TelemetryLog record into exact feature column dictionary matching ML Dataset schema.
    Used seamlessly by Module 7 (Prediction Engine).
    """
    return telemetry_record.to_ml_feature_vector()


@telemetry_bp.route('/ingest', methods=['POST'])
def ingest_telemetry():
    """
    POST /api/telemetry/ingest
    Ingests live request telemetry or simulated network telemetry payload.
    """
    start_time = time.time()
    try:
        data = request.get_json(silent=True) or {}

        # Capture system metrics
        cpu_usage, memory_usage = capture_system_metrics()

        # Extract request metadata with fallbacks for manual ingestion payloads
        source_ip = data.get('source_ip') or data.get('Source IP') or request.remote_addr or '127.0.0.1'
        destination_ip = data.get('destination_ip') or data.get('Destination IP') or '10.0.0.1'
        protocol = data.get('protocol') or data.get('Protocol') or 'TCP'
        port = int(data.get('port') or data.get('Port') or 80)
        packets = int(data.get('packets') or data.get('Packets') or 1)
        bytes_transferred = int(data.get('bytes') or data.get('Bytes') or 500)
        request_count = int(data.get('request_count') or data.get('Request Count') or 1)
        login_attempts = int(data.get('login_attempts') or data.get('Login Attempts') or 0)

        # Explicit hardware overrides if supplied in payload
        if 'cpu_usage' in data or 'CPU Usage' in data:
            cpu_usage = float(data.get('cpu_usage', data.get('CPU Usage')))
        if 'memory_usage' in data or 'Memory Usage' in data:
            memory_usage = float(data.get('memory_usage', data.get('Memory Usage')))

        # Calculate response execution latency in ms
        execution_time_ms = round((time.time() - start_time) * 1000 + float(data.get('response_time', data.get('Response Time', 15.0))), 2)

        # Create new TelemetryLog entry
        telemetry_entry = TelemetryLog(
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            packets=packets,
            bytes=bytes_transferred,
            request_count=request_count,
            login_attempts=login_attempts,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            response_time=execution_time_ms,
            method=data.get('method') or request.method,
            path=data.get('path') or request.path,
            endpoint=data.get('endpoint') or (request.endpoint or 'custom_endpoint')
        )

        db.session.add(telemetry_entry)
        db.session.commit()

        logger.info(f"Telemetry Ingested successfully: ID={telemetry_entry.id}, IP={source_ip}, Packets={packets}, CPU={cpu_usage}%")

        # Response matching strict format specifications
        return jsonify({
            'message': 'Telemetry record ingested successfully.',
            'telemetry': telemetry_entry.to_dict(),
            'ml_feature_vector': telemetry_entry.to_ml_feature_vector()
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to collect telemetry: {e}", exc_info=True)
        return jsonify({'error': 'Failed to ingest telemetry data.', 'details': str(e)}), 500


@telemetry_bp.route('/recent', methods=['GET'])
def get_recent_telemetry():
    """
    GET /api/telemetry/recent?limit=50
    Retrieve recent telemetry records.
    """
    try:
        limit = request.args.get('limit', default=50, type=int)
        limit = min(max(limit, 1), 500)  # Bound limit between 1 and 500

        records = TelemetryLog.query.order_by(TelemetryLog.timestamp.desc()).limit(limit).all()
        return jsonify({
            'count': len(records),
            'telemetry_logs': [r.to_dict() for r in records]
        }), 200

    except Exception as e:
        logger.error(f"Error fetching recent telemetry logs: {e}")
        return jsonify({'error': 'Failed to retrieve telemetry records.'}), 500


@telemetry_bp.route('/stats', methods=['GET'])
def get_telemetry_stats():
    """
    GET /api/telemetry/stats
    Aggregated telemetry summary statistics.
    """
    try:
        total_requests = db.session.query(db.func.count(TelemetryLog.id)).scalar() or 0
        avg_cpu = db.session.query(db.func.avg(TelemetryLog.cpu_usage)).scalar() or 0.0
        avg_memory = db.session.query(db.func.avg(TelemetryLog.memory_usage)).scalar() or 0.0
        total_bytes = db.session.query(db.func.sum(TelemetryLog.bytes)).scalar() or 0
        total_packets = db.session.query(db.func.sum(TelemetryLog.packets)).scalar() or 0

        # Current live system stats
        live_cpu, live_memory = capture_system_metrics()

        return jsonify({
            'total_telemetry_records': total_requests,
            'avg_cpu_usage': round(avg_cpu, 2),
            'avg_memory_usage': round(avg_memory, 2),
            'total_bytes_transferred': total_bytes,
            'total_packets_processed': total_packets,
            'live_system_metrics': {
                'cpu_percent': live_cpu,
                'memory_percent': live_memory
            }
        }), 200

    except Exception as e:
        logger.error(f"Error computing telemetry statistics: {e}")
        return jsonify({'error': 'Failed to compute telemetry statistics.'}), 500
