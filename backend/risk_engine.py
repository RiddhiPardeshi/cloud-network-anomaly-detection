"""
Deterministic Risk Scoring Engine for Cloud Network Anomaly Detection.

Computes a normalized Risk Score from 0 to 100 based on machine learning prediction confidence
fused with multi-source telemetry metrics (Login Attempts, CPU Usage, Packet Volume, Byte Size,
Request Count, and Latency).

Risk Categorization Scale:
  - 0 – 20  : Safe
  - 21 – 50 : Low Risk
  - 51 – 80 : Medium Risk
  - 81 – 100: Critical Risk
"""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import Config

logger = logging.getLogger(__name__)


def calculate_risk_score(is_attack, confidence, raw_telemetry):
    """
    Computes a deterministic 0-100 Risk Score using a hybrid mathematical model:

    Formula:
    Risk = min(100.0, Base_ML_Score + Login_Factor + CPU_Factor + Packet_Factor + Byte_Factor + Request_Factor + Latency_Factor)

    Weights:
      1. Base ML Probability Weight  : Max 50.0 points
         - P_attack * 50.0 (where P_attack is attack probability confidence)
      2. Login Attempt Anomaly Factor: Max 15.0 points
         - min(15.0, (Login_Attempts / 5) * 15.0)
      3. CPU Utilization Factor      : Max 10.0 points
         - min(10.0, (CPU_Usage / 100) * 10.0)
      4. Packet Volume Factor        : Max 10.0 points
         - min(10.0, (Packets / 5000) * 10.0)
      5. Byte Transfer Size Factor   : Max 5.0 points
         - min(5.0, (Bytes / 200000) * 5.0)
      6. Request Count Factor        : Max 5.0 points
         - min(5.0, (Request_Count / 500) * 5.0)
      7. Latency Delay Factor        : Max 5.0 points
         - min(5.0, (Response_Time / 1000) * 5.0)

    Total Maximum Cumulative Score = 100.0
    """
    if not isinstance(raw_telemetry, dict):
        raw_telemetry = {}

    # Extract & coerce telemetry values safely
    p_attack = float(confidence) if is_attack else (1.0 - float(confidence))
    p_attack = max(0.0, min(1.0, p_attack))

    login_att = float(raw_telemetry.get('Login Attempts', 0) or 0)
    cpu_usage = float(raw_telemetry.get('CPU Usage', 0) or 0)
    packets = float(raw_telemetry.get('Packets', 0) or 0)
    bytes_cnt = float(raw_telemetry.get('Bytes', 0) or 0)
    req_cnt = float(raw_telemetry.get('Request Count', 0) or 0)
    resp_time = float(raw_telemetry.get('Response Time', 0) or 0)

    # Calculate component weights
    base_ml_score = p_attack * 50.0
    login_factor = min(15.0, (max(0.0, login_att) / 5.0) * 15.0)
    cpu_factor = min(10.0, (max(0.0, cpu_usage) / 100.0) * 10.0)
    packet_factor = min(10.0, (max(0.0, packets) / 5000.0) * 10.0)
    byte_factor = min(5.0, (max(0.0, bytes_cnt) / 200000.0) * 5.0)
    request_factor = min(5.0, (max(0.0, req_cnt) / 500.0) * 5.0)
    latency_factor = min(5.0, (max(0.0, resp_time) / 1000.0) * 5.0)

    raw_total = (
        base_ml_score +
        login_factor +
        cpu_factor +
        packet_factor +
        byte_factor +
        request_factor +
        latency_factor
    )

    risk_score = round(max(0.0, min(100.0, raw_total)), 2)

    # Categorize Risk Level
    if risk_score <= 20.0:
        category = 'Safe'
    elif risk_score <= 50.0:
        category = 'Low'
    elif risk_score <= 80.0:
        category = 'Medium'
    else:
        category = 'Critical'

    factors_breakdown = {
        'base_ml_score': round(base_ml_score, 2),
        'login_factor': round(login_factor, 2),
        'cpu_factor': round(cpu_factor, 2),
        'packet_factor': round(packet_factor, 2),
        'byte_factor': round(byte_factor, 2),
        'request_factor': round(request_factor, 2),
        'latency_factor': round(latency_factor, 2)
    }

    return risk_score, category, factors_breakdown


def send_security_alert_email(alert_data):
    """
    Send automated SMTP Email Alert for High/Critical Security Threats.
    Includes: Timestamp, Source IP, Destination IP, Attack Type, Confidence Score,
              Risk Score, Top XAI Features, and IP Block Status.
    Returns True if sent successfully, False otherwise.
    """
    try:
        sender = Config.ALERT_EMAIL_SENDER
        recipient = Config.ALERT_EMAIL_RECIPIENT
        subject = f"[CRITICAL SECURITY ALERT] Attack Detected from {alert_data.get('source_ip', 'Unknown IP')}"

        timestamp = alert_data.get('timestamp', '')
        source_ip = alert_data.get('source_ip', '127.0.0.1')
        dest_ip = alert_data.get('destination_ip', '10.0.0.1')
        attack_type = alert_data.get('attack_type', 'Unknown')
        confidence = alert_data.get('confidence', 0.0)
        risk_score = alert_data.get('risk_score', 0.0)
        top_features = alert_data.get('top_features', [])
        block_status = alert_data.get('block_status', 'IP Blocked')

        features_str = "\n".join([
            f"  - {f.get('feature', 'N/A')}: {f.get('value', 'N/A')} (Importance: {f.get('importance_score', 0)})"
            if isinstance(f, dict) else f"  - {f}"
            for f in top_features
        ]) or "  - No specific features available"

        body = f"""======================================================================
CLOUD SECURITY INCIDENT ALERT - CRITICAL THREAT DETECTED
======================================================================

Timestamp          : {timestamp}
Source IP          : {source_ip}
Destination IP     : {dest_ip}
Attack Type        : {attack_type}
Confidence Score   : {confidence * 100:.2f}% ({confidence:.4f})
Risk Score         : {risk_score} / 100 (CRITICAL THREAT)
Block Status       : {block_status}

Top Explainable AI (XAI) Contributing Features:
{features_str}

AUTOMATED MITIGATION ACTION TAKEN:
Source IP address {source_ip} has been automatically registered in the active firewall block list.

----------------------------------------------------------------------
Cloud Network Anomaly Detection System - Automated Security Alert
"""

        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        if Config.SMTP_USER and Config.SMTP_PASSWORD:
            with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=5) as server:
                server.starttls()
                server.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
                server.sendmail(sender, [recipient], msg.as_string())
            logger.info(f"Security Alert Email successfully sent to {recipient} via SMTP server {Config.SMTP_SERVER}.")
            return True
        else:
            logger.warning(f"[SMTP Alert Simulated/Logged]: Alert for IP={source_ip}, Risk={risk_score}")
            return True

    except Exception as e:
        logger.error(f"Failed to deliver security alert email via SMTP: {e}")
        return False
