"""
Multi-Source Cloud Telemetry Dataset Generator for Machine Learning Anomaly Detection.
Synthesizes 50,000 rows of realistic cloud network traffic, application logs, API logs, and system metrics.
"""

import os
import sys
import random
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
import numpy as np

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import Config

# Reproducibility seed
SEED = 42
random.seed(SEED)
np.random.seed(SEED)


def generate_ip(is_internal=False):
    """Generate realistic IPv4 addresses."""
    if is_internal:
        return f"10.0.{random.randint(0, 5)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_telemetry_dataset(num_rows=50000, output_file=None):
    """
    Generate 50,000 rows of cloud network telemetry data across 5 attack classes:
    - Normal (60% ~ 30,000)
    - DDoS (15% ~ 7,500)
    - Port Scan (10% ~ 5,000)
    - Brute Force (10% ~ 5,000)
    - Malicious Payload (5% ~ 2,500)
    """
    print(f"Generating synthetic telemetry dataset of {num_rows} rows...")
    start_timestamp = datetime(2026, 8, 1, 0, 0, 0)

    # Class distributions
    class_counts = {
        'Normal': int(num_rows * 0.60),
        'DDoS': int(num_rows * 0.15),
        'Port Scan': int(num_rows * 0.10),
        'Brute Force': int(num_rows * 0.10),
        'Malicious Payload': num_rows - (int(num_rows * 0.60) + int(num_rows * 0.15) + int(num_rows * 0.10) * 2)
    }

    # Dedicated IP pools for malicious actors
    ddos_ip_pool = [generate_ip() for _ in range(50)]
    scan_ip_pool = [generate_ip() for _ in range(20)]
    brute_ip_pool = [generate_ip() for _ in range(20)]
    payload_ip_pool = [generate_ip() for _ in range(15)]
    normal_ip_pool = [generate_ip() for _ in range(500)]

    dest_ips = ['10.0.0.1', '10.0.0.2', '10.0.0.5']

    data = []
    current_time = start_timestamp

    for attack_type, count in class_counts.items():
        is_attack = 0 if attack_type == 'Normal' else 1

        for _ in range(count):
            # Time progression with small random intervals
            current_time += timedelta(milliseconds=random.randint(5, 500))

            if attack_type == 'Normal':
                source_ip = random.choice(normal_ip_pool)
                dest_ip = random.choice(dest_ips)
                protocol = random.choice(['TCP', 'HTTP', 'HTTPS'])
                port = random.choice([80, 443, 8080])
                packets = random.randint(1, 40)
                bytes_cnt = random.randint(200, 4500)
                req_cnt = random.randint(1, 8)
                login_attempts = random.choice([0, 0, 0, 0, 0, 1])
                cpu_usage = round(random.uniform(5.0, 35.0), 2)
                mem_usage = round(random.uniform(15.0, 45.0), 2)
                resp_time = round(random.uniform(10.0, 80.0), 2)

            elif attack_type == 'DDoS':
                source_ip = random.choice(ddos_ip_pool)
                dest_ip = random.choice(dest_ips)
                protocol = random.choice(['TCP', 'UDP'])
                port = random.choice([80, 443])
                packets = random.randint(800, 8000)
                bytes_cnt = random.randint(45000, 500000)
                req_cnt = random.randint(150, 1500)
                login_attempts = 0
                cpu_usage = round(random.uniform(75.0, 99.9), 2)
                mem_usage = round(random.uniform(70.0, 95.0), 2)
                resp_time = round(random.uniform(400.0, 3500.0), 2)

            elif attack_type == 'Port Scan':
                source_ip = random.choice(scan_ip_pool)
                dest_ip = random.choice(dest_ips)
                protocol = 'TCP'
                port = random.randint(1, 65535)
                packets = random.randint(1, 5)
                bytes_cnt = random.randint(40, 300)
                req_cnt = random.randint(20, 100)
                login_attempts = 0
                cpu_usage = round(random.uniform(30.0, 60.0), 2)
                mem_usage = round(random.uniform(30.0, 55.0), 2)
                resp_time = round(random.uniform(5.0, 30.0), 2)

            elif attack_type == 'Brute Force':
                source_ip = random.choice(brute_ip_pool)
                dest_ip = random.choice(dest_ips)
                protocol = 'HTTP'
                port = random.choice([80, 443, 22])
                packets = random.randint(10, 80)
                bytes_cnt = random.randint(1200, 9000)
                req_cnt = random.randint(15, 80)
                login_attempts = random.randint(8, 120)
                cpu_usage = round(random.uniform(40.0, 75.0), 2)
                mem_usage = round(random.uniform(40.0, 70.0), 2)
                resp_time = round(random.uniform(120.0, 600.0), 2)

            elif attack_type == 'Malicious Payload':
                source_ip = random.choice(payload_ip_pool)
                dest_ip = random.choice(dest_ips)
                protocol = 'HTTP'
                port = random.choice([80, 443, 8080])
                packets = random.randint(50, 300)
                bytes_cnt = random.randint(15000, 95000)
                req_cnt = random.randint(5, 30)
                login_attempts = random.randint(0, 3)
                cpu_usage = round(random.uniform(50.0, 85.0), 2)
                mem_usage = round(random.uniform(50.0, 80.0), 2)
                resp_time = round(random.uniform(250.0, 1200.0), 2)

            # Record dictionary matching exact schema
            row = {
                'Timestamp': current_time.isoformat(),
                'Source IP': source_ip,
                'Destination IP': dest_ip,
                'Protocol': protocol,
                'Port': port,
                'Packets': packets,
                'Bytes': bytes_cnt,
                'Request Count': req_cnt,
                'Login Attempts': login_attempts,
                'CPU Usage': cpu_usage,
                'Memory Usage': mem_usage,
                'Response Time': resp_time,
                'Attack Type': attack_type,
                'Label': is_attack
            }
            data.append(row)

    # Shuffle data to interleave attack and normal traffic
    random.shuffle(data)
    df = pd.DataFrame(data)

    if output_file is None:
        output_file = Config.DATASET_DIR / 'cloud_telemetry_50k.csv'

    output_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False)
    print(f"Dataset generated successfully and saved to: {output_file}")
    print(f"Total Rows: {len(df)}")
    print("Class Distribution:")
    print(df['Attack Type'].value_counts())
    print("\nLabel Summary (0=Normal, 1=Attack):")
    print(df['Label'].value_counts())

    return df


if __name__ == '__main__':
    generate_telemetry_dataset()
