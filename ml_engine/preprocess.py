"""
Data Preprocessing Pipeline for Cloud Network Anomaly Detection.
Handles deduplication, missing values, categorical encoding, feature scaling, and stratified splitting.
"""

import sys
import logging
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import Config

logger = logging.getLogger(__name__)

# Feature column order expected by ML models
FEATURE_COLUMNS = [
    'Protocol',
    'Port',
    'Packets',
    'Bytes',
    'Request Count',
    'Login Attempts',
    'CPU Usage',
    'Memory Usage',
    'Response Time'
]


def load_and_preprocess_data(dataset_path=None, save_artifacts=True):
    """
    Load telemetry dataset, clean missing/duplicate rows, encode categorical columns,
    scale numerical features, and split into train (70%), val (15%), and test (15%).
    """
    if dataset_path is None:
        dataset_path = Config.DATASET_DIR / 'cloud_telemetry_50k.csv'

    print(f"Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)

    # 1. Deduplication & Missing Value Removal
    initial_rows = len(df)
    df.drop_duplicates(inplace=True)
    df.dropna(inplace=True)
    cleaned_rows = len(df)
    print(f"Cleaned dataset: Removed {initial_rows - cleaned_rows} duplicates/missing values. Final row count: {cleaned_rows}")

    # 2. Categorical Encoding
    protocol_encoder = LabelEncoder()
    df['Protocol'] = protocol_encoder.fit_transform(df['Protocol'].astype(str))

    # 3. Extract Features (X) and Target (y)
    X = df[FEATURE_COLUMNS].copy()
    y = df['Label'].values

    # 4. Feature Scaling with StandardScaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Convert back to DataFrame to preserve feature column names
    X_scaled_df = pd.DataFrame(X_scaled, columns=FEATURE_COLUMNS)

    # 5. Stratified Train (70%), Validation (15%), Test (15%) Split
    X_train, X_temp, y_train, y_temp = train_test_split(
        X_scaled_df, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    print(f"Dataset split summary:")
    print(f"  - Training Set: {len(X_train)} samples (70%)")
    print(f"  - Validation Set: {len(X_val)} samples (15%)")
    print(f"  - Test Set: {len(X_test)} samples (15%)")

    # 6. Save Preprocessing Artifacts
    if save_artifacts:
        Config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
        scaler_path = Config.MODELS_DIR / 'scaler.pkl'
        encoder_path = Config.MODELS_DIR / 'encoder.pkl'
        features_path = Config.MODELS_DIR / 'feature_names.json'

        joblib.dump(scaler, scaler_path)
        joblib.dump(protocol_encoder, encoder_path)

        with open(features_path, 'w') as f:
            import json
            json.dump(FEATURE_COLUMNS, f, indent=4)

        print(f"Saved preprocessing scaler to: {scaler_path}")
        print(f"Saved protocol encoder to: {encoder_path}")

    return {
        'X_train': X_train, 'y_train': y_train,
        'X_val': X_val, 'y_val': y_val,
        'X_test': X_test, 'y_test': y_test,
        'scaler': scaler,
        'protocol_encoder': protocol_encoder,
        'feature_columns': FEATURE_COLUMNS
    }


if __name__ == '__main__':
    load_and_preprocess_data()
