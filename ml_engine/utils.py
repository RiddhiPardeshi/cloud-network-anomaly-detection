"""
Machine Learning Utility Helpers for Cloud Network Anomaly Detection.
Provides evaluation metrics computation and JSON export functions.
"""

import json
import logging
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

logger = logging.getLogger(__name__)


def evaluate_classifier_performance(y_true, y_pred, model_name="Classifier"):
    """
    Compute Accuracy, Precision, Recall, and F1 Score.
    """
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred).tolist()

    metrics = {
        'model_name': model_name,
        'accuracy': round(float(acc), 4),
        'precision': round(float(prec), 4),
        'recall': round(float(rec), 4),
        'f1_score': round(float(f1), 4),
        'confusion_matrix': cm
    }

    logger.info(
        f"[{model_name}] Accuracy: {metrics['accuracy']:.4f} | "
        f"Precision: {metrics['precision']:.4f} | "
        f"Recall: {metrics['recall']:.4f} | "
        f"F1 Score: {metrics['f1_score']:.4f}"
    )

    return metrics


def save_metrics_to_json(metrics_dict, output_path):
    """Save model performance metrics summary to JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(metrics_dict, f, indent=4)
    logger.info(f"Model comparison metrics saved to: {output_path}")
