"""
Machine Learning Model Training & Comparative Evaluation Pipeline.
Trains Random Forest, XGBoost, Decision Tree, and Logistic Regression models.
Selects best performing model and exports champion artifacts.
"""

import sys
import logging
from pathlib import Path
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import Config
from ml_engine.preprocess import load_and_preprocess_data
from ml_engine.utils import evaluate_classifier_performance, save_metrics_to_json

logger = logging.getLogger(__name__)


def train_and_evaluate_models():
    """
    Train 4 machine learning classifiers, compare evaluation metrics,
    select best model, and save champion model artifacts.
    """
    print("==========================================================================")
    print("STARTING ML MODEL TRAINING & COMPARATIVE EVALUATION PIPELINE")
    print("==========================================================================")

    # 1. Preprocess & Split Data
    data = load_and_preprocess_data(save_artifacts=True)
    X_train, y_train = data['X_train'], data['y_train']
    X_val, y_val = data['X_val'], data['y_val']
    X_test, y_test = data['X_test'], data['y_test']

    # 2. Define Model Classifier Suite
    models = {
        'Random Forest': RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1),
        'XGBoost': XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, eval_metric='logloss', n_jobs=-1),
        'Decision Tree': DecisionTreeClassifier(max_depth=12, random_state=42),
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42)
    }

    results = {}
    fitted_models = {}

    print("\nTraining Classifiers...")
    for model_name, model in models.items():
        print(f"\n---> Training {model_name}...")
        model.fit(X_train, y_train)

        # Validate on Validation set
        val_preds = model.predict(X_val)
        val_metrics = evaluate_classifier_performance(y_val, val_preds, f"{model_name} (Validation)")

        # Evaluate on Test set
        test_preds = model.predict(X_test)
        test_metrics = evaluate_classifier_performance(y_test, test_preds, f"{model_name} (Test)")

        results[model_name] = {
            'validation': val_metrics,
            'test': test_metrics
        }
        fitted_models[model_name] = model

    # 3. Model Selection based on Test F1 Score & Accuracy
    best_model_name = None
    best_f1_score = -1.0
    best_model = None

    for name, res in results.items():
        f1 = res['test']['f1_score']
        if f1 > best_f1_score:
            best_f1_score = f1
            best_model_name = name
            best_model = fitted_models[name]

    print("\n==========================================================================")
    print("MODEL COMPARISON SUMMARY (TEST SET)")
    print("==========================================================================")
    print(f"{'Model Name':<22} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1 Score':<10}")
    print("-" * 75)
    for name, res in results.items():
        m = res['test']
        print(f"{name:<22} | {m['accuracy']:<10.4f} | {m['precision']:<10.4f} | {m['recall']:<10.4f} | {m['f1_score']:<10.4f}")

    print("-" * 75)
    print(f"CHAMPION MODEL SELECTED: '{best_model_name}' (F1 Score: {best_f1_score:.4f})")
    print("==========================================================================")

    # 4. Save Best Model & Metrics JSON
    Config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    best_model_path = Config.MODELS_DIR / 'best_model.pkl'
    metrics_path = Config.MODELS_DIR / 'metrics.json'

    joblib.dump(best_model, best_model_path)
    print(f"Saved Champion Model to: {best_model_path}")

    # Build summary metrics payload
    metrics_summary = {
        'champion_model': best_model_name,
        'best_f1_score': best_f1_score,
        'models_evaluation': results
    }
    save_metrics_to_json(metrics_summary, metrics_path)

    return best_model_name, results


if __name__ == '__main__':
    train_and_evaluate_models()
