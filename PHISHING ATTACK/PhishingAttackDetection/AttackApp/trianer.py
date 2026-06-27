"""
security_core/ml_models/trainer.py

Trains and saves all 5 detection models:
  - Phishing      → RandomForestClassifier
  - Malware       → XGBClassifier
  - Brute Force   → LogisticRegression
  - SQL Injection → LinearSVC
  - DoS           → IsolationForest

Run:  python manage.py train_models
"""
import logging
import numpy as np
from pathlib import Path

logger = logging.getLogger('security_core')

import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
# ── Synthetic training data generators ──────────────────────────────────────

def _make_phishing_data(n=2000):
    """32 features: 22 URL + 10 message features."""
    rng = np.random.default_rng(42)
    X_safe = rng.random((n, 32)) * [
        100, 20, 50, 30, 1, 5, 2, 0, 1, 1, 2, 3, 1,
        0, 1, 0, 0, 1, 2.5, 1.5, 0.2, 0,
        50, 8, 3, 0, 0, 30, 0.05, 0, 0, 2.5,
    ]
    # Phishing samples: longer URLs, high entropy, keyword hits
    X_phish = rng.random((n, 32)) * [
        250, 50, 120, 80, 4, 15, 8, 2, 3, 3, 6, 8, 10,
        1, 0, 1, 1, 5, 4.0, 3.5, 0.6, 1,
        120, 20, 6, 3, 2, 8, 0.4, 1, 1, 4.5,
    ]
    X = np.vstack([X_safe, X_phish])
    y = np.array([0] * n + [1] * n)
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


def _make_malware_data(n=2000):
    """22 URL features only."""
    rng = np.random.default_rng(43)
    X_safe = rng.random((n, 22)) * [100, 20, 50, 30, 1, 5, 2, 0, 1, 1, 2, 3, 1, 0, 1, 0, 0, 1, 2.5, 1.5, 0.2, 0]
    X_mal = rng.random((n, 22)) * [300, 60, 200, 100, 5, 20, 10, 1, 4, 2, 8, 15, 30, 1, 0, 1, 1, 0, 4.5, 4.0, 0.8, 1]
    X = np.vstack([X_safe, X_mal])
    y = np.array([0] * n + [1] * n)
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


def _make_brute_force_data(n=2000):
    """9 request metadata features."""
    rng = np.random.default_rng(44)
    X_normal = rng.random((n, 9)) * [1, 5, 0, 1, 0, 1, 2, 0, 0]
    X_brute = rng.random((n, 9)) * [50, 200, 10, 1, 1, 1, 0.5, 1, 1]
    X_brute[:, 2] = rng.integers(6, 50, n)  # failed_auth_count
    X = np.vstack([X_normal, X_brute])
    y = np.array([0] * n + [1] * n)
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


def _make_sqli_data(n=2000):
    """8 SQL injection features."""
    rng = np.random.default_rng(45)
    X_safe = rng.random((n, 8)) * [0, 100, 0, 0, 0, 0.01, 0, 0]
    X_sqli = rng.random((n, 8)) * [10, 500, 8, 4, 5, 0.3, 1, 1]
    X_sqli[:, 0] = rng.integers(3, 15, n)  # pattern_hits
    X = np.vstack([X_safe, X_sqli])
    y = np.array([0] * n + [1] * n)
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


def _make_dos_data(n=2000):
    """9 request metadata features (same shape as brute force)."""
    rng = np.random.default_rng(46)
    X_normal = rng.random((n, 9)) * [2, 10, 0, 1, 0, 0.5, 5, 0, 0]
    X_dos = rng.random((n, 9)) * [500, 10000, 0, 0, 0, 0, 50, 0, 0]
    X_dos[:, 0] = rng.uniform(100, 1000, n)  # rps
    X = np.vstack([X_normal, X_dos])
    # IsolationForest only uses X (unsupervised)
    idx = rng.permutation(len(X))
    return X[idx], None


# ─── Model definitions ────────────────────────────────────────────────────────

def build_models():
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.linear_model import LogisticRegression
    from sklearn.svm import LinearSVC
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    try:
        from xgboost import XGBClassifier
        xgb_model = XGBClassifier(n_estimators=100, max_depth=5, use_label_encoder=False,
                                   eval_metric='logloss', random_state=42)
    except ImportError:
        from sklearn.ensemble import GradientBoostingClassifier
        xgb_model = GradientBoostingClassifier(n_estimators=100, max_depth=4, random_state=42)
        logger.warning("XGBoost not available, using GradientBoostingClassifier for malware model")

    return {
        'phishing': RandomForestClassifier(n_estimators=150, max_depth=8, random_state=42),
        'malware': xgb_model,
        'brute_force': Pipeline([
            ('scaler', StandardScaler()),
            ('lr', LogisticRegression(max_iter=500, random_state=42)),
        ]),
        'sql_injection': Pipeline([
            ('scaler', StandardScaler()),
            ('svm', LinearSVC(max_iter=2000, random_state=42)),
        ]),
        'dos': IsolationForest(n_estimators=100, contamination=0.1, random_state=42),
    }


def train_all(output_dir: Path):
    import joblib
    output_dir.mkdir(parents=True, exist_ok=True)

    datasets = {
        'phishing':      (_make_phishing_data, 'phishing_rf.pkl'),
        'malware':       (_make_malware_data,  'malware_xgb.pkl'),
        'brute_force':   (_make_brute_force_data, 'brute_force_lr.pkl'),
        'sql_injection': (_make_sqli_data,     'sqli_svm.pkl'),
        'dos':           (_make_dos_data,       'dos_isolation_forest.pkl'),
    }
    models = build_models()

    for name, (data_fn, filename) in datasets.items():
        logger.info(f"Training {name} model...")
        X, y = data_fn()
        model = models[name]

        if y is not None:
            model.fit(X, y)
        else:
            model.fit(X)  # IsolationForest

        out = output_dir / filename
        joblib.dump(model, out)
        logger.info(f"  Saved → {out}")

    logger.info("All 5 models trained and saved.")