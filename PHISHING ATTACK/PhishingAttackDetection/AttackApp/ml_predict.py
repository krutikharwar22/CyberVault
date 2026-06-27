from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from django.conf import settings

from .domain_trust import apply_domain_trust_to_prediction
from .url_features import extract_url_features


@dataclass(frozen=True)
class UrlThreatPrediction:
    verdict: str  # "threat" | "safe"
    threat_type: str  # "phishing" | "malware" | "safe"
    score: float  # winning score (0..1 when available)
    scores: dict[str, float]  # per-model scores
    model: str  # winning model key/name used


def _models_dir() -> Path:
    # Stored inside the Django project root by default
    return Path(settings.BASE_DIR) / "AttackApp" / "ml_models"


def _load_joblib(path: Path) -> Any:
    import joblib

    return joblib.load(path)


def _score_binary(model: Any, X: np.ndarray) -> float:
    """
    Returns a threat score in [0,1] when possible.
    Falls back to squashed decision scores when proba isn't available.
    """
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        return float(proba[0, 1])

    if hasattr(model, "decision_function"):
        s = float(model.decision_function(X)[0])
        # Logistic squash: maps (-inf, +inf) -> (0,1)
        return float(1.0 / (1.0 + np.exp(-s)))

    # Last resort: treat predict() as hard label
    y = int(model.predict(X)[0])
    return 1.0 if y == 1 else 0.0


def predict_url(url: str, *, threshold: float = 0.5) -> UrlThreatPrediction:
    """
    Predict whether a URL is a threat.

    Runs both models (when present) and returns the highest scoring threat type.
    """
    models_dir = _models_dir()
    phishing_path = models_dir / "phishing_rf.pkl"
    malware_path = models_dir / "malware_xgb.pkl"

    url_feats22 = extract_url_features(url).reshape(1, -1)

    scores: dict[str, float] = {}

    # Malware model (22 features)
    if malware_path.exists():
        malware_model = _load_joblib(malware_path)
        scores["malware"] = _score_binary(malware_model, url_feats22)

    # Phishing model (32 features: 22 URL + 10 zeros)
    if phishing_path.exists():
        pad10 = np.zeros((1, 10), dtype=np.float32)
        X32 = np.concatenate([url_feats22.astype(np.float32), pad10], axis=1)
        phishing_model = _load_joblib(phishing_path)
        scores["phishing"] = _score_binary(phishing_model, X32)

    if not scores:
        raise FileNotFoundError(
            f"No model files found in {models_dir}. Run: python manage.py train_models"
        )

    threat_type = max(scores, key=scores.get)
    best = float(scores[threat_type])
    if best >= threshold:
        ml_verdict, ml_type, ml_score = "threat", threat_type, best
    else:
        ml_verdict, ml_type, ml_score = "safe", "safe", best

    final_verdict, final_type, final_score, domain = apply_domain_trust_to_prediction(
        url, ml_verdict, ml_type, ml_score
    )
    model_used = threat_type if (final_verdict == "threat" and ml_verdict == "threat") else "domain_policy"
    return UrlThreatPrediction(
        verdict=final_verdict,
        threat_type=final_type,
        score=final_score,
        scores=scores,
        model=model_used,
    )

