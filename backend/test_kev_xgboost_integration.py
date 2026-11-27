"""Focused tests for the exploratory KEV XGBoost integration."""

from pathlib import Path

import pytest

from app.risk.xgboost_model import KEVXGBoostPredictor
from app.services.risk_service import KEVRiskService


def test_missing_model_raises():
    with pytest.raises(FileNotFoundError):
        KEVXGBoostPredictor("/nonexistent/kev-model.json")


def test_model_rejects_invalid_features():
    model_paths = sorted(
        Path("data/ml_experiments").glob(
            "kev90d_exploratory_*/xgboost_model.json"
        )
    )
    if not model_paths:
        pytest.skip("No locally trained model available")

    predictor = KEVXGBoostPredictor(model_paths[-1])

    with pytest.raises(ValueError):
        predictor.predict_probability(-0.1, 0.5, 365)

    with pytest.raises(ValueError):
        predictor.predict_probability(0.5, 1.1, 365)

    with pytest.raises(ValueError):
        predictor.predict_probability(0.5, 0.9, -1)


def test_service_inference():
    model_paths = sorted(
        Path("data/ml_experiments").glob(
            "kev90d_exploratory_*/xgboost_model.json"
        )
    )
    if not model_paths:
        pytest.skip("No locally trained model available")

    service = KEVRiskService(model_paths[-1])
    result = service.predict(
        epss=0.5,
        percentile=0.9,
        age_days=365,
    )

    assert 0 <= result["kev_90d_ranking_score"] <= 1
    assert result["calibrated"] is False
    assert result["model_status"] == "exploratory"
