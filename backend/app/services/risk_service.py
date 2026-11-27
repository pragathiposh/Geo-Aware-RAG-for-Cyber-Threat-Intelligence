"""Service layer for exploratory 90-day CISA KEV ranking."""

from pathlib import Path

from app.risk.xgboost_model import KEVXGBoostPredictor


class KEVRiskService:
    """Serve XGBoost KEV ranking scores without modifying heuristic risk."""

    def __init__(self, model_path: str | Path):
        self.predictor = KEVXGBoostPredictor(model_path)

    def predict(
        self,
        epss: float,
        percentile: float,
        age_days: float,
    ) -> dict:
        score = self.predictor.predict_probability(
            epss=epss,
            percentile=percentile,
            age_days=age_days,
        )
        return {
            "kev_90d_ranking_score": score,
            "target": "CISA KEV addition within 90 days",
            "calibrated": False,
            "model_status": "exploratory",
        }
