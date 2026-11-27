"""Exploratory XGBoost predictor for 90-day CISA KEV addition."""

from pathlib import Path

import numpy as np
from xgboost import XGBClassifier


class KEVXGBoostPredictor:
    """Load a trained model and predict 90-day KEV addition probability."""

    FEATURE_NAMES = ("epss", "percentile", "age_days")

    def __init__(self, model_path: str | Path):
        self.model_path = Path(model_path)

        if not self.model_path.is_file():
            raise FileNotFoundError(
                f"XGBoost model not found: {self.model_path}"
            )

        self.model = XGBClassifier()
        self.model.load_model(str(self.model_path))

    def predict_probability(
        self,
        epss: float,
        percentile: float,
        age_days: float,
    ) -> float:
        """Return estimated probability of KEV addition within 90 days."""

        values = (epss, percentile, age_days)

        if not all(np.isfinite(value) for value in values):
            raise ValueError("All features must be finite numbers")

        if not 0 <= epss <= 1:
            raise ValueError("EPSS score must be between 0 and 1")

        if not 0 <= percentile <= 1:
            raise ValueError("EPSS percentile must be between 0 and 1")

        if age_days < 0:
            raise ValueError("CVE age cannot be negative")

        features = np.asarray([values], dtype=np.float32)
        return float(self.model.predict_proba(features)[0, 1])
