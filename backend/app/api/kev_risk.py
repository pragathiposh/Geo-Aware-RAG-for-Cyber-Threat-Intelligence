"""Exploratory XGBoost API for 90-day CISA KEV listing."""

from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.risk_service import KEVRiskService


router = APIRouter(prefix="/api/risk", tags=["Risk Prediction"])


class KEVRiskRequest(BaseModel):
    epss: float = Field(ge=0, le=1)
    percentile: float = Field(ge=0, le=1)
    age_days: float = Field(ge=0)


@lru_cache(maxsize=1)
def get_service() -> KEVRiskService:
    base = Path(__file__).resolve().parents[2]
    model_paths = sorted(
        (base / "data/ml_experiments").glob(
            "kev90d_exploratory_*/xgboost_model.json"
        )
    )

    if not model_paths:
        raise FileNotFoundError("No trained KEV XGBoost model found")

    return KEVRiskService(model_paths[-1])


@router.post("/kev-90d")
def predict_kev_risk(request: KEVRiskRequest):
    try:
        service = get_service()
        return service.predict(
            epss=request.epss,
            percentile=request.percentile,
            age_days=request.age_days,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
