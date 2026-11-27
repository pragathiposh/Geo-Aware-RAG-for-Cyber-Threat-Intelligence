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
    model_path = base / "models/kev_xgboost_exploratory.json"

    if not model_path.is_file():
        raise FileNotFoundError(
            f"Portable KEV XGBoost model not found: {model_path}"
        )

    return KEVRiskService(model_path)


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


# Automatic CVE feature extraction
import re
from datetime import datetime, timezone

import requests
from app.collectors.epss_collector import fetch_epss
from app.collectors.nvd import NVDCollector


class KEVCVERequest(BaseModel):
    cve_id: str


@router.post("/kev-90d/by-cve")
def predict_kev_risk_by_cve(request: KEVCVERequest):
    cve_id = request.cve_id.strip().upper()

    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve_id):
        raise HTTPException(
            status_code=422,
            detail="Invalid CVE identifier",
        )

    try:
        epss_records = fetch_epss([cve_id])
        nvd_records = NVDCollector().fetch_by_cve(cve_id)
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail="External vulnerability data service unavailable",
        ) from exc

    epss_record = next(
        (
            item for item in epss_records
            if item.get("cve", "").upper() == cve_id
        ),
        None,
    )

    nvd_record = next(
        (
            item.get("cve", {})
            for item in nvd_records
            if item.get("cve", {}).get("id", "").upper() == cve_id
        ),
        None,
    )

    if nvd_record is None:
        raise HTTPException(
            status_code=404,
            detail="CVE not found in NVD",
        )

    if epss_record is None:
        raise HTTPException(
            status_code=404,
            detail="Historical or current EPSS score unavailable for CVE",
        )

    if str(nvd_record.get("vulnStatus", "")).lower() == "rejected":
        raise HTTPException(
            status_code=422,
            detail="NVD marks this CVE as rejected",
        )

    try:
        published = datetime.fromisoformat(
            nvd_record["published"].replace("Z", "+00:00")
        )
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - published).total_seconds() / 86400

        if age_days < 0:
            raise ValueError("Publication date is in the future")

        epss = float(epss_record["epss"])
        percentile = float(epss_record["percentile"])

        service = get_service()
        prediction = service.predict(
            epss=epss,
            percentile=percentile,
            age_days=age_days,
        )

    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Invalid vulnerability feature data",
        ) from exc

    return {
        "cve_id": cve_id,
        "epss": epss,
        "epss_percentile": percentile,
        "epss_date": epss_record.get("date"),
        "nvd_published": published.isoformat(),
        "age_days": round(age_days, 2),
        "features_as_of": now.isoformat(),
        **prediction,
    }
