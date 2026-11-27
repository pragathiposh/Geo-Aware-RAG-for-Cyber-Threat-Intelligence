"""Tests for automatic CVE-based KEV ranking."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import kev_risk


def make_client(monkeypatch, epss_available=True):
    def fake_epss(cve_ids):
        if not epss_available:
            return []
        return [{
            "cve": cve_ids[0],
            "epss": 0.5,
            "percentile": 0.9,
            "date": "2026-11-27",
        }]

    def fake_nvd(self, cve_id):
        return [{
            "cve": {
                "id": cve_id,
                "published": "2024-04-12T12:00:00.000",
            }
        }]

    monkeypatch.setattr(kev_risk, "fetch_epss", fake_epss)
    monkeypatch.setattr(
        kev_risk.NVDCollector,
        "fetch_by_cve",
        fake_nvd,
    )

    app = FastAPI()
    app.include_router(kev_risk.router)
    return TestClient(app)


def test_automatic_cve_prediction(monkeypatch):
    client = make_client(monkeypatch)
    response = client.post(
        "/api/risk/kev-90d/by-cve",
        json={"cve_id": "cve-2024-3400"},
    )

    assert response.status_code == 200, response.text

    data = response.json()
    assert data["cve_id"] == "CVE-2024-3400"
    assert data["epss"] == 0.5
    assert data["epss_percentile"] == 0.9
    assert data["age_days"] > 0
    assert 0 <= data["kev_90d_ranking_score"] <= 1
    assert data["calibrated"] is False


def test_invalid_cve_rejected(monkeypatch):
    client = make_client(monkeypatch)
    response = client.post(
        "/api/risk/kev-90d/by-cve",
        json={"cve_id": "not-a-cve"},
    )
    assert response.status_code == 422


def test_missing_epss_handled(monkeypatch):
    client = make_client(monkeypatch, epss_available=False)
    response = client.post(
        "/api/risk/kev-90d/by-cve",
        json={"cve_id": "CVE-2024-3400"},
    )
    assert response.status_code == 404
