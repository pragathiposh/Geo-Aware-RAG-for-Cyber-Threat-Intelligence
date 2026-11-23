
from typing import Optional

from app.risk.schemas import ThreatInput, TargetContext, RiskLevel


RISK_WEIGHTS = {
    "severity": 0.30,
    "exploitability": 0.25,
    "threat_activity": 0.25,
    "geo_exposure": 0.20,
}


def calculate_severity(threat: ThreatInput) -> float:
    """Convert CVSS score (0-10) into a 0-100 severity score."""
    if threat.cvss_score is None:
        return 0.0

    return round(threat.cvss_score * 10, 2)


def calculate_exploitability(threat: ThreatInput) -> float:
    """Calculate a preliminary rule-based exploitability score."""
    score = 20.0

    if threat.is_actively_exploited:
        score += 60.0

    if threat.attack_ids:
        score += 10.0

    if threat.cve_ids:
        score += 10.0

    return min(round(score, 2), 100.0)


def calculate_threat_activity(threat: ThreatInput) -> float:
    """Estimate activity using available threat intelligence indicators."""
    score = 0.0

    if threat.malware_families:
        score += 20.0

    score += min(threat.indicators_count * 2, 30.0)

    if threat.is_actively_exploited:
        score += 30.0

    if threat.attack_ids:
        score += 20.0

    return min(round(score, 2), 100.0)


def calculate_geo_exposure(
    threat: ThreatInput,
    context: Optional[TargetContext] = None
) -> float:
    """Estimate geographic relevance using country matching."""

    if context is None or not context.target_country:
        return 0.0

    if not threat.countries:
        return 0.0

    target_country = context.target_country.strip().casefold()

    threat_countries = {
        country.strip().casefold()
        for country in threat.countries
    }

    if target_country in threat_countries:
        return 100.0

    return 0.0


def calculate_industry_relevance(
    threat: ThreatInput,
    context: Optional[TargetContext] = None
) -> float:
    """Estimate relevance using industry matching."""

    if context is None or not context.target_industry:
        return 0.0

    if not threat.industries:
        return 0.0

    target_industry = context.target_industry.strip().casefold()

    threat_industries = {
        industry.strip().casefold()
        for industry in threat.industries
    }

    if target_industry in threat_industries:
        return 100.0

    return 0.0


def calculate_heuristic_score(
    threat: ThreatInput,
    context: Optional[TargetContext] = None
) -> tuple[float, dict[str, float]]:
    """Calculate the weighted baseline risk score."""

    features = {
        "severity": calculate_severity(threat),
        "exploitability": calculate_exploitability(threat),
        "threat_activity": calculate_threat_activity(threat),
        "geo_exposure": calculate_geo_exposure(threat, context),
    }

    score = sum(
        features[name] * weight
        for name, weight in RISK_WEIGHTS.items()
    )

    return round(min(max(score, 0.0), 100.0), 2), features


def classify_risk(score: float) -> RiskLevel:
    """Classify a risk score into a risk category."""

    if not 0.0 <= score <= 100.0:
        raise ValueError("Risk score must be between 0 and 100.")

    if score >= 75:
        return RiskLevel.CRITICAL
    elif score >= 50:
        return RiskLevel.HIGH
    elif score >= 25:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW
