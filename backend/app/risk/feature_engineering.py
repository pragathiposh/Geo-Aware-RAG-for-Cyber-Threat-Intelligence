
from typing import Optional

from app.risk.schemas import ThreatInput, TargetContext


FEATURE_NAMES = [
    "cvss_score",
    "active_exploitation",
    "indicator_count",
    "malware_family_count",
    "attack_technique_count",
    "cve_count",
    "country_count",
    "industry_count",
    "geo_relevance",
    "industry_relevance",
    "network_exposure",
    "critical_asset_tier",
    "existing_controls_score",
]


def _normalize_text(value: Optional[str]) -> str:
    """Normalize text for consistent matching."""
    return value.strip().casefold() if value else ""


def _calculate_geo_relevance(
    threat: ThreatInput,
    context: Optional[TargetContext],
) -> float:
    """Determine whether the threat geography matches the target."""

    if context is None or not context.target_country:
        return 0.0

    target_country = _normalize_text(context.target_country)

    threat_countries = {
        _normalize_text(country)
        for country in threat.countries
        if country
    }

    return float(target_country in threat_countries)


def _calculate_industry_relevance(
    threat: ThreatInput,
    context: Optional[TargetContext],
) -> float:
    """Determine whether the threat targets the specified industry."""

    if context is None or not context.target_industry:
        return 0.0

    target_industry = _normalize_text(context.target_industry)

    threat_industries = {
        _normalize_text(industry)
        for industry in threat.industries
        if industry
    }

    return float(target_industry in threat_industries)


def extract_features(
    threat: ThreatInput,
    context: Optional[TargetContext] = None,
) -> dict[str, float]:
    """
    Convert threat intelligence into numerical ML features.

    All returned feature values are numeric and finite.
    """

    features = {
        "cvss_score": (
            float(threat.cvss_score)
            if threat.cvss_score is not None
            else 0.0
        ),

        "active_exploitation": float(threat.is_actively_exploited),

        "indicator_count": float(threat.indicators_count),

        "malware_family_count": float(len(threat.malware_families)),

        "attack_technique_count": float(len(threat.attack_ids)),

        "cve_count": float(len(threat.cve_ids)),

        "country_count": float(len(threat.countries)),

        "industry_count": float(len(threat.industries)),

        "geo_relevance": _calculate_geo_relevance(threat, context),

        "industry_relevance": _calculate_industry_relevance(
            threat,
            context,
        ),

        "network_exposure": (
            float(context.network_exposure)
            if context is not None
            else 0.5
        ),

        "critical_asset_tier": (
            float(context.critical_asset_tier)
            if context is not None
            else 2.0
        ),

        "existing_controls_score": (
            float(context.existing_controls_score)
            if context is not None
            else 0.0
        ),
    }

    return features


def extract_feature_vector(
    threat: ThreatInput,
    context: Optional[TargetContext] = None,
) -> list[float]:
    """Return features in a consistent order for ML prediction."""

    features = extract_features(threat, context)

    return [features[name] for name in FEATURE_NAMES]


def get_feature_names() -> list[str]:
    """Return the ordered ML feature names."""

    return FEATURE_NAMES.copy()

