
from app.risk.schemas import (
    ThreatInput,
    TargetContext,
    ConfidenceBreakdown,
    ConfidenceLevel,
)


def calculate_data_completeness(threat: ThreatInput) -> float:
    """Estimate completeness of the threat intelligence record."""

    checks = [
        bool(threat.title),
        bool(threat.description),
        bool(threat.author),
        bool(threat.tlp),
        bool(threat.malware_families),
        bool(threat.attack_ids),
        bool(threat.countries),
        bool(threat.industries),
        threat.indicators_count > 0,
        threat.cvss_score is not None,
        bool(threat.cve_ids),
        bool(threat.created_at),
    ]

    return round(sum(checks) / len(checks), 2)


def calculate_source_reliability(threat: ThreatInput) -> float:
    """Estimate reliability using available source attribution."""

    if not threat.author:
        return 0.40

    return 0.75


def calculate_model_certainty(threat: ThreatInput) -> float:
    """Estimate certainty from the availability of structured threat evidence."""

    evidence_count = sum([
        bool(threat.attack_ids),
        bool(threat.cve_ids),
        bool(threat.malware_families),
        bool(threat.countries),
        bool(threat.industries),
        threat.indicators_count > 0,
        threat.cvss_score is not None,
        threat.is_actively_exploited,
    ])

    return round(min(evidence_count / 6, 1.0), 2)


def calculate_context_alignment(
    threat: ThreatInput,
    context: TargetContext | None = None,
) -> float:
    """Measure how well threat intelligence matches the target context."""

    if context is None:
        return 0.50

    matches = []
    comparisons = 0

    if context.target_country:
        comparisons += 1
        countries = {
            country.strip().casefold()
            for country in threat.countries
        }
        matches.append(
            1.0 if context.target_country.strip().casefold() in countries
            else 0.0
        )

    if context.target_industry:
        comparisons += 1
        industries = {
            industry.strip().casefold()
            for industry in threat.industries
        }
        matches.append(
            1.0 if context.target_industry.strip().casefold() in industries
            else 0.0
        )

    if comparisons == 0:
        return 0.50

    return round(sum(matches) / comparisons, 2)


def calculate_overall_confidence(
    data_completeness: float,
    source_reliability: float,
    model_certainty: float,
    context_alignment: float,
) -> float:
    """Calculate weighted overall confidence."""

    score = (
        data_completeness * 0.30
        + source_reliability * 0.20
        + model_certainty * 0.30
        + context_alignment * 0.20
    )

    return round(max(0.0, min(score, 1.0)), 2)


def classify_confidence(score: float) -> ConfidenceLevel:
    """Convert confidence score into a confidence category."""

    if not 0.0 <= score <= 1.0:
        raise ValueError("Confidence score must be between 0 and 1.")

    if score >= 0.75:
        return ConfidenceLevel.HIGH
    elif score >= 0.45:
        return ConfidenceLevel.MEDIUM

    return ConfidenceLevel.LOW


def assess_confidence(
    threat: ThreatInput,
    context: TargetContext | None = None,
) -> ConfidenceBreakdown:
    """Generate the complete confidence assessment."""

    completeness = calculate_data_completeness(threat)
    reliability = calculate_source_reliability(threat)
    certainty = calculate_model_certainty(threat)
    alignment = calculate_context_alignment(threat, context)

    overall = calculate_overall_confidence(
        completeness,
        reliability,
        certainty,
        alignment,
    )

    notes = []

    if completeness < 0.60:
        notes.append("Threat intelligence record has missing fields.")

    if not threat.author:
        notes.append("Source attribution is unavailable.")

    if certainty < 0.50:
        notes.append("Limited structured threat evidence is available.")

    if context is None:
        notes.append("Target context was not provided.")

    if not notes:
        notes.append("Sufficient evidence is available for this assessment.")

    return ConfidenceBreakdown(
        data_completeness=completeness,
        source_reliability=reliability,
        model_certainty=certainty,
        context_alignment=alignment,
        overall_confidence=overall,
        confidence_level=classify_confidence(overall),
        evaluation_notes=notes,
    )
