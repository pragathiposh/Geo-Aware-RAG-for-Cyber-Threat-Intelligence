"""Transparent, context-dependent review prioritization (not attack prediction)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.geo.geo_resolver import GeoResolver
from app.threat_analysis.cti_schema import GeographicEvidenceRole, GeographicEvidenceStatus
from app.threat_analysis.normalization import CTINormalizer


@dataclass(frozen=True)
class PriorityConfig:
    """Provisional review-priority weights; they are not trained or predictive."""

    factor_weights: dict[str, float] = field(default_factory=lambda: {
        "explicit_exploitation_mention": 0.40,
        "industry_context_match": 0.20,
        "geographic_context_match": 0.20,
        "information_recency": 0.20,
    })
    recency_horizon_days: int = 365

    def __post_init__(self):
        required = {"explicit_exploitation_mention", "industry_context_match", "geographic_context_match", "information_recency"}
        if not required.issubset(self.factor_weights):
            raise ValueError(f"factor_weights missing: {sorted(required - self.factor_weights.keys())}")
        if self.recency_horizon_days < 1:
            raise ValueError("recency_horizon_days must be positive")
        if any(not 0 <= weight <= 1 for weight in self.factor_weights.values()):
            raise ValueError("factor weights must be between 0 and 1")


class PriorityContext(BaseModel):
    industry: str | None = None
    country: str | None = None
    region: str | None = None
    as_of: datetime | None = None


class PriorityFactor(BaseModel):
    factor: str
    configured_weight: float
    value: float | None = Field(default=None, ge=0, le=1)
    normalized_contribution: float | None = None
    status: str
    evidence: list[str] = Field(default_factory=list)
    rationale: str


class ContextualPriorityAssessment(BaseModel):
    source_record_id: str
    contextual_priority_score: float | None = Field(default=None, ge=0, le=100)
    score_semantics: str = "explainable contextual review priority; not a probability or prediction"
    coverage: float = Field(ge=0, le=1)
    factors: list[PriorityFactor]
    missing_factors: list[str] = Field(default_factory=list)
    not_configured_factors: list[str] = Field(default_factory=list)
    excluded_unavailable_factors: dict[str, str]
    explanation: str


def _record(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        raw = value.get("canonical_cti")
        if isinstance(raw, str):
            try:
                return json.loads(raw)
            except (ValueError, TypeError):
                pass
        return raw if isinstance(raw, dict) else value
    metadata = getattr(value, "metadata", None)
    if isinstance(metadata, dict) and metadata.get("canonical_cti"):
        return _record(metadata)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="python")
    return {}


def _get(value: Any, field_name: str, default=None):
    return value.get(field_name, default) if isinstance(value, dict) else getattr(value, field_name, default)


def _date(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        result = value
    elif value:
        try:
            result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, (list, tuple, set)) else [value]


class ContextualPriorityAssessor:
    """Score attention for an analyst's stated context, with explicit coverage."""

    NEGATIVE_EXPLOITATION = re.compile(
        r"\b(?:no|not|without)\s+(?:known\s+|reported\s+|observed\s+)?(?:evidence\s+of\s+)?(?:active\s+)?exploitation\b|\bnot\s+(?:been\s+)?exploited\b",
        re.I,
    )
    POSITIVE_EXPLOITATION = re.compile(
        r"\b(?:actively\s+exploited|exploited\s+in\s+the\s+wild|exploitation\s+(?:has\s+been\s+)?observed|observed\s+exploitation|exploiting\s+CVE-\d{4}-\d{4,}|(?:was|were|has\s+been)\s+exploited)\b",
        re.I,
    )
    SUPPORTED_GEO_ROLES = {GeographicEvidenceRole.INCIDENT_LOCATION.value, GeographicEvidenceRole.TARGET_LOCATION.value, GeographicEvidenceRole.VICTIM_LOCATION.value}

    def __init__(self, config: PriorityConfig | None = None):
        self.config = config or PriorityConfig()

    def assess(self, record: Any, context: PriorityContext | None = None) -> ContextualPriorityAssessment:
        item = _record(record)
        context = context or PriorityContext()
        source_id = str(item.get("record_id") or item.get("source_record_id") or "")
        weights = self.config.factor_weights
        factors: list[PriorityFactor] = []
        missing: list[str] = []
        not_configured: list[str] = []

        description = str(item.get("description") or "")
        negative = self.NEGATIVE_EXPLOITATION.search(description)
        positive = self.POSITIVE_EXPLOITATION.search(description)
        if negative:
            factors.append(PriorityFactor(
                factor="explicit_exploitation_mention", configured_weight=weights["explicit_exploitation_mention"], value=0.0,
                status="source_reports_no_exploitation_observed", evidence=[negative.group(0)],
                rationale="A source denial/absence statement is recorded as that source's claim; it is not proof of safety.",
            ))
        elif positive:
            sentence = self._sentence_for(description, positive.start(), positive.end())
            factors.append(PriorityFactor(
                factor="explicit_exploitation_mention", configured_weight=weights["explicit_exploitation_mention"], value=1.0,
                status="explicit_source_claim", evidence=[sentence],
                rationale="Explicit reported exploitation wording increases review urgency; no severity is inferred.",
            ))
        else:
            missing.append("explicit_exploitation_mention")
            factors.append(PriorityFactor(factor="explicit_exploitation_mention", configured_weight=weights["explicit_exploitation_mention"], status="missing", rationale="No recognized explicit exploitation claim was available; this is not negative evidence."))

        if context.industry:
            requested = CTINormalizer.normalize_industry(context.industry)
            industries = [CTINormalizer.normalize_industry(str(value)) for value in _list((item.get("targets") or {}).get("industries") if isinstance(item.get("targets"), dict) else _get(item.get("targets"), "industries", []))]
            industries = [industry for industry in industries if industry]
            if industries:
                matched = requested in industries
                factors.append(PriorityFactor(
                    factor="industry_context_match", configured_weight=weights["industry_context_match"], value=float(matched),
                    status="matched" if matched else "explicit_nonmatch", evidence=[f"record industries: {', '.join(industries)}", f"requested industry: {requested}"],
                    rationale="This is analyst-supplied relevance, not intrinsic threat severity.",
                ))
            else:
                missing.append("industry_context_match")
                factors.append(PriorityFactor(factor="industry_context_match", configured_weight=weights["industry_context_match"], status="missing", evidence=[f"requested industry: {requested}"], rationale="No source-supported target industry is available; missing is not a non-match."))
        else:
            not_configured.append("industry_context_match")
            factors.append(PriorityFactor(factor="industry_context_match", configured_weight=weights["industry_context_match"], status="not_configured", rationale="No analyst industry context was supplied."))

        if context.country or context.region:
            geo_claims = self._supported_geo(item)
            if geo_claims:
                target_country = GeoResolver.normalize_country(context.country) if context.country else None
                target_region = GeoResolver.resolve_region(context.region)["region"] if context.region else None
                matching = []
                for claim in geo_claims:
                    country = GeoResolver.normalize_country(str(claim.get("country") or "")) if claim.get("country") else None
                    region = claim.get("region") or (GeoResolver.get_region(country) if country else None)
                    if ((target_country and country == target_country) or (target_region and region and region.casefold() == target_region.casefold())):
                        matching.append(claim)
                value = 1.0 if matching else 0.0
                source_text = [f"{claim.get('role')}: {claim.get('country') or claim.get('region')} — {claim.get('evidence_text', '')}" for claim in geo_claims]
                factors.append(PriorityFactor(
                    factor="geographic_context_match", configured_weight=weights["geographic_context_match"], value=value,
                    status="matched" if matching else "explicit_nonmatch", evidence=source_text,
                    rationale="Only supported incident/target/victim evidence is compared; source-associated countries are ignored.",
                ))
            else:
                missing.append("geographic_context_match")
                factors.append(PriorityFactor(factor="geographic_context_match", configured_weight=weights["geographic_context_match"], status="missing", rationale="No supported incident/target/victim location is available; source-associated country metadata is not substituted."))
        else:
            not_configured.append("geographic_context_match")
            factors.append(PriorityFactor(factor="geographic_context_match", configured_weight=weights["geographic_context_match"], status="not_configured", rationale="No analyst geographic context was supplied."))

        as_of = _date(context.as_of) or datetime.now(timezone.utc)
        timestamp = _date(item.get("modified_at")) or _date(item.get("created_at"))
        if timestamp and timestamp <= as_of:
            age = max(0.0, (as_of - timestamp).total_seconds() / 86400.0)
            value = max(0.0, 1.0 - age / self.config.recency_horizon_days)
            factors.append(PriorityFactor(
                factor="information_recency", configured_weight=weights["information_recency"], value=value,
                status="scored", evidence=[f"latest available publication/update: {timestamp.isoformat()}", f"age_days: {age:.1f}"],
                rationale=f"Linear freshness decay across {self.config.recency_horizon_days} days; recency means current information, not future risk.",
            ))
        else:
            missing.append("information_recency")
            factors.append(PriorityFactor(factor="information_recency", configured_weight=weights["information_recency"], status="missing", evidence=[f"as_of: {as_of.isoformat()}"], rationale="No valid non-future source timestamp is available; missing is not evidence of safety."))

        considered = [factor for factor in factors if factor.status != "not_configured"]
        available_weight = sum(factor.configured_weight for factor in considered if factor.value is not None)
        total_weight = sum(factor.configured_weight for factor in considered)
        coverage = available_weight / total_weight if total_weight else 0.0
        if available_weight:
            score = sum(factor.configured_weight * float(factor.value) for factor in considered if factor.value is not None) / available_weight * 100.0
            for factor in factors:
                if factor.value is not None:
                    factor.normalized_contribution = round(factor.configured_weight * factor.value / available_weight * 100, 4)
            score = round(score, 2)
            explanation = f"Contextual review priority is {score:.2f}/100 over {coverage:.0%} of configured factor weight. Missing factors were excluded and listed; this score is not an attack probability."
        else:
            score = None
            explanation = "Priority is unknown because no configured factor has supported data; missing data is not evidence of safety."

        return ContextualPriorityAssessment(
            source_record_id=source_id,
            contextual_priority_score=score,
            coverage=round(coverage, 4), factors=factors,
            missing_factors=missing, not_configured_factors=not_configured,
            excluded_unavailable_factors={
                "threat_severity": "No validated severity field in the OTX CSV.",
                "cvss_severity": "CVEs may occur in descriptions, but CVSS values are unavailable.",
                "source_reliability": "The available records do not carry calibrated source reliability scores.",
                "attack_technique_severity": "ATT&CK IDs describe behavior; generic technique presence is not used as severity.",
                "retrieval_similarity": "Retrieval/reranker scores are relevance measures and are not risk inputs.",
            },
            explanation=explanation,
        )

    @staticmethod
    def _sentence_for(text: str, start: int, end: int) -> str:
        left = max(text.rfind(".", 0, start), text.rfind("!", 0, start), text.rfind("?", 0, start)) + 1
        stops = [position for mark in (".", "!", "?") if (position := text.find(mark, end)) >= 0]
        right = min(stops) + 1 if stops else len(text)
        return text[left:right].strip()

    @classmethod
    def _supported_geo(cls, record: dict[str, Any]) -> list[dict[str, Any]]:
        results = []
        for claim in _list(record.get("geographic_evidence")):
            role, status = _get(claim, "role", ""), _get(claim, "status", "")
            role, status = _get(role, "value", role), _get(status, "value", status)
            if role in cls.SUPPORTED_GEO_ROLES and status == GeographicEvidenceStatus.SUPPORTED.value:
                results.append(claim if isinstance(claim, dict) else claim.model_dump(mode="json"))
        return results
