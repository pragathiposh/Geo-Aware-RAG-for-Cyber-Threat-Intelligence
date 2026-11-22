"""Explainable pairwise CTI record correlation.

Scores are configurable evidence-strength heuristics, not probabilities and
not assertions that two reports describe the same campaign.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from pydantic import BaseModel, Field

from app.geo.geo_resolver import GeoResolver
from app.threat_analysis.cti_schema import GeographicEvidenceRole, GeographicEvidenceStatus


@dataclass(frozen=True)
class CorrelationConfig:
    """Weights reflect evidence specificity; tune from reviewed cases only."""

    factor_weights: dict[str, float] = field(default_factory=lambda: {
        "shared_ioc": 0.85,
        "shared_malware": 0.70,
        "shared_actor": 0.70,
        "shared_campaign": 0.70,
        "shared_cve": 0.25,
        "shared_attack_technique": 0.10,
        "geographic_overlap": 0.08,
        "temporal_proximity": 0.05,
    })
    minimum_confidence: float = 0.20
    temporal_window_days: int = 90

    def __post_init__(self):
        required = {"shared_ioc", "shared_malware", "shared_actor", "shared_campaign", "shared_cve", "shared_attack_technique", "geographic_overlap", "temporal_proximity"}
        if not required.issubset(self.factor_weights):
            raise ValueError(f"factor_weights missing: {sorted(required - self.factor_weights.keys())}")
        if not 0 <= self.minimum_confidence <= 1:
            raise ValueError("minimum_confidence must be between 0 and 1")
        if self.temporal_window_days < 0:
            raise ValueError("temporal_window_days cannot be negative")
        if any(not 0 <= value <= 1 for value in self.factor_weights.values()):
            raise ValueError("factor weights must be between 0 and 1")


class CorrelationSourceEvidence(BaseModel):
    source_record_id: str
    text: str
    provenance: str


class MatchedCorrelationEntity(BaseModel):
    entity_type: str
    normalized_value: str
    relationship_type: str
    source_evidence: list[CorrelationSourceEvidence]


class CorrelationFactorContribution(BaseModel):
    factor: str
    configured_weight: float
    contribution: float
    evidence_count: int


class ThreatCorrelation(BaseModel):
    source_record_id: str
    related_record_id: str
    related_record_ids: list[str]
    matched_entities: list[MatchedCorrelationEntity]
    relationship_types: list[str]
    supporting_evidence: list[CorrelationSourceEvidence]
    factor_contributions: list[CorrelationFactorContribution]
    correlation_confidence: float = Field(ge=0, le=1)
    confidence_semantics: str = "uncalibrated evidence-strength heuristic; not a probability"
    relationship_strength: str
    explanation: str


def _get(value: Any, name: str, default=None):
    return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)


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


def _label(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def _values(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, (list, tuple, set)) else [value]


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        dt = value
    elif value:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _cve_evidence(record: dict[str, Any]) -> dict[str, str]:
    found: dict[str, str] = {}
    for value in _values(record.get("vulnerabilities")):
        for match in re.finditer(r"\bCVE-\d{4}-\d{4,}\b", str(value), re.I):
            found[match.group().upper()] = f"vulnerabilities: {value}"
    description = str(record.get("description") or "")
    for match in re.finditer(r"\bCVE-\d{4}-\d{4,}\b", description, re.I):
        found[match.group().upper()] = description[max(0, match.start() - 90):min(len(description), match.end() + 100)].strip()
    return found


def _ioc_key(indicator: Any) -> tuple[str, str] | None:
    value = str(_get(indicator, "value", "") or "").strip()
    kind = _label(_get(indicator, "indicator_type", "") or "")
    if not value:
        return None
    compact = value.casefold().replace(":", "").replace("-", "")
    if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}", compact):
        return "hash", compact
    kind_aliases = {"sha256": "hash", "sha-256": "hash", "sha1": "hash", "md5": "hash", "ipv4": "ip", "ipv6": "ip", "ip_address": "ip", "fqdn": "domain"}
    kind = kind_aliases.get(kind, kind)
    if kind in {"ip", "ip address"}:
        try:
            return "ip", str(ipaddress.ip_address(value))
        except ValueError:
            return None
    if kind in {"domain", "hostname"}:
        try:
            return "domain", value.rstrip(".").encode("idna").decode("ascii").casefold()
        except UnicodeError:
            return None
    return (kind or "exact", re.sub(r"\s+", " ", value).casefold())


def _entity_set(items: Any, *, actor: bool = False) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for item in _values(items):
        fields = ["name", "aliases"] if actor else ["name", "family", "aliases"]
        for field_name in fields:
            for candidate in _values(_get(item, field_name)):
                normalized = _label(candidate)
                if normalized:
                    found.setdefault(normalized, []).append(str(candidate))
    return found


class ThreatCorrelationEngine:
    """Build a flat, deduplicated graph of evidence-backed record pairs."""

    def __init__(self, config: CorrelationConfig | None = None):
        self.config = config or CorrelationConfig()

    @staticmethod
    def _source_id(record: dict[str, Any]) -> str:
        return str(record.get("record_id") or record.get("source_record_id") or "").strip()

    def correlate(self, records: Iterable[Any]) -> list[ThreatCorrelation]:
        by_id: dict[str, dict[str, Any]] = {}
        for value in records:
            record = _record(value)
            source_id = self._source_id(record)
            if source_id:
                by_id.setdefault(source_id, record)
        ordered = sorted(by_id.items())
        output: list[ThreatCorrelation] = []
        for index, (left_id, left) in enumerate(ordered):
            for right_id, right in ordered[index + 1:]:
                factors: dict[str, list[MatchedCorrelationEntity]] = {}

                def add(factor: str, entity_type: str, value: str, relationship: str, left_text: str, right_text: str, left_prov: str, right_prov: str):
                    factors.setdefault(factor, []).append(MatchedCorrelationEntity(
                        entity_type=entity_type, normalized_value=value, relationship_type=relationship,
                        source_evidence=[
                            CorrelationSourceEvidence(source_record_id=left_id, text=left_text, provenance=left_prov),
                            CorrelationSourceEvidence(source_record_id=right_id, text=right_text, provenance=right_prov),
                        ],
                    ))

                left_iocs, right_iocs = {}, {}
                for record, target in ((left, left_iocs), (right, right_iocs)):
                    for indicator in _values(record.get("indicators")):
                        key = _ioc_key(indicator)
                        if key:
                            target.setdefault(key, str(_get(indicator, "value")))
                for key in sorted(left_iocs.keys() & right_iocs.keys()):
                    add("shared_ioc", key[0], key[1], "shared_exact_ioc", left_iocs[key], right_iocs[key], "canonical indicators", "canonical indicators")

                for field_name, factor, entity_type, relationship, actor in (
                    ("malware", "shared_malware", "malware", "shared_reported_malware", False),
                    ("threat_actors", "shared_actor", "threat_actor", "shared_reported_actor_name_or_alias", True),
                ):
                    lset, rset = _entity_set(left.get(field_name), actor=actor), _entity_set(right.get(field_name), actor=actor)
                    for key in sorted(lset.keys() & rset.keys()):
                        add(factor, entity_type, key, relationship, ", ".join(sorted(set(lset[key]))), ", ".join(sorted(set(rset[key]))), f"canonical {field_name}", f"canonical {field_name}")

                lcve, rcve = _cve_evidence(left), _cve_evidence(right)
                for key in sorted(lcve.keys() & rcve.keys()):
                    add("shared_cve", "cve", key, "shared_exact_cve_reference", lcve[key], rcve[key], "record field or source description", "record field or source description")

                latt = {str(_get(t, "attack_id", "")).upper(): t for t in _values(left.get("attack_techniques")) if re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(_get(t, "attack_id", "")).upper())}
                ratt = {str(_get(t, "attack_id", "")).upper(): t for t in _values(right.get("attack_techniques")) if re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(_get(t, "attack_id", "")).upper())}
                for key in sorted(latt.keys() & ratt.keys()):
                    add("shared_attack_technique", "attack_technique", key, "shared_attack_technique_supporting_only", key, key, str(_get(latt[key], "enrichment_status", "status")), str(_get(ratt[key], "enrichment_status", "status")))

                lcampaign = self._campaigns(left)
                rcampaign = self._campaigns(right)
                for key in sorted(lcampaign.keys() & rcampaign.keys()):
                    add("shared_campaign", "campaign", key, "shared_exact_reported_campaign", lcampaign[key], rcampaign[key], "raw source campaign field", "raw source campaign field")

                lgeo, rgeo = self._supported_geography(left), self._supported_geography(right)
                for key in sorted(lgeo.keys() & rgeo.keys()):
                    lval, rval = lgeo[key], rgeo[key]
                    add("geographic_overlap", "geography", key, "shared_supported_geographic_context_not_campaign_proof", lval["evidence_text"], rval["evidence_text"], f"{lval['role']} / {lval['provenance']}", f"{rval['role']} / {rval['provenance']}")

                ldate, rdate = self._record_date(left), self._record_date(right)
                if ldate and rdate and abs((ldate - rdate).days) <= self.config.temporal_window_days:
                    add("temporal_proximity", "publication_time", f"within_{self.config.temporal_window_days}_days", "publication_temporal_proximity", ldate.isoformat(), rdate.isoformat(), "created_at/modified_at", "created_at/modified_at")

                # Techniques, geography, and time alone never create a link.
                anchors = {"shared_ioc", "shared_malware", "shared_actor", "shared_campaign", "shared_cve"}
                if not (factors.keys() & anchors):
                    continue
                active = [(name, self.config.factor_weights[name], entities) for name, entities in factors.items() if name in self.config.factor_weights and entities]
                confidence = 1.0
                prior = 0.0
                contributions = []
                for name, weight, entities in sorted(active, key=lambda row: (-row[1], row[0])):
                    contribution = weight * (1.0 - prior)
                    prior += contribution
                    confidence *= (1.0 - weight)
                    contributions.append(CorrelationFactorContribution(factor=name, configured_weight=weight, contribution=contribution, evidence_count=len(entities)))
                confidence = 1.0 - confidence
                if confidence < self.config.minimum_confidence:
                    continue
                matched = [entity for _, _, entities in active for entity in entities]
                relations = sorted({entity.relationship_type for entity in matched})
                evidence = [source for entity in matched for source in entity.source_evidence]
                strong = bool(factors.keys() & {"shared_ioc", "shared_malware", "shared_actor", "shared_campaign"})
                strength = "strong_evidence" if strong else "contextual_match"
                output.append(ThreatCorrelation(
                    source_record_id=left_id, related_record_id=right_id,
                    related_record_ids=[right_id], matched_entities=matched,
                    relationship_types=relations, supporting_evidence=evidence,
                    factor_contributions=contributions, correlation_confidence=round(confidence, 6),
                    relationship_strength=strength,
                    explanation=("Exact or structured shared CTI entities support a relationship; this is not proof of a shared campaign." if strong else "The records share an exact CVE reference, which is a contextual link and not proof of a common actor or campaign."),
                ))
        return output

    @staticmethod
    def _campaigns(record: dict[str, Any]) -> dict[str, str]:
        raw = record.get("raw_metadata") or {}
        result = {}
        for key in ("campaign", "campaign_name", "campaign_names", "campaign_id", "campaign_ids"):
            for value in _values(raw.get(key)):
                text = str(value).strip()
                if text and text.casefold() not in {"unknown", "none", "nan"}:
                    result.setdefault(_label(text), text)
        return result

    @staticmethod
    def _supported_geography(record: dict[str, Any]) -> dict[str, dict[str, str]]:
        supported_roles = {role.value for role in GeographicEvidenceRole if role != GeographicEvidenceRole.GENERAL_MENTION}
        result = {}
        for claim in _values(record.get("geographic_evidence")):
            role = _get(claim, "role", "")
            status = _get(claim, "status", "")
            role = _get(role, "value", role)
            status = _get(status, "value", status)
            if status != GeographicEvidenceStatus.SUPPORTED.value or role not in supported_roles:
                continue
            country = _get(claim, "country")
            region = _get(claim, "region")
            canonical = GeoResolver.normalize_country(country) if country else None
            location = f"country:{canonical or _label(country)}" if country else f"region:{_label(region)}" if region else None
            if location:
                result.setdefault(location, {
                    "role": str(role), "provenance": str(_get(claim, "provenance", "source_description")),
                    "evidence_text": str(_get(claim, "evidence_text", "")),
                })
        return result

    @staticmethod
    def _record_date(record: dict[str, Any]) -> datetime | None:
        return _as_datetime(record.get("created_at")) or _as_datetime(record.get("modified_at"))
