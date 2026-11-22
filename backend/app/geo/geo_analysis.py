"""Evidence-only geographic filtering and distinct-source aggregation."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Iterable

from app.geo.geo_resolver import GeoResolver
from app.threat_analysis.cti_schema import GeographicEvidenceRole as Role
from app.threat_analysis.cti_schema import GeographicEvidenceStatus as Status

SUPPORTED_ANALYSIS_ROLES = {Role.INCIDENT_LOCATION.value, Role.TARGET_LOCATION.value, Role.VICTIM_LOCATION.value}


def _metadata(record: Any) -> dict[str, Any]:
    if isinstance(record, dict):
        return record
    return getattr(record, "metadata", {}) or {}


def _canonical(metadata: dict[str, Any]) -> dict[str, Any]:
    raw = metadata.get("canonical_cti")
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return {}
    return raw if isinstance(raw, dict) else {}


def supported_location_evidence(records: Iterable[Any], *, country: str | None = None, region: str | None = None) -> list[dict[str, Any]]:
    """Return explicit, supported incident/target/victim evidence only."""
    evidence = []
    normalized_country = GeoResolver.normalize_country(country) if country else None
    normalized_region = GeoResolver.resolve_region(region)["region"] if region else None
    for item in records:
        metadata = _metadata(item)
        canonical = _canonical(metadata)
        source_id = str(metadata.get("source_record_id") or metadata.get("record_id") or canonical.get("record_id") or "")
        for claim in canonical.get("geographic_evidence", metadata.get("geographic_evidence", [])) or []:
            role = claim.get("role")
            status = claim.get("status")
            if role not in SUPPORTED_ANALYSIS_ROLES or status != Status.SUPPORTED.value:
                continue
            claim_country = GeoResolver.normalize_country(claim.get("country") or "")
            if country and (claim_country or (claim.get("country") or "").casefold()) != (normalized_country or country.casefold()):
                continue
            claim_region = claim.get("region") or ""
            if region and claim_region.casefold() != (normalized_region or region).casefold():
                continue
            evidence.append({**claim, "source_record_id": claim.get("source_record_id") or source_id})
    return evidence


def aggregate_geography(records: Iterable[Any], *, group_by: str = "country", threat_categories: Iterable[str] | None = None) -> dict[str, Any]:
    """Aggregate distinct source records; report source associations separately."""
    if group_by not in {"country", "region"}:
        raise ValueError("group_by must be 'country' or 'region'")
    rows = list(records)
    groups: dict[str, dict[str, Any]] = defaultdict(lambda: {"source_record_ids": set(), "evidence": [], "threat_categories": defaultdict(set)})
    associations: dict[str, set[str]] = defaultdict(set)
    unknown: set[str] = set()
    no_evidence: set[str] = set()
    unsupported_evidence: set[str] = set()
    status_counts: dict[str, set[str]] = defaultdict(set)
    categories = {str(value).casefold() for value in (threat_categories or [])}
    for item in rows:
        metadata = _metadata(item)
        canonical = _canonical(metadata)
        source_id = str(metadata.get("source_record_id") or metadata.get("record_id") or canonical.get("record_id") or "")
        if not source_id:
            continue
        geography = canonical.get("geography") or {}
        country_values = metadata.get("countries", geography.get("countries", [])) or []
        if isinstance(country_values, str):
            country_values = [part.strip() for part in country_values.replace("|", ",").split(",") if part.strip()]
        for value in country_values:
            associations[str(value)].add(source_id)
        claims = canonical.get("geographic_evidence", metadata.get("geographic_evidence", [])) or []
        usable = [claim for claim in claims if claim.get("role") in SUPPORTED_ANALYSIS_ROLES and claim.get("status") == Status.SUPPORTED.value]
        if not usable:
            unknown.add(source_id)
            if claims:
                unsupported_evidence.add(source_id)
            else:
                no_evidence.add(source_id)
        for claim in claims:
            status_counts[str(claim.get("status", "unknown"))].add(source_id)
        raw_tags = canonical.get("tags", metadata.get("canonical_tags", metadata.get("tags", []))) or []
        if isinstance(raw_tags, str):
            raw_tags = [raw_tags]
        tags = set(map(str.casefold, raw_tags))
        for claim in usable:
            key = claim.get(group_by)
            if not key:
                continue
            entry = groups[str(key)]
            entry["source_record_ids"].add(source_id)
            # avoid duplicate support from sibling chunks of a source record
            if not any(e.get("source_record_id") == source_id and e.get("evidence_text") == claim.get("evidence_text") and e.get("role") == claim.get("role") for e in entry["evidence"]):
                entry["evidence"].append({**claim, "source_record_id": source_id})
            for tag in tags & categories:
                entry["threat_categories"][tag].add(source_id)
    serialized = {
        key: {"count": len(value["source_record_ids"]), "source_record_ids": sorted(value["source_record_ids"]),
              "evidence": value["evidence"], "threat_category_counts": {tag: len(ids) for tag, ids in sorted(value["threat_categories"].items())}}
        for key, value in sorted(groups.items())
    }
    return {"group_by": group_by, "evidence_supported_counts": serialized,
            "source_association_counts": {key: len(ids) for key, ids in sorted(associations.items())},
            "unknown_or_unsupported_source_record_ids": sorted(unknown),
            "records_with_no_location_evidence_ids": sorted(no_evidence),
            "records_with_only_ambiguous_or_negated_evidence_ids": sorted(unsupported_evidence),
            "evidence_status_source_record_counts": {status: len(ids) for status, ids in sorted(status_counts.items())}}
