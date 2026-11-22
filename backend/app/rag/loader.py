"""Load source CTI rows and optionally canonicalize them for indexing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
from langchain_core.documents import Document


def _source_value(value: Any) -> str:
    """Convert CSV scalars to display text without leaking NaN/None."""
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    text = str(value).strip()
    return "" if text.lower() in {"nan", "none", "null"} else text


def load_cti_csv(file_path: str | Path) -> list[Document]:
    """Load OTX-style CSV records while preserving row level provenance."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {file_path}")

    frame = pd.read_csv(path)
    documents: list[Document] = []
    for row_number, (_, row) in enumerate(frame.iterrows(), start=1):
        values = {str(key): _source_value(value) for key, value in row.items()}
        description = values.get("Description", "")
        if not description:
            continue

        pulse_id = values.get("Pulse_ID", "")
        source_record_id = pulse_id or f"{path.stem}:row:{row_number}"
        title = values.get("Title", "")
        content = "\n\n".join((
            f"Title: {title}",
            f"Description:\n{description}",
            f"Malware Families: {values.get('Malware_Families', '')}",
            f"Attack IDs: {values.get('Attack_IDs', '')}",
            f"Industries: {values.get('Industries', '')}",
            f"Countries: {values.get('Countries', '')}",
            f"Tags: {values.get('Tags', '')}",
        )).strip()
        metadata = {
            "pulse_id": pulse_id,
            "source_record_id": source_record_id,
            "source_row": row_number,
            "title": title,
            "author": values.get("Author", ""),
            "created": values.get("Created", ""),
            "modified": values.get("Modified", ""),
            "tlp": values.get("TLP", ""),
            "malware_families": values.get("Malware_Families", ""),
            "attack_ids": values.get("Attack_IDs", ""),
            "industries": values.get("Industries", ""),
            "countries": values.get("Countries", ""),
            "tags": values.get("Tags", ""),
            "source": path.name,
            "source_path": path.as_posix(),
            # Exact source description for canonical evidence offsets and traceability.
            "source_description": description,
        }
        documents.append(Document(page_content=content, metadata=metadata))
    return documents


def load_canonical_cti_csv(
    file_path: str | Path,
    attack_enricher: Any | None = None,
) -> list[Document]:
    """Load, map, normalize, and optionally ATT&CK-enrich source records.

    ``countries`` remains the source's geographic association field. This
    ingestion path does not claim that those countries are incident locations.
    """
    from app.threat_analysis.cti_mapper import CTIRecordMapper
    from app.threat_analysis.normalization import CTINormalizer
    from app.geo.geographic_extractor import GeographicEvidenceExtractor

    documents: list[Document] = []
    geo_extractor = GeographicEvidenceExtractor()
    for source_document in load_cti_csv(file_path):
        description = source_document.metadata.get("source_description", "")
        record = CTIRecordMapper.from_metadata(
            metadata=source_document.metadata,
            description=description,
        )
        record = CTINormalizer.normalize_record(record)
        record = record.model_copy(update={
            "geographic_evidence": geo_extractor.extract(description, record.record_id)
        })
        if attack_enricher is not None:
            record = attack_enricher.enrich_record(record)

        canonical = record.model_dump(mode="json")
        metadata = dict(source_document.metadata)
        metadata.pop("source_description", None)
        metadata.update({
            "record_id": record.record_id,
            "canonical_cti": json.dumps(canonical, ensure_ascii=False, sort_keys=True),
            "canonical_tags": record.tags,
            "canonical_malware": [item.name for item in record.malware],
            "canonical_attack_ids": [item.attack_id for item in record.attack_techniques],
            "attack_enrichment": [item.model_dump(mode="json") for item in record.attack_techniques],
            "countries": record.geography.countries,
            "industries": record.targets.industries,
            "malware_families": [item.name for item in record.malware],
            "attack_ids": [item.attack_id for item in record.attack_techniques],
            "tags": record.tags,
            "geography_semantics": "source_association_only",
        })
        documents.append(Document(page_content=source_document.page_content, metadata=metadata))
    return documents
