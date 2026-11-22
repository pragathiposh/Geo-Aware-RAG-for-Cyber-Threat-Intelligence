import json
from pathlib import Path

import pandas as pd

from app.geo.geo_analysis import aggregate_geography, supported_location_evidence
from app.geo.geographic_extractor import GeographicEvidenceExtractor
from app.rag.loader import load_canonical_cti_csv


ROOT = Path(__file__).parent
CSV = ROOT / "data/raw/csv/1_otx_threat_intel.csv"
EVALUATION = ROOT / "data/evaluation/phase3_geographic.json"


def _key(item):
    return (item.get("country") or item.get("region"), item["role"], item["status"])


def _gold_key(item):
    return (item.get("country") or item.get("region"), item["role"], item["status"])


def test_extractor_roles_aliases_and_conservative_mentions():
    extractor = GeographicEvidenceExtractor()
    result = extractor.extract(
        "Ransomware incidents in Japan; a Pakistan-based threat actor targeted Indian government entities. "
        "The campaign mentions India and British Indian Ocean Territory.", "src-1"
    )
    got = [(item.country, item.role.value, item.status.value) for item in result]
    assert ("Japan", "incident_location", "supported") in got
    assert ("Pakistan", "claimed_actor_origin", "supported") in got
    assert ("India", "target_location", "supported") in got
    assert ("India", "general_mention", "ambiguous") in got
    assert ("British Indian Ocean Territory", "general_mention", "ambiguous") in got
    assert all(item.source_record_id == "src-1" and item.evidence_text for item in result)


def test_negated_claim_not_aggregated_and_us_not_pronoun():
    extractor = GeographicEvidenceExtractor()
    assert extractor.extract("The malware said it would help us later.", "src") == []
    claim = extractor.extract("No victims were located in India.", "src")[0]
    assert claim.status.value == "negated"
    assert claim.role.value == "general_mention"
    assert supported_location_evidence([{"source_record_id": "src", "geographic_evidence": [claim.model_dump(mode="json")]}]) == []
    assert extractor.extract("Victims are located in the US and Canada.", "src")[0].country == "United States"


def test_canonical_ingestion_preserves_description_association_and_ids(tmp_path):
    path = tmp_path / "records.csv"
    pd.DataFrame([{
        "Pulse_ID": "p-1", "Title": "Evidence", "Description": "Users in India were targeted.",
        "Countries": "USA", "Attack_IDs": "T1486", "Tags": "ransomware"
    }]).to_csv(path, index=False)
    document = load_canonical_cti_csv(path)[0]
    canonical = json.loads(document.metadata["canonical_cti"])
    assert canonical["description"] == "Users in India were targeted."
    assert canonical["geography"]["countries"] == ["United States"]
    assert canonical["geographic_evidence"][0]["country"] == "India"
    assert canonical["geographic_evidence"][0]["source_record_id"] == "p-1"
    assert document.metadata["geography_semantics"] == "source_association_only"
    assert document.metadata["attack_ids"] == ["T1486"]
    assert "source_description" not in document.metadata


def test_analysis_counts_distinct_records_and_separates_associations():
    claims = [{"country": "India", "region": "South Asia", "role": "target_location", "status": "supported", "evidence_text": "targeted in India", "source_record_id": "p1"}]
    records = [
        {"source_record_id": "p1", "countries": ["United States"], "canonical_cti": {"record_id": "p1", "tags": ["malware"], "geography": {"countries": ["United States"]}, "geographic_evidence": claims}},
        {"source_record_id": "p1", "countries": ["United States"], "canonical_cti": {"record_id": "p1", "tags": ["malware"], "geography": {"countries": ["United States"]}, "geographic_evidence": claims}},
        {"source_record_id": "p2", "countries": ["India"], "canonical_cti": {"record_id": "p2", "geography": {"countries": ["India"]}, "geographic_evidence": []}},
    ]
    report = aggregate_geography(records, group_by="country", threat_categories=["malware"])
    assert report["evidence_supported_counts"]["India"]["count"] == 1
    assert report["evidence_supported_counts"]["India"]["threat_category_counts"] == {"malware": 1}
    assert report["source_association_counts"] == {"India": 1, "United States": 1}
    assert report["unknown_or_unsupported_source_record_ids"] == ["p2"]
    assert report["records_with_no_location_evidence_ids"] == ["p2"]
    assert report["records_with_only_ambiguous_or_negated_evidence_ids"] == []
    assert supported_location_evidence(records, country="India")[0]["source_record_id"] == "p1"
    assert supported_location_evidence(records, country="India")[0]["country"] == "India"
    assert supported_location_evidence(records, country="India") == supported_location_evidence(records, country="india")
    region_report = aggregate_geography(records, group_by="region")
    assert region_report["evidence_supported_counts"]["South Asia"]["count"] == 1


def test_actual_otx_evaluation_labels_and_metrics():
    data = json.loads(EVALUATION.read_text(encoding="utf-8"))
    frame = pd.read_csv(CSV).fillna("")
    by_id = {str(row.get("Pulse_ID", "")): str(row.get("Description", "")) for _, row in frame.iterrows()}
    extractor = GeographicEvidenceExtractor()
    tp = fp = fn = role_correct = role_total = 0
    distribution = {}
    for record in data["records"]:
        source_id = record["source_record_id"]
        assert source_id in by_id and by_id[source_id]
        predicted = extractor.extract(by_id[source_id], source_id)
        predicted_keys = {_key(item.model_dump(mode="json")) for item in predicted}
        gold_keys = {_gold_key(item) for item in record["expected"]}
        tp += len(predicted_keys & gold_keys)
        fp += len(predicted_keys - gold_keys)
        fn += len(gold_keys - predicted_keys)
        for item in record["expected"]:
            distribution[item["role"]] = distribution.get(item["role"], 0) + 1
        for prediction in predicted:
            if (prediction.country or prediction.region, prediction.status.value) in {(g.get("country") or g.get("region"), g["status"]) for g in record["expected"]}:
                role_total += 1
                role_correct += prediction.role.value in {g["role"] for g in record["expected"] if (prediction.country or prediction.region, prediction.status.value) == (g.get("country") or g.get("region"), g["status"])}
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    role_accuracy = role_correct / role_total if role_total else 0
    print({"records": len(data["records"]), "labels_by_role": distribution, "tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "role_accuracy": role_accuracy})
    assert len(data["records"]) == 11
    assert precision >= .80 and recall >= .80 and role_accuracy >= .80
