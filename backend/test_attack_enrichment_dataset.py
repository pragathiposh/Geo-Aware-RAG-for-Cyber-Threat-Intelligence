from collections import Counter

from app.collectors.mitre_attack import load_attack
from app.rag.loader import load_cti_csv
from app.threat_analysis.attack_enricher import ATTACKEnricher
from app.threat_analysis.cti_mapper import CTIRecordMapper
from app.threat_analysis.normalization import CTINormalizer


CSV_PATH = "data/raw/csv/1_otx_threat_intel.csv"


def test_real_dataset_attack_enrichment():
    # 1. Load the real CTI dataset
    documents = load_cti_csv(CSV_PATH)

    # 2. Load MITRE ATT&CK knowledge base
    mitre_techniques = load_attack()
    enricher = ATTACKEnricher(mitre_techniques)

    normalized_records = []

    # 3. Map + normalize every CTI record
    for document in documents:
        record = CTIRecordMapper.from_metadata(
            metadata=document.metadata,
            description=document.page_content,
        )

        normalized_record = CTINormalizer.normalize_record(
            record
        )

        normalized_records.append(normalized_record)

    # 4. Calculate ATT&CK statistics before enrichment
    records_with_attack_ids = 0
    records_without_attack_ids = 0

    total_attack_references = 0
    unique_attack_ids = set()

    for record in normalized_records:
        attack_ids = {
            technique.attack_id
            for technique in record.attack_techniques
        }

        if attack_ids:
            records_with_attack_ids += 1
            total_attack_references += len(
                record.attack_techniques
            )
            unique_attack_ids.update(attack_ids)
        else:
            records_without_attack_ids += 1

    # 5. Determine which unique IDs MITRE can resolve
    resolved_ids = {
        attack_id
        for attack_id in unique_attack_ids
        if attack_id in enricher.techniques_by_id
    }

    unresolved_ids = (
        unique_attack_ids - resolved_ids
    )

    # 6. Enrich every record
    enriched_records = [
        enricher.enrich_record(record)
        for record in normalized_records
    ]

    # 7. Verify enrichment actually populated metadata
    enriched_technique_count = 0

    for record in enriched_records:
        for technique in record.attack_techniques:
            if technique.name:
                enriched_technique_count += 1

    # 8. Calculate coverage
    if unique_attack_ids:
        id_coverage = (
            len(resolved_ids)
            / len(unique_attack_ids)
        ) * 100
    else:
        id_coverage = 0.0

    if records_with_attack_ids:
        record_coverage = (
            sum(
                1
                for record in enriched_records
                if record.attack_techniques
                and all(
                    technique.name
                    for technique in record.attack_techniques
                )
            )
            / records_with_attack_ids
        ) * 100
    else:
        record_coverage = 0.0

    # 9. Print report
    print()
    print("=" * 60)
    print("ATT&CK FULL DATASET ENRICHMENT REPORT")
    print("=" * 60)

    print(f"Total CTI records:              {len(normalized_records)}")
    print(
        f"Records with ATT&CK IDs:        "
        f"{records_with_attack_ids}"
    )
    print(
        f"Records without ATT&CK IDs:     "
        f"{records_without_attack_ids}"
    )
    print(
        f"Total ATT&CK references:        "
        f"{total_attack_references}"
    )
    print(
        f"Unique ATT&CK IDs:              "
        f"{len(unique_attack_ids)}"
    )
    print(
        f"Resolved ATT&CK IDs:            "
        f"{len(resolved_ids)}"
    )
    print(
        f"Unresolved ATT&CK IDs:          "
        f"{len(unresolved_ids)}"
    )
    print(
        f"ID-level enrichment coverage:   "
        f"{id_coverage:.2f}%"
    )
    print(
        f"Record-level enrichment coverage:"
        f" {record_coverage:.2f}%"
    )
    print(
        f"Enriched technique references:   "
        f"{enriched_technique_count}"
    )

    if unresolved_ids:
        print()
        print("Unresolved ATT&CK IDs:")
        for attack_id in sorted(unresolved_ids):
            print(f"  - {attack_id}")

    print("=" * 60)

    # 10. Basic correctness assertions
    assert normalized_records
    assert len(mitre_techniques) > 0
    assert records_with_attack_ids > 0
    assert unique_attack_ids
    assert enriched_technique_count > 0


if __name__ == "__main__":
    test_real_dataset_attack_enrichment()