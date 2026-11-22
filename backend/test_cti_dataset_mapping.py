from app.rag.loader import load_cti_csv
from app.threat_analysis.cti_mapper import CTIRecordMapper


def test_real_dataset_mapping():

    csv_path = "data/raw/csv/1_otx_threat_intel.csv"

    documents = load_cti_csv(csv_path)

    assert len(documents) > 0

    records = []

    for document in documents:

        record = CTIRecordMapper.from_metadata(
            metadata=document.metadata,
            description=document.page_content,
        )

        records.append(record)

    assert len(records) == len(documents)

    print(
        f"\nMapped {len(records)} CTI documents "
        "into the canonical CTI schema."
    )

    for record in records[:3]:

        print("\n--- CTI RECORD ---")

        print("ID:", record.record_id)

        print("Title:", record.title)

        print(
            "Countries:",
            record.geography.countries,
        )

        print(
            "Industries:",
            record.targets.industries,
        )

        print(
            "Malware:",
            [malware.name for malware in record.malware],
        )

        print(
            "ATT&CK IDs:",
            [
                technique.attack_id
                for technique
                in record.attack_techniques
            ],
        )