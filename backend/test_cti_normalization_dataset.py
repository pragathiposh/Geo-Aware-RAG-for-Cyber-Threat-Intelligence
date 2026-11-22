from collections import Counter

from app.rag.loader import load_cti_csv
from app.threat_analysis.cti_mapper import CTIRecordMapper
from app.threat_analysis.normalization import CTINormalizer


def test_real_dataset_normalization_profile():

    csv_path = "data/raw/csv/1_otx_threat_intel.csv"

    documents = load_cti_csv(csv_path)

    assert documents

    total_records = len(documents)

    normalized_records = []

    raw_countries = Counter()
    normalized_countries = Counter()

    raw_industries = Counter()
    normalized_industries = Counter()

    raw_malware = Counter()
    normalized_malware = Counter()

    raw_attack_ids = Counter()
    normalized_attack_ids = Counter()

    country_changes = Counter()
    industry_changes = Counter()

    for document in documents:

        record = CTIRecordMapper.from_metadata(
            metadata=document.metadata,
            description=document.page_content,
        )

        normalized_record = CTINormalizer.normalize_record(
            record
        )

        normalized_records.append(normalized_record)

        # -------------------------------------------------
        # Countries
        # -------------------------------------------------

        for country in record.geography.countries:
            raw_countries[country] += 1

        for country in normalized_record.geography.countries:
            normalized_countries[country] += 1

        raw_country_values = {
            str(country).strip()
            for country in record.geography.countries
        }

        normalized_country_values = {
            str(country).strip()
            for country in normalized_record.geography.countries
        }

        if raw_country_values != normalized_country_values:
            country_changes[
                (
                    tuple(sorted(raw_country_values)),
                    tuple(sorted(normalized_country_values)),
                )
            ] += 1

        # -------------------------------------------------
        # Industries
        # -------------------------------------------------

        for industry in record.targets.industries:
            raw_industries[industry] += 1

        for industry in normalized_record.targets.industries:
            normalized_industries[industry] += 1

        raw_industry_values = {
            str(industry).strip()
            for industry in record.targets.industries
        }

        normalized_industry_values = {
            str(industry).strip()
            for industry in normalized_record.targets.industries
        }

        if raw_industry_values != normalized_industry_values:
            industry_changes[
                (
                    tuple(sorted(raw_industry_values)),
                    tuple(sorted(normalized_industry_values)),
                )
            ] += 1

        # -------------------------------------------------
        # Malware
        # -------------------------------------------------

        for malware in record.malware:
            raw_malware[malware.name] += 1

        for malware in normalized_record.malware:
            normalized_malware[malware.name] += 1

        # -------------------------------------------------
        # ATT&CK
        # -------------------------------------------------

        for technique in record.attack_techniques:
            raw_attack_ids[technique.attack_id] += 1

        for technique in normalized_record.attack_techniques:
            normalized_attack_ids[technique.attack_id] += 1

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    records_with_country = sum(
        1
        for record in normalized_records
        if record.geography.countries
    )

    records_without_country = (
        total_records - records_with_country
    )

    records_with_industry = sum(
        1
        for record in normalized_records
        if record.targets.industries
    )

    records_without_industry = (
        total_records - records_with_industry
    )

    records_with_malware = sum(
        1
        for record in normalized_records
        if record.malware
    )

    records_without_malware = (
        total_records - records_with_malware
    )

    records_with_attack_ids = sum(
        1
        for record in normalized_records
        if record.attack_techniques
    )

    records_without_attack_ids = (
        total_records - records_with_attack_ids
    )

    print("\n")
    print("=" * 70)
    print("CTI DATASET NORMALIZATION PROFILE")
    print("=" * 70)

    print(f"\nTotal records: {total_records}")

    print("\n--- GEOGRAPHY ---")

    print(
        f"Records with country: "
        f"{records_with_country}"
    )

    print(
        f"Records without country: "
        f"{records_without_country}"
    )

    print("\nTop normalized countries:")

    for country, count in normalized_countries.most_common(20):
        print(f"  {country}: {count}")

    print("\n--- INDUSTRIES ---")

    print(
        f"Records with industry: "
        f"{records_with_industry}"
    )

    print(
        f"Records without industry: "
        f"{records_without_industry}"
    )

    print("\nNormalized industries:")

    for industry, count in normalized_industries.most_common():
        print(f"  {industry}: {count}")

    print("\n--- MALWARE ---")

    print(
        f"Records with malware: "
        f"{records_with_malware}"
    )

    print(
        f"Records without malware: "
        f"{records_without_malware}"
    )

    print("\nTop malware names:")

    for malware, count in normalized_malware.most_common(20):
        print(f"  {malware}: {count}")

    print("\n--- MITRE ATT&CK ---")

    print(
        f"Records with ATT&CK IDs: "
        f"{records_with_attack_ids}"
    )

    print(
        f"Records without ATT&CK IDs: "
        f"{records_without_attack_ids}"
    )

    print(
        f"Unique normalized ATT&CK IDs: "
        f"{len(normalized_attack_ids)}"
    )

    print("\nTop ATT&CK IDs:")

    for attack_id, count in normalized_attack_ids.most_common(20):
        print(f"  {attack_id}: {count}")

    print("\n--- NORMALIZATION CHANGES ---")

    print(
        f"Country normalization changes: "
        f"{sum(country_changes.values())}"
    )

    print(
        f"Industry normalization changes: "
        f"{sum(industry_changes.values())}"
    )

    print("\nExample country transformations:")

    for (
        raw_values,
        normalized_values,
    ), count in country_changes.most_common(10):

        print(
            f"  {raw_values} -> "
            f"{normalized_values} "
            f"({count} records)"
        )

    print("\nExample industry transformations:")

    for (
        raw_values,
        normalized_values,
    ), count in industry_changes.most_common(10):

        print(
            f"  {raw_values} -> "
            f"{normalized_values} "
            f"({count} records)"
        )

    print("\n" + "=" * 70)

    assert len(normalized_records) == total_records