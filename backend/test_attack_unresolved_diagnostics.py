import json
from pathlib import Path

from app.collectors.mitre_attack import load_attack
from app.rag.loader import load_cti_csv
from app.threat_analysis.attack_enricher import ATTACKEnricher
from app.threat_analysis.cti_mapper import CTIRecordMapper
from app.threat_analysis.normalization import CTINormalizer


CSV_PATH = "data/raw/csv/1_otx_threat_intel.csv"

MITRE_PATH = Path(
    "data/mitre/enterprise-attack.json"
)


def test_unresolved_attack_diagnostics():

    # ---------------------------------------------------------
    # 1. Load and normalize CTI dataset
    # ---------------------------------------------------------

    documents = load_cti_csv(CSV_PATH)

    normalized_records = []

    for document in documents:
        record = CTIRecordMapper.from_metadata(
            metadata=document.metadata,
            description=document.page_content,
        )

        normalized_record = CTINormalizer.normalize_record(
            record
        )

        normalized_records.append(normalized_record)

    dataset_attack_ids = set()

    for record in normalized_records:
        for technique in record.attack_techniques:
            dataset_attack_ids.add(
                technique.attack_id
            )

    # ---------------------------------------------------------
    # 2. Load current filtered MITRE techniques
    # ---------------------------------------------------------

    techniques = load_attack()

    enricher = ATTACKEnricher(techniques)

    current_ids = set(
        enricher.techniques_by_id.keys()
    )

    unresolved_ids = (
        dataset_attack_ids - current_ids
    )

    # ---------------------------------------------------------
    # 3. Load RAW MITRE STIX bundle
    # ---------------------------------------------------------

    with MITRE_PATH.open(
        "r",
        encoding="utf-8"
    ) as file:
        bundle = json.load(file)

    raw_objects = bundle.get(
        "objects",
        []
    )

    raw_attack_objects = {}

    for obj in raw_objects:

        if obj.get("type") != "attack-pattern":
            continue

        for reference in obj.get(
            "external_references",
            []
        ):

            external_id = reference.get(
                "external_id"
            )

            if external_id:
                raw_attack_objects[
                    external_id
                ] = obj

    # ---------------------------------------------------------
    # 4. Classify unresolved IDs
    # ---------------------------------------------------------

    present_in_raw = set()
    not_present_in_raw = set()

    revoked_or_deprecated = set()
    active_but_not_loaded = set()

    for attack_id in sorted(
        unresolved_ids
    ):

        obj = raw_attack_objects.get(
            attack_id
        )

        if obj is None:

            not_present_in_raw.add(
                attack_id
            )

            continue

        present_in_raw.add(
            attack_id
        )

        revoked = obj.get(
            "revoked",
            False
        )

        deprecated = obj.get(
            "x_mitre_deprecated",
            False
        )

        if revoked or deprecated:

            revoked_or_deprecated.add(
                attack_id
            )

        else:

            active_but_not_loaded.add(
                attack_id
            )

    # ---------------------------------------------------------
    # 5. Print report
    # ---------------------------------------------------------

    print()
    print("=" * 70)
    print("ATT&CK UNRESOLVED-ID DIAGNOSTIC REPORT")
    print("=" * 70)

    print(
        f"Dataset unique ATT&CK IDs:       "
        f"{len(dataset_attack_ids)}"
    )

    print(
        f"Currently resolved IDs:          "
        f"{len(current_ids & dataset_attack_ids)}"
    )

    print(
        f"Currently unresolved IDs:        "
        f"{len(unresolved_ids)}"
    )

    print()
    print(
        f"Present in raw MITRE bundle:     "
        f"{len(present_in_raw)}"
    )

    print(
        f"Revoked/deprecated:              "
        f"{len(revoked_or_deprecated)}"
    )

    print(
        f"Active but not loaded:            "
        f"{len(active_but_not_loaded)}"
    )

    print(
        f"Not present in raw bundle:       "
        f"{len(not_present_in_raw)}"
    )

    if revoked_or_deprecated:

        print()
        print(
            "REVoked / DEPRECATED IDs:"
        )

        for attack_id in sorted(
            revoked_or_deprecated
        ):
            print(
                f"  - {attack_id}"
            )

    if active_but_not_loaded:

        print()
        print(
            "ACTIVE IDs NOT LOADED:"
        )

        for attack_id in sorted(
            active_but_not_loaded
        ):
            print(
                f"  - {attack_id}"
            )

    if not_present_in_raw:

        print()
        print(
            "NOT PRESENT IN CURRENT MITRE BUNDLE:"
        )

        for attack_id in sorted(
            not_present_in_raw
        ):
            print(
                f"  - {attack_id}"
            )

    print("=" * 70)

    assert dataset_attack_ids