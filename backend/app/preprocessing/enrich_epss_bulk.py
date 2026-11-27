
"""Enrich existing CVE records using the official FIRST EPSS CSV feed."""

import csv
import gzip
import json
from datetime import datetime, timezone
from pathlib import Path


SOURCE_PATH = Path("data/processed/enriched_cves_bulk.json")
OUTPUT_PATH = Path("data/processed/enriched_cves_final.json")
EPSS_PATH = Path.home() / "epss-feeds" / "epss_scores-current.csv.gz"


def enrich_epss():
    """Merge EPSS scores by CVE ID without changing NVD information."""

    if not SOURCE_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {SOURCE_PATH}")

    if not EPSS_PATH.exists():
        raise FileNotFoundError(f"EPSS feed not found: {EPSS_PATH}")

    if OUTPUT_PATH.exists():
        raise FileExistsError(
            f"Output already exists: {OUTPUT_PATH}. "
            "Refusing to overwrite an existing dataset."
        )

    with SOURCE_PATH.open("r", encoding="utf-8") as file:
        records = json.load(file)

    records_by_cve = {
        record["cve_id"]: record
        for record in records
    }

    if len(records_by_cve) != len(records):
        raise ValueError("Duplicate CVE IDs detected.")

    matched = set()
    snapshot_date = None
    processed_at = datetime.now(timezone.utc).isoformat()

    with gzip.open(EPSS_PATH, "rt", encoding="utf-8") as file:
        metadata = file.readline().strip()

        if not metadata.startswith("#"):
            raise ValueError("Unexpected EPSS feed metadata format.")

        print("EPSS metadata:", metadata)

        for item in metadata.lstrip("#").split(","):
            if item.startswith("score_date:"):
                snapshot_date = item.split(":", 1)[1]

        reader = csv.DictReader(file)

        required = {"cve", "epss", "percentile"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError("Required EPSS columns are missing.")

        for row in reader:
            cve_id = row["cve"].strip().upper()

            if cve_id not in records_by_cve:
                continue

            record = records_by_cve[cve_id]

            record["epss_score"] = float(row["epss"])
            record["epss_percentile"] = float(row["percentile"])
            record["epss_date"] = snapshot_date
            record["epss_enriched_at"] = processed_at

            if "FIRST_EPSS" not in record["sources"]:
                record["sources"].append("FIRST_EPSS")

            matched.add(cve_id)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT_PATH.with_suffix(".tmp")

    with temporary.open("w", encoding="utf-8") as file:
        json.dump(records, file, indent=2, ensure_ascii=False)

    temporary.replace(OUTPUT_PATH)

    with_cvss = sum(
        record.get("cvss_score") is not None
        for record in records
    )
    with_epss = sum(
        record.get("epss_score") is not None
        for record in records
    )

    print("\nFINAL ENRICHMENT SUMMARY")
    print("Total CVEs:", len(records))
    print("Unique CVEs:", len(records_by_cve))
    print("Matched in EPSS snapshot:", len(matched))
    print("CVEs with CVSS:", with_cvss)
    print("CVEs with EPSS:", with_epss)
    print("CVEs without EPSS:", len(records) - with_epss)
    print("EPSS snapshot date:", snapshot_date)
    print("Saved to:", OUTPUT_PATH)


if __name__ == "__main__":
    enrich_epss()
