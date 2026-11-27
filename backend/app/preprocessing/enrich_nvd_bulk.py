
"""Enrich existing CVE records using an NVD yearly JSON feed."""

import argparse
import gzip
import json
from datetime import datetime, timezone
from pathlib import Path

from app.preprocessing.normalizer import normalize_nvd


SOURCE_PATH = Path(
    "data/processed/enriched_cves_with_nvd.json"
)

OUTPUT_PATH = Path(
    "data/processed/enriched_cves_bulk.json"
)


def enrich_from_feed(year: int = 2026) -> None:
    """Match NVD feed records to existing CVEs."""

    feed_path = (
        Path.home()
        / "nvd-feeds"
        / f"nvdcve-2.0-{year}.json.gz"
    )

    if not SOURCE_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {SOURCE_PATH}"
        )

    if not feed_path.exists():
        raise FileNotFoundError(
            f"NVD feed not found: {feed_path}"
        )

    
    # Resume from the bulk-enriched dataset when available.
    # Otherwise, start from the earlier NVD checkpoint.
    dataset_path = (
        OUTPUT_PATH if OUTPUT_PATH.exists() else SOURCE_PATH
    )

    print("Loading dataset from:", dataset_path)

    with dataset_path.open("r", encoding="utf-8") as file:
        records = json.load(file)


    # Map CVE IDs to their existing dataset records.
    records_by_cve = {
        record["cve_id"]: record
        for record in records
    }

    if len(records_by_cve) != len(records):
        raise ValueError(
            "Duplicate CVE IDs detected in source dataset."
        )

    target_ids = {
        cve_id
        for cve_id in records_by_cve
        if cve_id.startswith(f"CVE-{year}-")
    }

    print("Loading NVD yearly feed...")

    with gzip.open(feed_path, "rt", encoding="utf-8") as file:
        feed = json.load(file)

    feed_timestamp = feed.get("timestamp")
    processed_at = datetime.now(timezone.utc).isoformat()

    matched_ids = set()
    cvss_available = 0

    for raw_record in feed.get("vulnerabilities", []):
        cve_id = raw_record.get("cve", {}).get("id")

        if cve_id not in target_ids:
            continue

        normalized = normalize_nvd(raw_record)

        record = records_by_cve[cve_id]

        # Preserve previously collected CISA and EPSS data.
        
        # Preserve existing values when the NVD feed omits a field.
        if normalized.get("cvss_score") is not None:
            record["cvss_score"] = normalized["cvss_score"]

        if normalized.get("cvss_severity") is not None:
            record["cvss_severity"] = normalized["cvss_severity"]

        if normalized.get("published_at") is not None:
            record["published_at"] = normalized["published_at"]

        if normalized.get("modified_at") is not None:
            record["modified_at"] = normalized["modified_at"]


        if not record.get("description"):
            record["description"] = normalized.get("description")

        if "NVD" not in record["sources"]:
            record["sources"].append("NVD")

        record["nvd_lookup_status"] = "found"

        # Identify the feed used for enrichment.
        record["nvd_feed_year"] = year
        record["nvd_feed_timestamp"] = feed_timestamp
        record["nvd_enriched_at"] = processed_at

        matched_ids.add(cve_id)

        if record["cvss_score"] is not None:
            cvss_available += 1

    missing_ids = target_ids - matched_ids

    # Save to a separate file, using an atomic replacement.
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = OUTPUT_PATH.with_suffix(".tmp")

    with temp_path.open("w", encoding="utf-8") as file:
        json.dump(records, file, indent=2, ensure_ascii=False)

    temp_path.replace(OUTPUT_PATH)

    print("\nNVD BULK ENRICHMENT SUMMARY")
    print("Feed year:", year)
    print("Total dataset CVEs:", len(records))
    print("Target year CVEs:", len(target_ids))
    print("Matched CVEs:", len(matched_ids))
    print("Matched CVEs with CVSS:", cvss_available)
    print("Not found in feed:", len(missing_ids))
    print("Output:", OUTPUT_PATH)

    if missing_ids:
        print("Missing CVE IDs:", sorted(missing_ids))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--year",
        type=int,
        default=2026,
        help="Year of downloaded NVD feed",
    )

    args = parser.parse_args()

    enrich_from_feed(year=args.year)
