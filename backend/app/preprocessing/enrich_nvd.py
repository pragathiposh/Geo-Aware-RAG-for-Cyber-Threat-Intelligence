
"""Enrich existing CVE records with NVD vulnerability information."""

import argparse
import json
import time
from pathlib import Path
from datetime import datetime, timezone
import requests

from app.collectors.nvd import NVDCollector
from app.preprocessing.normalizer import normalize_nvd


SOURCE_PATH = Path("data/processed/enriched_cves.json")
OUTPUT_PATH = Path("data/processed/enriched_cves_with_nvd.json")


def save_progress(records: list[dict], path: Path) -> None:
    """Save progress safely without overwriting the source dataset."""
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = path.with_suffix(".tmp")

    with temporary_path.open("w", encoding="utf-8") as file:
        json.dump(records, file, indent=2, ensure_ascii=False)

    temporary_path.replace(path)


def enrich_with_nvd(
    limit: int = 3,
    retry_not_found: bool = False,
) -> None:
    """Add NVD data to a limited number of CVEs."""

    if not SOURCE_PATH.exists():
        raise FileNotFoundError(
            f"Source dataset not found: {SOURCE_PATH}"
        )

    # Resume from a previous checkpoint when available.
    dataset_path = (
        OUTPUT_PATH if OUTPUT_PATH.exists() else SOURCE_PATH
    )

    with dataset_path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    collector = NVDCollector()

    processed = 0
    requests_made = 0

    for record in records:
        if processed >= limit:
            break

        # Skip CVEs that have already been checked.
        status = record.get("nvd_lookup_status")

        if status == "found":
            continue

        if status == "not_found" and not retry_not_found:
            continue

        cve_id = record.get("cve_id")

        if not cve_id:
            continue

        # Wait between API requests.
        if requests_made > 0:
            time.sleep(7)

        print(f"Checking NVD: {cve_id}", flush=True)

        try:
            raw_records = collector.fetch_by_cve(cve_id)

        except requests.RequestException as error:
            print(f"NVD request failed: {error}")
            print("Stopping safely. Existing progress is preserved.")
            break

        requests_made += 1

        if raw_records:
            normalized = normalize_nvd(raw_records[0])

            record["cvss_score"] = normalized.get("cvss_score")
            record["cvss_severity"] = normalized.get("cvss_severity")
            record["published_at"] = normalized.get("published_at")
            record["modified_at"] = normalized.get("modified_at")

            if not record.get("description"):
                record["description"] = normalized.get("description")

            if "NVD" not in record["sources"]:
                record["sources"].append("NVD")

            record["nvd_lookup_status"] = "found"

            print(
                f"  CVSS: {record['cvss_score']} | "
                f"Severity: {record['cvss_severity']}"
            )

        else:
            record["nvd_lookup_status"] = "not_found"
            print("  CVE not found in NVD")

        
        # Record when this CVE was checked against NVD.
        record["nvd_checked_at"] = datetime.now(
            timezone.utc
        ).isoformat()

        processed += 1

        # Save after each processed CVE.
        save_progress(records, OUTPUT_PATH)


    print("\nNVD ENRICHMENT SUMMARY")
    print("CVEs processed in this run:", processed)
    print("Total dataset records:", len(records))
    print("Output:", OUTPUT_PATH)



if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--limit",
        type=int,
        default=3,
        help="Maximum number of new CVEs to process",
    )

    parser.add_argument(
        "--retry-not-found",
        action="store_true",
        help="Recheck CVEs previously missing from NVD",
    )

    args = parser.parse_args()

    if args.limit < 1:
        parser.error("--limit must be at least 1")

    enrich_with_nvd(
        limit=args.limit,
        retry_not_found=args.retry_not_found,
    )
